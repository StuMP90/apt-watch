package risk

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"aptwatch/internal/collect"
)

// Finding kinds.
const (
	KindSecurityUpdate = "security-update-pending"
	KindUpdate         = "update-pending"
	KindReboot         = "reboot-required"
	KindKernel         = "kernel-not-running"
	KindOSEOL          = "os-eol"
	KindStaleLists     = "stale-apt-lists"
	KindThirdParty     = "third-party-packages"

	KindCVEFixAvailable   = "cve-fix-available"
	KindCVEFixUnreachable = "cve-fix-unreachable"
	KindCVEUnfixed        = "cve-unfixed"
	KindCVEUnfixedSummary = "cve-unfixed-summary"
)

// PkgRef is a package a finding refers to.
type PkgRef struct {
	Name      string `json:"name"`
	Installed string `json:"installed,omitempty"`
	Candidate string `json:"candidate,omitempty"`
	Origin    string `json:"origin,omitempty"`
}

// CVERef is a CVE a finding refers to.
type CVERef struct {
	ID       string  `json:"id"`
	Priority string  `json:"priority,omitempty"` // the distro's priority
	Fixed    string  `json:"fixed,omitempty"`    // source version with the fix
	KEV      bool    `json:"kev,omitempty"`
	EPSS     float64 `json:"epss,omitempty"`
	URL      string  `json:"url,omitempty"`
}

type Finding struct {
	Key       string    `json:"key"`
	Kind      string    `json:"kind"`
	Severity  Severity  `json:"severity"`
	Title     string    `json:"title"`
	Source    string    `json:"source,omitempty"` // source package
	Packages  []PkgRef  `json:"packages,omitempty"`
	CVEs      []CVERef  `json:"cves,omitempty"`
	FixAvail  bool      `json:"fix_available"`
	Since     time.Time `json:"since,omitzero"`
	FirstSeen time.Time `json:"first_seen,omitzero"`
	Detail    string    `json:"detail,omitempty"`
	// Suppressed is set if an ignore rule matched: the finding is still
	// reported, but doesn't count toward the exit code or summary.
	Suppressed *Suppression `json:"suppressed,omitempty"`
}

// Policy holds the tunables used by Evaluate and Escalate.
type Policy struct {
	EscalateAfter       time.Duration
	RebootEscalateAfter time.Duration
	EOLWarnBefore       time.Duration
	StaleListsAfter     time.Duration
	EPSSBump            float64       // raise CVE severity a level at this EPSS or above; 0 to disable
	ReportUnfixed       string        // UnfixedSummary, UnfixedNone or UnfixedFull
	RecentCVEs          time.Duration // window for the changelog findings that only concern recent CVEs; 0 to disable
	ThirdPartyGaps      bool          // report recent distro-fixed CVEs a third-party changelog doesn't name
}

// Values for Policy.ReportUnfixed.
const (
	UnfixedSummary = "summary"
	UnfixedNone    = "none"
	UnfixedFull    = "full"
)

func DefaultPolicy() Policy {
	return Policy{
		EscalateAfter:       7 * 24 * time.Hour,
		RebootEscalateAfter: 7 * 24 * time.Hour,
		EOLWarnBefore:       90 * 24 * time.Hour,
		StaleListsAfter:     48 * time.Hour,
		EPSSBump:            0.5,
		ReportUnfixed:       UnfixedSummary,
		RecentCVEs:          90 * 24 * time.Hour,
		ThirdPartyGaps:      true,
	}
}

// Evaluate derives findings from the inventory, at their base severities
// (plus escalations that don't depend on history, such as reboot age).
func Evaluate(inv *collect.Inventory, p Policy, now time.Time) []Finding {
	var out []Finding
	out = append(out, updateFindings(inv)...)
	out = append(out, thirdPartyFindings(inv)...)

	sys := inv.System
	if sys.Reboot.Required {
		f := Finding{
			Key: KindReboot, Kind: KindReboot, Severity: Medium,
			Title: "Reboot required", Since: sys.Reboot.Since, FixAvail: true,
		}
		if len(sys.Reboot.Packages) > 0 {
			f.Detail = "Requested by: " + strings.Join(sys.Reboot.Packages, ", ")
		}
		if p.RebootEscalateAfter > 0 && !f.Since.IsZero() && now.Sub(f.Since) >= p.RebootEscalateAfter {
			f.Severity = High
		}
		out = append(out, f)
	}
	if k := sys.Kernel; k.Newest != "" && k.Running != "" && k.Newest != k.Running {
		out = append(out, Finding{
			Key: KindKernel + ":" + k.Newest, Kind: KindKernel, Severity: Medium,
			Title:    "Newer kernel installed but not running",
			Detail:   fmt.Sprintf("Running %s, newest installed %s", k.Running, k.Newest),
			FixAvail: true,
		})
	}
	if e := sys.EOL; e != nil {
		left := e.SecurityEnd.Sub(now)
		name := sys.OS.PrettyName
		if name == "" {
			name = sys.OS.Codename
		}
		f := Finding{Key: KindOSEOL + ":" + sys.OS.Codename, Kind: KindOSEOL, Detail: e.Note}
		switch {
		case left <= 0:
			f.Severity = High
			f.Title = fmt.Sprintf("%s is past end of security support (%s)", name, e.SecurityEnd.Format(time.DateOnly))
		case left <= p.EOLWarnBefore:
			f.Severity = Medium
			f.Title = fmt.Sprintf("%s reaches end of security support on %s (%d days)", name, e.SecurityEnd.Format(time.DateOnly), int(left.Hours()/24))
		}
		if f.Title != "" {
			out = append(out, f)
		}
	}
	if t := sys.ListsUpdated; !t.IsZero() && p.StaleListsAfter > 0 && now.Sub(t) > p.StaleListsAfter {
		out = append(out, Finding{
			Key: KindStaleLists, Kind: KindStaleLists, Severity: Medium,
			Title: fmt.Sprintf("apt package lists last updated %s ago", Age(now.Sub(t))),
			Since: t,
		})
	}
	Sort(out)
	return out
}

// updateFindings groups pending updates by source package and candidate.
func updateFindings(inv *collect.Inventory) []Finding {
	srcOf := collect.SourceOf(inv.Packages)
	type group struct {
		src, cand      string
		sec, esm, phas bool
		pkgs           []PkgRef
	}
	groups := map[string]*group{}
	var order []string
	for _, u := range inv.Simulation.Updates {
		src := srcOf[u.Package]
		if src == "" {
			src = u.Source // new install, e.g. a new kernel image
		}
		if src == "" {
			src = u.Package
		}
		key := src + "/" + u.Candidate
		g := groups[key]
		if g == nil {
			g = &group{src: src, cand: u.Candidate}
			groups[key] = g
			order = append(order, key)
		}
		g.sec = g.sec || u.Security
		g.esm = g.esm || u.ESM
		g.phas = g.phas || u.Phased
		origin := ""
		if len(u.Origins) > 0 {
			origin = u.Origins[len(u.Origins)-1].String()
		}
		g.pkgs = append(g.pkgs, PkgRef{Name: u.Package, Installed: u.Installed, Candidate: u.Candidate, Origin: origin})
	}

	var out []Finding
	for _, key := range order {
		g := groups[key]
		f := Finding{Source: g.src, Packages: g.pkgs, FixAvail: true}
		var notes []string
		if g.sec {
			f.Kind, f.Severity, f.Key = KindSecurityUpdate, Medium, "security-update:"+key
			f.Title = fmt.Sprintf("Security update for %s (%s)", g.src, g.cand)
		} else {
			f.Kind, f.Severity, f.Key = KindUpdate, Info, "update:"+key
			f.Title = fmt.Sprintf("Update for %s (%s)", g.src, g.cand)
		}
		if g.esm {
			notes = append(notes, "from Ubuntu ESM")
		}
		if g.phas {
			notes = append(notes, "phased rollout: apt is holding it back on this host for now")
		}
		f.Detail = strings.Join(notes, "; ")
		out = append(out, f)
	}
	return out
}

// Escalate applies escalations that depend on FirstSeen, which the state
// package fills in.
func Escalate(fs []Finding, p Policy, now time.Time) {
	for i := range fs {
		f := &fs[i]
		escalates := f.Kind == KindSecurityUpdate || f.Kind == KindCVEFixAvailable || f.Kind == KindCVEFixUnreachable
		if escalates && p.EscalateAfter > 0 && !f.FirstSeen.IsZero() &&
			now.Sub(f.FirstSeen) >= p.EscalateAfter {
			f.Severity = f.Severity.Bump(1)
		}
	}
	Sort(fs)
}

// Sort orders findings by severity (highest first), then key.
func Sort(fs []Finding) {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		if c := cmp.Compare(b.Severity, a.Severity); c != 0 {
			return c
		}
		return cmp.Compare(a.Key, b.Key)
	})
}

// Counts returns the number of findings at each severity.
func Counts(fs []Finding) map[Severity]int {
	m := map[Severity]int{}
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// Highest returns the highest severity in fs, and false if fs is empty.
func Highest(fs []Finding) (Severity, bool) {
	if len(fs) == 0 {
		return Info, false
	}
	h := Info
	for _, f := range fs {
		h = max(h, f.Severity)
	}
	return h, true
}

// AtLeast returns the findings with severity >= min.
func AtLeast(fs []Finding, min Severity) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Severity >= min {
			out = append(out, f)
		}
	}
	return out
}

// Age formats a duration as a short human age: "45m", "6h", "3d".
func Age(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
