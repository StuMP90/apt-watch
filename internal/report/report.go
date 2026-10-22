// Package report renders a run's results as text, HTML or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/risk"
	"aptwatch/internal/state"
)

const SchemaVersion = 1

// Report is everything a printed report is built from.
type Report struct {
	Schema    int              `json:"schema"`
	Tool      string           `json:"tool"`
	Host      string           `json:"host"`
	Generated time.Time        `json:"generated"`
	System    collect.System   `json:"system"`
	Findings  []risk.Finding   `json:"findings"`
	Diff      *state.Diff      `json:"diff,omitempty"` // nil when there is no history (scan)
	Updates   []collect.Update `json:"updates"`
	VulnDB    *VulnDB          `json:"vulndb,omitempty"` // nil when no CVE data was available
	Warnings  []string         `json:"warnings,omitempty"`
	// Expired are the ignore rules past their until date, which no longer apply.
	Expired []risk.IgnoreRule `json:"expired_ignores,omitempty"`
}

// VulnDB describes the vulnerability data the CVE findings came from.
type VulnDB struct {
	Sources []string  `json:"sources"`
	Fetched time.Time `json:"fetched"` // oldest of the advisory feeds
	KEV     int       `json:"kev"`     // entries loaded; 0 when off or unavailable
	EPSS    int       `json:"epss"`
}

// Summary is the one-line overview, e.g.
// "web01: 1 HIGH, 2 MEDIUM — 9 updates pending (2 security, 3 phased) — reboot required (3d)".
func (r *Report) Summary() string {
	var parts []string
	counts := risk.Counts(risk.Active(r.Findings))
	var sev []string
	for s := risk.Critical; s >= risk.Low; s-- {
		if n := counts[s]; n > 0 {
			sev = append(sev, fmt.Sprintf("%d %s", n, s.Label()))
		}
	}
	if len(sev) == 0 {
		parts = append(parts, "no risks found")
	} else {
		parts = append(parts, strings.Join(sev, ", "))
	}
	if n := len(r.Updates); n > 0 {
		sec, phased := 0, 0
		for _, u := range r.Updates {
			if u.Security {
				sec++
			}
			if u.Phased {
				phased++
			}
		}
		s := fmt.Sprintf("%d update%s pending (%d security", n, plural(n), sec)
		if phased > 0 {
			s += fmt.Sprintf(", %d phased", phased)
		}
		parts = append(parts, s+")")
	} else {
		parts = append(parts, "up to date")
	}
	if rb := r.System.Reboot; rb.Required {
		s := "reboot required"
		if !rb.Since.IsZero() {
			s += " (" + risk.Age(r.Generated.Sub(rb.Since)) + ")"
		}
		parts = append(parts, s)
	}
	return r.Host + ": " + strings.Join(parts, " — ")
}

// Highest is the highest severity of the findings no ignore rule
// suppresses, or Info if there are none.
func (r *Report) Highest() risk.Severity {
	h, _ := risk.Highest(risk.Active(r.Findings))
	return h
}

func (r *Report) JSON(w io.Writer) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}

// Text writes the full human-readable report.
func (r *Report) Text(w io.Writer) error {
	b := &strings.Builder{}
	p := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }

	p("%s\n", r.Summary())
	p("%s\n\n", strings.Repeat("=", min(len([]rune(r.Summary())), 78)))

	// System
	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	for _, row := range r.systemRows() {
		fmt.Fprintf(tw, "%s\t%s\n", row.Key, strings.Join(row.Lines, "\n\t"))
	}
	tw.Flush()

	// Changes
	if cs := r.changes(); len(cs) > 0 {
		p("\nChanges since last run\n")
		for _, c := range cs {
			p("  %-10s %-10s %s\n", c.Label, "["+c.Severity.Label()+"]", c.Title)
		}
	}

	// Findings (informational update findings are covered by the updates list)
	shown := risk.AtLeast(risk.Active(r.Findings), risk.Low)
	p("\nFindings (%d)\n", len(shown))
	if len(shown) == 0 {
		p("  none\n")
	}
	for _, f := range shown {
		line := fmt.Sprintf("  %-9s %s", f.Severity.Label(), f.Title)
		if when := r.when(f); when != "" {
			line += " — " + when
		}
		p("%s\n", line)
		if f.Detail != "" {
			p("            %s\n", f.Detail)
		}
		if len(f.Packages) > 0 {
			p("            Packages: %s\n", strings.Join(packageNames(f.Packages, 8), ", "))
		}
		for _, c := range f.CVEs {
			p("            %s\n", cveLine(c))
		}
	}

	// Findings ignore rules suppress, and the rules that have expired
	if sup := risk.Suppressed(r.Findings); len(sup) > 0 || len(r.Expired) > 0 {
		p("\nSuppressed findings (%d)\n", len(sup))
		for _, f := range sup {
			p("  %-9s %s\n", f.Severity.Label(), f.Title)
			p("            %s\n", suppressedLine(f.Suppressed))
		}
		for _, x := range r.Expired {
			p("  ! %s\n", expiredLine(x))
		}
	}

	// CVEs that third-party changelogs say the installed versions fix
	if fixed := r.thirdPartyFixed(); len(fixed) > 0 {
		p("\nRecent CVEs fixed in installed third-party packages\n")
		for _, f := range fixed {
			p("  %s\n", f.Title)
			for _, c := range f.CVEs {
				p("            %s\n", cveLine(c))
			}
		}
	}

	// Pending updates
	p("\nPending updates (%d)\n", len(r.Updates))
	if len(r.Updates) == 0 {
		p("  none\n")
	}
	for _, g := range r.updateGroups() {
		p("  %s (%d)\n", g.Label, len(g.Updates))
		tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
		for _, u := range g.Updates {
			fmt.Fprintf(tw, "    %s\t%s → %s\t%s", u.Package, installedOrNew(u), u.Candidate, suite(u))
			if fl := updateFlags(u); len(fl) > 0 {
				fmt.Fprintf(tw, "\t%s", strings.Join(fl, ","))
			}
			fmt.Fprintln(tw)
		}
		tw.Flush()
	}

	if cmds := r.suggestions(); len(cmds) > 0 {
		p("\nSuggested commands\n")
		for _, c := range cmds {
			p("  %s\n", c)
		}
	}

	if len(r.Warnings) > 0 {
		p("\nWarnings\n")
		for _, wn := range r.Warnings {
			p("  ! %s\n", wn)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// row is one line of the system table; extra lines are continuations.
type row struct {
	Key   string
	Lines []string
}

func (r *Report) systemRows() []row {
	sys := r.System
	var rows []row
	add := func(k string, lines ...string) { rows = append(rows, row{k, lines}) }
	add("Host", sys.Hostname)
	osLine := sys.OS.PrettyName
	if e := sys.EOL; e != nil {
		osLine += fmt.Sprintf(" (security support until %s", e.SecurityEnd.Format(time.DateOnly))
		if e.Note != "" {
			osLine += "; " + e.Note
		}
		osLine += ")"
	}
	add("OS", osLine)
	k := sys.Kernel.Running
	if sys.Kernel.Newest != "" && sys.Kernel.Newest != sys.Kernel.Running {
		k += " (newest installed: " + sys.Kernel.Newest + ")"
	}
	add("Kernel", k)
	if sys.Reboot.Required {
		s := "required"
		if !sys.Reboot.Since.IsZero() {
			s += " since " + sys.Reboot.Since.Local().Format("2006-01-02 15:04")
		}
		if len(sys.Reboot.Packages) > 0 {
			s += " (" + strings.Join(sys.Reboot.Packages, ", ") + ")"
		}
		add("Reboot", s)
	} else {
		add("Reboot", "not required")
	}
	if !sys.ListsUpdated.IsZero() {
		add("Apt lists", "updated "+risk.Age(r.Generated.Sub(sys.ListsUpdated))+" ago")
	}
	cve := []string{r.vulnLine()}
	for _, f := range r.Findings {
		if f.Kind == risk.KindCVEUnfixedSummary {
			cve = append(cve, f.Title+": "+f.Detail)
		}
	}
	add("CVE data", cve...)
	add("Checked", r.Generated.Local().Format("2006-01-02 15:04 MST")+" by "+r.Tool)
	return rows
}

// change is a line of "Changes since last run".
type change struct {
	Label    string // NEW, ESCALATED or RESOLVED
	Severity risk.Severity
	Title    string
}

func (r *Report) changes() []change {
	d := r.Diff
	if d == nil {
		return nil
	}
	var cs []change
	for _, f := range risk.Active(r.Findings) {
		switch {
		case d.IsNew(f.Key):
			cs = append(cs, change{"NEW", f.Severity, f.Title})
		case d.IsEscalated(f.Key):
			cs = append(cs, change{"ESCALATED", f.Severity, f.Title})
		}
	}
	for _, res := range d.Resolved {
		cs = append(cs, change{"RESOLVED", res.Severity, res.Title})
	}
	return cs
}

// when says how long a finding has been open, e.g.
// "since 2026-10-01 (3w)" or "first seen 2026-10-01"; "" if unknown.
func (r *Report) when(f risk.Finding) string {
	switch {
	case !f.Since.IsZero() && f.Kind != risk.KindStaleLists:
		return fmt.Sprintf("since %s (%s)", f.Since.Local().Format(time.DateOnly), risk.Age(r.Generated.Sub(f.Since)))
	case !f.FirstSeen.IsZero() && r.Diff != nil && !r.Diff.IsNew(f.Key):
		return "first seen " + f.FirstSeen.Local().Format(time.DateOnly)
	}
	return ""
}

// suppressedLine says why a finding is suppressed, e.g.
// "ignored (CVE-2025-1234, until 2026-12-31): not compiled in".
func suppressedLine(s *risk.Suppression) string {
	rule := s.Rule
	if !s.Until.IsZero() {
		rule += ", until " + s.Until.Format(time.DateOnly)
	}
	return fmt.Sprintf("ignored (%s): %s", rule, s.Reason)
}

// expiredLine notes an ignore rule that no longer applies.
func expiredLine(x risk.IgnoreRule) string {
	return fmt.Sprintf("ignore rule %s expired on %s (%s): its findings count again; renew or remove it",
		x, x.Until.Format(time.DateOnly), x.Reason)
}

// packageNames lists up to max names, then "and N more".
func packageNames(pkgs []risk.PkgRef, max int) []string {
	names := make([]string, len(pkgs))
	for i, pk := range pkgs {
		names[i] = pk.Name
	}
	if len(names) > max {
		names = append(names[:max:max], fmt.Sprintf("and %d more", len(names)-max))
	}
	return names
}

func (r *Report) thirdPartyFixed() []risk.Finding {
	var out []risk.Finding
	for _, f := range r.Findings {
		if f.Kind == risk.KindCVEFixedThirdParty {
			out = append(out, f)
		}
	}
	return out
}

type updateGroup struct {
	Label   string // Security or Other
	Updates []collect.Update
}

func (r *Report) updateGroups() []updateGroup {
	var gs []updateGroup
	for _, sec := range []bool{true, false} {
		var us []collect.Update
		for _, u := range r.Updates {
			if u.Security == sec {
				us = append(us, u)
			}
		}
		if len(us) == 0 {
			continue
		}
		label := "Other"
		if sec {
			label = "Security"
		}
		slices.SortFunc(us, func(a, b collect.Update) int { return strings.Compare(a.Package, b.Package) })
		gs = append(gs, updateGroup{label, us})
	}
	return gs
}

func installedOrNew(u collect.Update) string {
	if u.Installed == "" {
		return "(new)"
	}
	return u.Installed
}

func suite(u collect.Update) string {
	if len(u.Origins) > 0 {
		return u.Origins[len(u.Origins)-1].Suite
	}
	return ""
}

func updateFlags(u collect.Update) []string {
	var flags []string
	if u.ESM {
		flags = append(flags, "esm")
	}
	if u.Phased {
		flags = append(flags, "phased")
	}
	return flags
}

func (r *Report) vulnLine() string { return vulnLine(r.VulnDB, r.Generated) }

func vulnLine(v *VulnDB, now time.Time) string {
	if v == nil {
		return "not available (see warnings)"
	}
	s := strings.Join(v.Sources, ", ")
	if !v.Fetched.IsZero() {
		s += ", updated " + risk.Age(now.Sub(v.Fetched)) + " ago"
	}
	var extra []string
	if v.KEV > 0 {
		extra = append(extra, "KEV")
	}
	if v.EPSS > 0 {
		extra = append(extra, "EPSS")
	}
	if len(extra) > 0 {
		s += " (+" + strings.Join(extra, ", ") + ")"
	}
	return s
}

// cveLine is e.g. "CVE-2024-1234 (high, KEV, EPSS 94%) https://...".
func cveLine(c risk.CVERef) string {
	tags := cveTags(c)
	s := c.ID
	if len(tags) > 0 {
		s += " (" + strings.Join(tags, ", ") + ")"
	}
	if c.URL != "" {
		s += " " + c.URL
	}
	return s
}

func cveTags(c risk.CVERef) []string {
	var tags []string
	if c.Priority != "" && c.Priority != "unknown" {
		tags = append(tags, c.Priority)
	}
	if c.KEV {
		tags = append(tags, "★ known exploited")
	}
	if c.EPSS >= 0.01 {
		tags = append(tags, fmt.Sprintf("EPSS %.0f%%", c.EPSS*100))
	}
	return tags
}

func (r *Report) suggestions() []string {
	var cmds []string
	var sec []string
	installable := 0
	for _, u := range r.Updates {
		if !u.Phased {
			installable++
		}
		if u.Security && u.Installed != "" {
			sec = append(sec, u.Package)
		}
	}
	if len(sec) > 0 {
		slices.Sort(sec)
		cmds = append(cmds, "sudo apt-get install --only-upgrade "+strings.Join(sec, " "))
	}
	if installable > len(sec) {
		cmds = append(cmds, "sudo apt-get update && sudo apt-get dist-upgrade  # all pending updates for this release, including new kernels; doesn't change release")
	}
	if r.System.Reboot.Required || (r.System.Kernel.Newest != "" && r.System.Kernel.Newest != r.System.Kernel.Running) {
		cmds = append(cmds, "sudo reboot")
	}
	return cmds
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
