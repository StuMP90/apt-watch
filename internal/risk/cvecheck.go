package risk

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/debver"
	"aptwatch/internal/vulndb"
)

// The statuses of a CVE in an installed source package (SPEC §3.1), and
// overall. The overall status is the package status highest in this list;
// with no affected package installed it is not-affected if the data knows
// the CVE, else unknown.
const (
	StatusUnreachable   = "fix-unreachable"  // fixed in a version apt can't install
	StatusPro           = "fix-requires-pro" // fixed in Ubuntu Pro (ESM) only
	StatusPending       = "fix-pending"      // a pending update fixes it
	StatusRebootPending = "reboot-pending"   // fixed on disk, not yet running
	StatusNoFix         = "no-fix"           // no fix published yet
	StatusUnconfirmed   = "unconfirmed"      // third-party: the distribution fixed it, the changelog doesn't say
	StatusUnknown       = "unknown"          // can't tell
	StatusFixed         = "fixed"
	StatusNotAffected   = "not-affected" // overall only: no affected package installed
)

var statusOrder = []string{
	StatusUnreachable, StatusPro, StatusPending, StatusRebootPending, StatusNoFix,
	StatusUnconfirmed, StatusUnknown, StatusFixed, StatusNotAffected,
}

// NeedsAction reports whether a CVE status calls for something to be done
// (exit code 1); StatusUnknown is a warning (2).
func NeedsAction(status string) bool {
	return CompareStatus(status, StatusUnknown) < 0
}

// CompareStatus orders CVE statuses most in need of action first.
func CompareStatus(a, b string) int {
	return slices.Index(statusOrder, a) - slices.Index(statusOrder, b)
}

// CVECheck is the status of one CVE on the host (aptwatch cve).
type CVECheck struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Known     bool      `json:"known"` // in the vulnerability data or a changelog
	Priority  string    `json:"priority,omitempty"`
	Desc      string    `json:"description,omitempty"`
	URL       string    `json:"url,omitempty"`
	Published time.Time `json:"published,omitzero"`
	KEV       bool      `json:"kev,omitempty"`
	KEVAdded  time.Time `json:"kev_added,omitzero"`
	EPSS      float64   `json:"epss,omitempty"`
	// Packages are the installed source packages it affects.
	Packages []CVEPackage `json:"packages"`
	// NotInstalled are the affected source packages that aren't installed.
	NotInstalled []string `json:"not_installed,omitempty"`
}

// CVEPackage is the status of a CVE in one installed source package.
type CVEPackage struct {
	Source    string   `json:"source"`
	Status    string   `json:"status"`
	Repo      string   `json:"repo,omitempty"`
	Installed string   `json:"installed"`
	Candidate string   `json:"candidate,omitempty"`
	Fixed     string   `json:"fixed,omitempty"` // the version that fixes it, if known
	Binaries  []string `json:"binaries"`
	Note      string   `json:"note,omitempty"`
	Command   string   `json:"command,omitempty"` // what installs the fix
}

var cveID = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// NormCVE returns id in upper case if it is a CVE ID, else an error.
func NormCVE(id string) (string, error) {
	id = strings.TrimSpace(id)
	if !cveID.MatchString(id) {
		return "", fmt.Errorf("%q is not a CVE ID (CVE-YYYY-NNNN)", id)
	}
	return strings.ToUpper(id), nil
}

// CheckCVE works out the status of CVE id on the host: in the installed
// distribution source packages from db's advisories, as for CVEFindings,
// and in the third-party ones from their changelogs, as for
// changelogFindings. db may be nil.
func CheckCVE(inv *collect.Inventory, db *vulndb.DB, id string) CVECheck {
	c := CVECheck{ID: id, Packages: []CVEPackage{}}
	if db != nil {
		if a, ok := db.Lookup(id); ok {
			c.Known = true
			c.Priority, c.Desc, c.Published = a.Priority, a.Desc, a.Published
		}
		c.URL = db.URL(id)
		c.KEVAdded, c.KEV = db.KEV[id]
		c.EPSS = db.EPSS[id]
	}

	srcs := installedSources(inv)
	skip := map[string]bool{}
	for _, n := range otherKernels(inv, srcs) {
		skip[n] = true
	}
	third := map[string]bool{}
	for _, n := range thirdPartySources(inv) {
		third[n] = true
	}
	repo := map[string]string{}
	for _, pk := range inv.Packages {
		if repo[pk.Source] == "" || pk.ThirdParty {
			repo[pk.Source] = pk.Repo
		}
	}
	distro := distroName(inv.System.OS.ID)

	var advs map[string]vulndb.Advisory // source → advisory for id
	if db != nil {
		advs = map[string]vulndb.Advisory{}
		for src, as := range db.Advisories {
			for _, a := range as {
				if a.CVE == id {
					advs[src] = a
				}
			}
		}
	}
	// Third-party changelogs that name it count even where no advisory
	// does: many third-party packages aren't in the distribution.
	names := map[string]bool{}
	for src := range advs {
		names[src] = true
	}
	for src, cl := range inv.Changelogs {
		if slices.Contains(cl.Fixed, id) || slices.Contains(cl.Pending, id) {
			names[src] = true
			c.Known = true
		}
	}

	for _, src := range slices.Sorted(maps.Keys(names)) {
		s := srcs[src]
		if s == nil {
			c.NotInstalled = append(c.NotInstalled, src)
			continue
		}
		if skip[src] {
			continue // an old kernel: the newest one's status counts
		}
		a, hasAdv := advs[src]
		p := CVEPackage{Source: src, Repo: repo[src], Installed: s.installed, Candidate: s.candidate, Fixed: a.Fixed}
		for _, r := range s.pkgs {
			p.Binaries = append(p.Binaries, r.Name)
		}
		if third[src] {
			thirdPartyStatus(&p, inv.Changelogs[src], id, a, hasAdv, distro)
		} else {
			distroStatus(&p, a)
		}
		if p.Status == StatusPending {
			var bins []string
			for _, r := range s.pkgs {
				if r.Candidate != "" {
					bins = append(bins, r.Name)
				}
			}
			if len(bins) > 0 {
				p.Command = "sudo apt-get install --only-upgrade " + strings.Join(bins, " ")
			}
		}
		if p.Status == StatusFixed {
			rebootStatus(&p, inv)
		}
		c.Packages = append(c.Packages, p)
	}

	c.Status = StatusNotAffected
	if !c.Known {
		c.Status = StatusUnknown
	}
	for _, p := range c.Packages {
		if CompareStatus(p.Status, c.Status) < 0 {
			c.Status = p.Status
		}
	}
	return c
}

// distroStatus judges a distribution package by its advisory, as
// CVEFindings does.
func distroStatus(p *CVEPackage, a vulndb.Advisory) {
	switch {
	case a.Fixed != "" && debver.Compare(p.Installed, a.Fixed) >= 0:
		p.Status = StatusFixed
	case a.Fixed != "" && p.Candidate != "" && debver.Compare(p.Candidate, a.Fixed) >= 0:
		p.Status = StatusPending
	case a.Fixed != "" && a.Pro:
		p.Status = StatusPro
		p.Note = "the fix is in Ubuntu Pro (ESM): attach Pro, or check that the esm sources are enabled"
	case a.Fixed != "":
		p.Status = StatusUnreachable
		p.Note = "check the configured apt sources, holds and pins"
	default:
		p.Status = StatusNoFix
	}
}

// thirdPartyStatus judges a third-party package by its changelogs, as
// changelogFindings does.
func thirdPartyStatus(p *CVEPackage, cl *collect.Changelog, id string, a vulndb.Advisory, hasAdv bool, distro string) {
	from := p.Repo
	if from == "" {
		from = "the third-party repository"
	}
	switch {
	case cl == nil:
		p.Status = StatusUnknown
		p.Note = fmt.Sprintf("from %s, and its changelog wasn't read (vulndb.changelogs in the config)", from)
	case slices.Contains(cl.Fixed, id):
		p.Status = StatusFixed
		p.Fixed = ""
		p.Note = "named in the installed package's changelog"
	case slices.Contains(cl.Pending, id):
		p.Status = StatusPending
		p.Fixed = cl.Candidate
		p.Note = "named in the changelog of the pending update " + cl.Candidate
	case hasAdv && a.Fixed == "":
		p.Status = StatusNoFix
		p.Note = fmt.Sprintf("%s has no fix yet, and %s's changelog doesn't mention it", distro, from)
	case hasAdv:
		p.Status = StatusUnconfirmed
		p.Note = fmt.Sprintf("%s fixed it in %s; %s's changelog doesn't mention it, but the fix may be there under "+
			"another description: check the repository's announcements", distro, a.Fixed, from)
	}
}

// rebootStatus marks a fix that is installed but not yet running: in the
// kernel that runs after the next reboot, or in a package the system says
// needs one.
func rebootStatus(p *CVEPackage, inv *collect.Inventory) {
	k := inv.System.Kernel
	if inv.System.Reboot.Required && slices.Contains(inv.System.Reboot.Packages, p.Source) {
		p.Status = StatusRebootPending
		p.Note = join(p.Note, "fixed, but the system needs a reboot for it to take effect")
		return
	}
	for _, b := range p.Binaries {
		if k.Newest != "" && k.Running != k.Newest &&
			(b == "linux-image-"+k.Newest || b == "linux-image-unsigned-"+k.Newest || b == "linux-modules-"+k.Newest) {
			p.Status = StatusRebootPending
			p.Note = join(p.Note, fmt.Sprintf("fixed in kernel %s, but %s is running: reboot to run the fix", k.Newest, k.Running))
			return
		}
		if inv.System.Reboot.Required && slices.Contains(inv.System.Reboot.Packages, b) {
			p.Status = StatusRebootPending
			p.Note = join(p.Note, "fixed, but the system needs a reboot for "+b+" to take effect")
			return
		}
	}
}
