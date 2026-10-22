package risk

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/vulndb"
)

// Kinds for findings from third-party changelogs (SPEC §6.4a).
const (
	KindCVEFixedThirdParty = "cve-fixed-third-party"
	KindCVEThirdPartyGap   = "cve-third-party-unconfirmed"
)

// changelogFindings judges the third-party sources by the CVEs their
// Debian changelogs name (collect.AddChangelogs):
//   - a CVE named only in the pending update's changelog is fixed by it;
//   - recently published CVEs named in the installed changelog are
//     reported, as Info, so that a fix that came in is visible;
//   - recent CVEs that the distribution fixed in its own build of the same
//     source, but that neither changelog names, may be unfixed.
//
// Severities come from the distribution's data for the CVE, looked up by
// ID, whichever source package it was filed under.
func changelogFindings(inv *collect.Inventory, db *vulndb.DB, p Policy, now time.Time) []Finding {
	if len(inv.Changelogs) == 0 {
		return nil
	}
	srcs := installedSources(inv)
	repo := map[string]string{}
	for _, pk := range inv.Packages {
		if pk.ThirdParty && repo[pk.Source] == "" {
			repo[pk.Source] = pk.Repo
		}
	}
	distro := distroName(inv.System.OS.ID)
	recent := func(a vulndb.Advisory) bool {
		return p.RecentCVEs > 0 && !a.Published.IsZero() && now.Sub(a.Published) <= p.RecentCVEs
	}
	cveRef := func(id string) (CVERef, vulndb.Advisory, bool) {
		a, ok := db.Lookup(id)
		ref := CVERef{ID: id, Priority: a.Priority, URL: db.URL(id), EPSS: db.EPSS[id]}
		_, ref.KEV = db.KEV[id]
		return ref, a, ok
	}

	names := make([]string, 0, len(inv.Changelogs))
	for n := range inv.Changelogs {
		names = append(names, n)
	}
	slices.Sort(names)
	var out []Finding
	for _, name := range names {
		cl := inv.Changelogs[name]
		var pkgs []PkgRef
		if s := srcs[name]; s != nil {
			pkgs = s.pkgs
		}
		for _, id := range cl.Pending {
			ref, a, _ := cveRef(id)
			ref.Fixed = cl.Candidate
			out = append(out, Finding{
				Key: "cve:" + id + ":" + name, Kind: KindCVEFixAvailable, Source: name,
				Severity: cveSeverity(ref, p), FixAvail: true, Packages: pkgs, CVEs: []CVERef{ref},
				Title:  fmt.Sprintf("%s in %s %s: fixed by pending update %s", id, name, cl.Installed, cl.Candidate),
				Detail: join(join(a.Desc, "named in the changelog of "+cl.Candidate+" from "+repo[name]), kevNote(ref)),
			})
		}

		var fixed []CVERef
		for _, id := range cl.Fixed {
			if ref, a, ok := cveRef(id); ok && recent(a) {
				fixed = append(fixed, ref)
			}
		}
		if len(fixed) > 0 {
			out = append(out, Finding{
				Key: "changelog-cves:" + name, Kind: KindCVEFixedThirdParty, Severity: Info,
				Source: name, Packages: pkgs, CVEs: fixed,
				Title: fmt.Sprintf("%s %s from %s fixes %s", name, cl.Installed, repo[name], cveSummary(fixed)),
				Detail: fmt.Sprintf("Named in the installed package's changelog and published in the last %d days. No action needed",
					int(p.RecentCVEs.Hours()/24)),
			})
		}

		if !p.ThirdPartyGaps || len(cl.Fixed)+len(cl.Pending) == 0 {
			continue // a changelog that names no CVEs can't be judged by what it leaves out
		}
		named := map[string]bool{}
		for _, id := range slices.Concat(cl.Fixed, cl.Pending) {
			named[id] = true
		}
		for _, a := range db.Advisories[name] {
			if a.Fixed == "" || named[a.CVE] || !recent(a) {
				continue
			}
			ref, _, _ := cveRef(a.CVE)
			ref.Priority, ref.Fixed = a.Priority, a.Fixed
			sev := max(cveSeverity(ref, p).Bump(-1), Low)
			if ref.KEV {
				sev = High
			}
			out = append(out, Finding{
				Key: "cve-gap:" + a.CVE + ":" + name, Kind: KindCVEThirdPartyGap, Source: name,
				Severity: sev, Packages: pkgs, CVEs: []CVERef{ref},
				Title: fmt.Sprintf("%s in %s %s: %s fixed it in %s; %s's changelog doesn't mention it",
					a.CVE, name, cl.Installed, distro, a.Fixed, repo[name]),
				Detail: join(join(a.Desc, fmt.Sprintf("this matches %s's advisory to the third-party package by source name only, "+
					"and the fix may be in the package under another description: check the repository's announcements", distro)), kevNote(ref)),
			})
		}
	}
	return out
}

// cveSummary names up to three CVEs, and counts more by priority, e.g.
// "15 recent CVEs (2 critical, 13 medium)": the report lists them below.
func cveSummary(refs []CVERef) string {
	if len(refs) <= 3 {
		var ids []string
		for _, r := range refs {
			ids = append(ids, r.ID+priorityNote(r))
		}
		return plural(len(refs), "recent CVE") + ": " + strings.Join(ids, ", ")
	}
	counts := map[string]int{}
	for _, r := range refs {
		switch {
		case r.KEV:
			counts["exploited"]++
		case r.Priority == "":
			counts["unknown"]++
		default:
			counts[r.Priority]++
		}
	}
	var parts []string
	for _, pr := range []string{"exploited", "critical", "high", "medium", "low", "negligible", "unknown"} {
		if n := counts[pr]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, pr))
		}
	}
	return fmt.Sprintf("%s (%s)", plural(len(refs), "recent CVE"), strings.Join(parts, ", "))
}

func priorityNote(r CVERef) string {
	switch {
	case r.KEV:
		return " (exploited)"
	case r.Priority != "" && r.Priority != "unknown":
		return " (" + r.Priority + ")"
	}
	return ""
}

func kevNote(r CVERef) string {
	if r.KEV {
		return "known to be exploited (CISA KEV)"
	}
	return ""
}
