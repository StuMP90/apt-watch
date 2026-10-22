package risk

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"aptwatch/internal/collect"
)

// thirdPartySources returns the source packages whose installed binaries
// all come from third-party repositories. The distribution's CVE data
// describes the distribution's builds, so it says nothing about these: a
// PPA's php8.3 8.3.36-1 isn't "fixed" just because it sorts above
// Ubuntu's 8.3.6-0ubuntu0.24.04.13.
func thirdPartySources(inv *collect.Inventory) []string {
	return collect.ThirdPartySources(inv.Packages)
}

// thirdPartyFindings reports, per repository, the installed packages from
// third-party repositories. Those that replace distribution packages are
// Low: the distribution's security updates no longer reach them. The rest
// are Info. Their CVEs come from their changelogs (changelogFindings).
func thirdPartyFindings(inv *collect.Inventory) []Finding {
	type repo struct {
		name     string
		pkgs     []PkgRef
		replaces []PkgRef // those the distribution also ships
		pending  int
		read     int // packages whose source's changelog was read
	}
	repos := map[string]*repo{}
	cand := map[string]string{}
	for _, u := range inv.Simulation.Updates {
		cand[u.Package] = u.Candidate
	}
	for _, pk := range inv.Packages {
		if !pk.ThirdParty {
			continue
		}
		r := repos[pk.Repo]
		if r == nil {
			r = &repo{name: pk.Repo}
			repos[pk.Repo] = r
		}
		ref := PkgRef{Name: pk.Name, Installed: pk.Version, Candidate: cand[pk.Name], Origin: pk.Repo}
		r.pkgs = append(r.pkgs, ref)
		if pk.InDistro {
			r.replaces = append(r.replaces, ref)
		}
		if cand[pk.Name] != "" {
			r.pending++
		}
		if inv.Changelogs[pk.Source] != nil {
			r.read++
		}
	}
	distro := distroName(inv.System.OS.ID)
	var out []Finding
	for _, r := range repos {
		f := Finding{
			Key: "third-party:" + r.name, Kind: KindThirdParty, Severity: Info,
			Packages: r.pkgs, FixAvail: r.pending > 0,
		}
		f.Title = fmt.Sprintf("%s from %s (%s) %s covered by %s's CVE data",
			plural(len(r.pkgs), "package"), r.name, sample(r.pkgs, 4), isAre(len(r.pkgs), "isn't", "aren't"), distro)
		var notes []string
		if n := len(r.replaces); n > 0 {
			f.Severity = Low
			who, it := isAre(n, "It replaces", "They replace"), isAre(n, "it", "them")
			if n < len(r.pkgs) {
				who = fmt.Sprintf("%d of them (%s) %s", n, sample(r.replaces, 4), isAre(n, "replaces", "replace"))
			}
			notes = append(notes, fmt.Sprintf("%s %s's own %s, so %s's security updates no longer reach %s",
				who, distro, isAre(n, "package", "packages"), distro, it))
		}
		if r.read > 0 {
			notes = append(notes, "aptwatch reads the CVEs named in "+isAre(len(r.pkgs), "its changelog", "their changelogs")+
				", but can't tell which CVEs a changelog leaves out: keep this repository's updates applied")
		} else {
			notes = append(notes, "aptwatch can't check "+isAre(len(r.pkgs), "it", "them")+" for CVEs: keep this repository's updates applied")
		}
		if r.pending > 0 {
			notes = append(notes, fmt.Sprintf("%s from it pending", plural(r.pending, "update")))
		}
		f.Detail = strings.Join(notes, ". ") + "."
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Finding) int { return cmp.Compare(a.Key, b.Key) })
	return out
}

func distroName(id string) string {
	switch id {
	case "ubuntu":
		return "Ubuntu"
	case "debian":
		return "Debian"
	}
	return "the distribution"
}

// sample names up to n packages, preferring distinct name stems so that
// php8.3-cli, php8.3-fpm, … don't crowd out php8.4.
func sample(pkgs []PkgRef, n int) string {
	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	slices.Sort(names)
	var picked []string
	seen := map[string]bool{}
	for _, nm := range names {
		stem, _, _ := strings.Cut(nm, "-")
		if !seen[stem] {
			seen[stem] = true
			picked = append(picked, nm)
		}
	}
	for _, nm := range names {
		if len(picked) >= len(names) || len(picked) >= n+1 {
			break
		}
		if !slices.Contains(picked, nm) {
			picked = append(picked, nm)
		}
	}
	more := len(picked) > n
	picked = picked[:min(n, len(picked))]
	slices.Sort(picked)
	if more {
		return strings.Join(picked, ", ") + ", …"
	}
	return strings.Join(picked, ", ")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func isAre(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
