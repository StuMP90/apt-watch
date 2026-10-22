package risk

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/debver"
	"aptwatch/internal/vulndb"
)

// AddCVEFindings matches the installed source packages against db
// (SPEC §6.4) and adds the CVE findings to fs. A security update whose
// source package has a CVE fixed by the pending update is dropped: the
// CVE findings describe it better. Third-party sources are judged by
// their changelogs instead (changelogFindings).
func AddCVEFindings(fs []Finding, inv *collect.Inventory, db *vulndb.DB, p Policy, now time.Time) []Finding {
	cves := append(CVEFindings(inv, db, p), changelogFindings(inv, db, p, now)...)
	covered := map[string]bool{}
	for _, f := range cves {
		if f.Kind == KindCVEFixAvailable {
			covered[f.Source] = true
		}
	}
	out := slices.DeleteFunc(fs, func(f Finding) bool {
		return f.Kind == KindSecurityUpdate && covered[f.Source]
	})
	out = append(out, cves...)
	Sort(out)
	return out
}

// srcPkg is one installed source package.
type srcPkg struct {
	installed string // highest installed source version
	candidate string // highest source version among pending updates
	pkgs      []PkgRef
}

func installedSources(inv *collect.Inventory) map[string]*srcPkg {
	srcs := map[string]*srcPkg{}
	cand := map[string]string{} // binary name → candidate version
	for _, u := range inv.Simulation.Updates {
		cand[u.Package] = u.Candidate
	}
	for _, pk := range inv.Packages {
		s := srcs[pk.Source]
		if s == nil {
			s = &srcPkg{}
			srcs[pk.Source] = s
		}
		if s.installed == "" || debver.Compare(pk.SourceVersion, s.installed) > 0 {
			s.installed = pk.SourceVersion
		}
		if !slices.ContainsFunc(s.pkgs, func(r PkgRef) bool { return r.Name == pk.Name }) {
			s.pkgs = append(s.pkgs, PkgRef{Name: pk.Name, Installed: pk.Version, Candidate: cand[pk.Name]})
		}
	}
	srcOf := collect.SourceOf(inv.Packages)
	for _, u := range inv.Simulation.Updates {
		name, ver := u.Source, u.SourceVersion
		if name == "" { // apt-cache couldn't say; assume the usual case
			name, ver = srcOf[u.Package], u.Candidate
		}
		s := srcs[name]
		if s == nil || ver == "" { // a new install: nothing vulnerable installed yet
			continue
		}
		if s.candidate == "" || debver.Compare(ver, s.candidate) > 0 {
			s.candidate = ver
		}
	}
	return srcs
}

// CVEFindings returns the CVE findings for the installed packages.
func CVEFindings(inv *collect.Inventory, db *vulndb.DB, p Policy) []Finding {
	if db == nil {
		return nil
	}
	var out []Finding
	unfixed := map[string]int{} // source → CVEs reported only in the summary
	nUnfixed := 0
	srcs := installedSources(inv)
	for _, n := range otherKernels(inv, srcs) {
		delete(srcs, n)
	}
	for _, n := range thirdPartySources(inv) {
		delete(srcs, n)
	}
	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, name := range names {
		s := srcs[name]
		for _, a := range db.Advisories[name] {
			ref := CVERef{ID: a.CVE, Priority: a.Priority, Fixed: a.Fixed, URL: db.URL(a.CVE), EPSS: db.EPSS[a.CVE]}
			_, ref.KEV = db.KEV[a.CVE]
			f := Finding{
				Key: "cve:" + a.CVE + ":" + name, Source: name,
				Packages: s.pkgs, CVEs: []CVERef{ref}, Detail: a.Desc,
			}
			var note string
			switch {
			case a.Fixed != "" && debver.Compare(s.installed, a.Fixed) >= 0:
				continue
			case a.Fixed != "" && s.candidate != "" && debver.Compare(s.candidate, a.Fixed) >= 0:
				f.Kind, f.FixAvail = KindCVEFixAvailable, true
				f.Severity = cveSeverity(ref, p)
				f.Title = fmt.Sprintf("%s in %s %s: fixed by pending update %s", a.CVE, name, s.installed, s.candidate)
			case a.Fixed != "":
				f.Kind = KindCVEFixUnreachable
				f.Severity = cveSeverity(ref, p).Bump(1)
				f.Title = fmt.Sprintf("%s in %s %s: fixed in %s, which apt can't install", a.CVE, name, s.installed, a.Fixed)
				note = "check the configured apt sources, holds and pins"
				if a.Pro {
					f.Title = fmt.Sprintf("%s in %s %s: fixed in %s, available with Ubuntu Pro", a.CVE, name, s.installed, a.Fixed)
					note = "the fix is in Ubuntu Pro (ESM): attach Pro, or check that the esm sources are enabled"
				}
			default:
				if !ref.KEV && p.ReportUnfixed != UnfixedFull {
					if p.ReportUnfixed != UnfixedNone {
						unfixed[name]++
						nUnfixed++
					}
					continue
				}
				f.Kind, f.Severity = KindCVEUnfixed, Info
				if ref.KEV {
					f.Severity = High
				}
				f.Title = fmt.Sprintf("%s in %s %s: no fix available yet", a.CVE, name, s.installed)
			}
			if ref.KEV {
				note = join(note, "known to be exploited (CISA KEV)")
			}
			f.Detail = join(f.Detail, note)
			out = append(out, f)
		}
	}
	if nUnfixed > 0 {
		out = append(out, unfixedSummary(unfixed, nUnfixed))
	}
	return out
}

// abiPkg matches a kernel binary whose name carries its ABI, e.g.
// linux-modules-6.8.0-91-generic. A new kernel is a new package, so old
// ones stay installed at their old version and never get upgraded.
var abiPkg = regexp.MustCompile(`^linux-(image|modules|headers|tools|cloud-tools|buildinfo|objects)(-[a-z]+)*-\d+\.\d+\.\d+-\d+`)

// otherKernels returns the kernel source packages that don't build the
// kernel that will run after the next reboot (the newest installed one).
// Like debsecan and Ubuntu's OVAL data, only that kernel's CVEs count: the
// old kernels' are fixed by the newer kernel, and the reboot-required
// finding covers the time until it runs.
func otherKernels(inv *collect.Inventory, srcs map[string]*srcPkg) []string {
	rel := inv.System.Kernel.Newest
	if rel == "" {
		rel = inv.System.Kernel.Running
	}
	if rel == "" {
		return nil
	}
	kernels := map[string]bool{}
	var image, modules string
	for _, pk := range inv.Packages {
		if abiPkg.MatchString(pk.Name) {
			kernels[pk.Source] = true
		}
		switch pk.Name {
		case "linux-image-" + rel, "linux-image-unsigned-" + rel:
			image = pk.Source
		case "linux-modules-" + rel:
			modules = pk.Source
		}
	}
	if _, ok := srcs["linux"]; ok {
		kernels["linux"] = true
	}
	// Ubuntu builds the modules from the source the advisories name; the
	// image may come from a linux-signed-* wrapper. Debian's signed image
	// (linux-signed-amd64) wraps "linux".
	keep := modules
	if keep == "" {
		keep = image
		if r, ok := strings.CutPrefix(image, "linux-signed"); ok {
			keep = "linux" + r
			if !kernels[keep] {
				keep = "linux"
			}
		}
	}
	if keep == "" {
		return nil // can't tell which kernel runs: judge them all
	}
	var out []string
	for n := range kernels {
		if n != keep {
			out = append(out, n)
		}
	}
	return out
}

// cveSeverity is the base severity of a fixable CVE.
func cveSeverity(c CVERef, p Policy) Severity {
	if c.KEV {
		return Critical
	}
	var s Severity
	switch c.Priority {
	case "critical":
		s = Critical
	case "high":
		s = High
	case "low", "negligible":
		s = Low
	default:
		s = Medium
	}
	if p.EPSSBump > 0 && c.EPSS >= p.EPSSBump {
		s = s.Bump(1)
	}
	return s
}

func unfixedSummary(bySrc map[string]int, n int) Finding {
	type sc struct {
		src string
		n   int
	}
	var l []sc
	for s, k := range bySrc {
		l = append(l, sc{s, k})
	}
	slices.SortFunc(l, func(a, b sc) int {
		if c := cmp.Compare(b.n, a.n); c != 0 {
			return c
		}
		return cmp.Compare(a.src, b.src)
	})
	var parts []string
	for i, e := range l {
		if i == 10 {
			parts = append(parts, fmt.Sprintf("and %d more", len(l)-10))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", e.src, e.n))
	}
	return Finding{
		Key: KindCVEUnfixedSummary, Kind: KindCVEUnfixedSummary, Severity: Info,
		Title:  fmt.Sprintf("%d CVEs with no fix yet affect %d installed source packages", n, len(l)),
		Detail: strings.Join(parts, ", "),
	}
}

func join(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return strings.TrimRight(a, ". ") + ". " + strings.ToUpper(b[:1]) + b[1:] + "."
}
