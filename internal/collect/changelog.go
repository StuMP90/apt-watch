package collect

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"aptwatch/internal/debver"
	"aptwatch/internal/runx"
)

// DocDir is where installed packages keep their changelogs.
var DocDir = "/usr/share/doc"

// Changelog is what a third-party source package's Debian changelog says
// about CVEs (SPEC §5.3a). The distribution's CVE data doesn't describe
// third-party builds, but their changelogs usually name the CVEs each
// release fixes.
type Changelog struct {
	Source    string   `json:"source"`
	Installed string   `json:"installed"`           // installed source version
	Candidate string   `json:"candidate,omitempty"` // pending source version
	Fixed     []string `json:"fixed,omitempty"`     // CVEs named up to the installed version
	Pending   []string `json:"pending,omitempty"`   // CVEs named only after it, up to the candidate
	From      string   `json:"from"`                // the file or .deb it was read from
}

// ChangelogEntry is one entry of a Debian changelog.
type ChangelogEntry struct {
	Version string   `json:"version"`
	CVEs    []string `json:"cves,omitempty"`
}

var (
	// e.g. "php8.3 (8.3.36-1) unstable; urgency=medium"
	changelogHeader = regexp.MustCompile(`^(\S+) \(([^()\s]+)\)\s+[^;]*;\s*urgency=`)
	cveID           = regexp.MustCompile(`\bCVE-\d{4}-\d{4,}\b`)
)

// ParseChangelog returns the entries of a Debian changelog, newest first.
func ParseChangelog(r io.Reader) ([]ChangelogEntry, error) {
	var out []ChangelogEntry
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if m := changelogHeader.FindStringSubmatch(line); m != nil {
			out = append(out, ChangelogEntry{Version: m[2]})
			clear(seen)
			continue
		}
		if len(out) == 0 {
			continue
		}
		e := &out[len(out)-1]
		for _, id := range cveID.FindAllString(line, -1) {
			if !seen[id] {
				seen[id] = true
				e.CVEs = append(e.CVEs, id)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("not a Debian changelog")
	}
	return out, nil
}

// SplitChangelog sorts the CVEs named in entries into those fixed in the
// installed version and those only a newer version up to candidate fixes.
// A snapshot entry such as 8.3.36-1+0~20261021.1+ubuntu24.04~1.gbp250f7c
// sorts below the release it became, so it counts with it.
func SplitChangelog(entries []ChangelogEntry, installed, candidate string) (fixed, pending []string) {
	inFixed := map[string]bool{}
	for _, e := range entries {
		if debver.Compare(e.Version, installed) <= 0 {
			for _, id := range e.CVEs {
				if !inFixed[id] {
					inFixed[id] = true
					fixed = append(fixed, id)
				}
			}
		}
	}
	slices.Sort(fixed)
	if candidate == "" {
		return fixed, nil
	}
	for _, e := range entries {
		if debver.Compare(e.Version, installed) > 0 && debver.Compare(e.Version, candidate) <= 0 {
			for _, id := range e.CVEs {
				if !inFixed[id] && !slices.Contains(pending, id) {
					pending = append(pending, id)
				}
			}
		}
	}
	slices.Sort(pending)
	return fixed, pending
}

// ThirdPartySources returns the source packages whose installed binaries
// all come from third-party repositories.
func ThirdPartySources(pkgs []Package) []string {
	all := map[string]bool{}
	for _, pk := range pkgs {
		if v, ok := all[pk.Source]; !ok || v {
			all[pk.Source] = pk.ThirdParty
		}
	}
	var out []string
	for s, tp := range all {
		if tp {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// AddChangelogs reads the changelogs of the third-party source packages
// into inv.Changelogs: the installed one from DocDir, and for a pending
// update the candidate's, from the .deb that apt-get download fetches
// (third-party repositories rarely support apt-get changelog). The CVEs
// found in downloaded changelogs are cached in dir/changelogs. Problems
// are returned as warnings.
func AddChangelogs(ctx context.Context, inv *Inventory, dir string) []string {
	var warnings []string
	cache := filepath.Join(dir, "changelogs")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return []string{"changelogs: " + err.Error()}
	}
	used := map[string]bool{}
	inv.Changelogs = map[string]*Changelog{}
	for _, src := range ThirdPartySources(inv.Packages) {
		cl, err := readChangelog(ctx, inv, src, cache, used)
		// Many vendors' packages ship no changelog: the third-party
		// finding already says that their CVEs can't be checked.
		if err != nil && !errors.Is(err, errNoChangelog) {
			warnings = append(warnings, fmt.Sprintf("changelog of %s: %v", src, err))
		}
		if cl != nil {
			inv.Changelogs[src] = cl
		}
	}
	// Forget the versions no longer installed or pending.
	if des, err := os.ReadDir(cache); err == nil {
		for _, de := range des {
			if !used[de.Name()] {
				os.RemoveAll(filepath.Join(cache, de.Name()))
			}
		}
	}
	return warnings
}

func readChangelog(ctx context.Context, inv *Inventory, src, cache string, used map[string]bool) (*Changelog, error) {
	cl := &Changelog{Source: src}
	var bins []Package
	for _, pk := range inv.Packages {
		if pk.Source == src {
			bins = append(bins, pk)
			if cl.Installed == "" || debver.Compare(pk.SourceVersion, cl.Installed) > 0 {
				cl.Installed = pk.SourceVersion
			}
		}
	}
	var updates []Update // pending updates of src's binaries
	for _, u := range inv.Simulation.Updates {
		if u.Source == src && u.SourceVersion != "" && u.Installed != "" {
			updates = append(updates, u)
			if cl.Candidate == "" || debver.Compare(u.SourceVersion, cl.Candidate) > 0 {
				cl.Candidate = u.SourceVersion
			}
		}
	}
	// Binaries with their own doc directory first: their .deb carries
	// the changelog rather than a symlink to another package's.
	order := func(names []string) []string {
		own := func(n string) int {
			if fi, err := os.Lstat(filepath.Join(DocDir, n)); err == nil && fi.IsDir() {
				if n == src {
					return 0
				}
				return 1
			}
			return 2
		}
		slices.SortStableFunc(names, func(a, b string) int { return own(a) - own(b) })
		return names
	}

	var entries []ChangelogEntry
	var err error
	if cl.Candidate != "" {
		var names []string
		for _, u := range updates {
			if u.SourceVersion == cl.Candidate {
				names = append(names, u.Package+"="+u.Candidate)
			}
		}
		// The candidate's changelog covers the installed version too.
		if entries, cl.From, err = fetchChangelog(ctx, order(names), cache, used); err == nil {
			cl.Fixed, cl.Pending = SplitChangelog(entries, cl.Installed, cl.Candidate)
			return cl, nil
		}
		// The installed changelog still gives the fixed CVEs.
		err = fmt.Errorf("candidate %s: %w", cl.Candidate, err)
		cl.Candidate = ""
		if entries, cl.From, _ = installedChangelog(bins, order); entries == nil {
			return nil, err
		}
		cl.Fixed, _ = SplitChangelog(entries, cl.Installed, "")
		return cl, err
	}
	if entries, cl.From, err = installedChangelog(bins, order); err != nil {
		// No /usr/share/doc (a minimized image): download the installed
		// version, if the repository still has it.
		names := make([]string, 0, len(bins))
		for _, pk := range bins {
			names = append(names, pk.Name+"="+pk.Version)
		}
		if entries, cl.From, _ = fetchChangelog(ctx, order(names), cache, used); entries == nil {
			return nil, err
		}
	}
	cl.Fixed, cl.Pending = SplitChangelog(entries, cl.Installed, cl.Candidate)
	return cl, nil
}

// installedChangelog reads the first of bins' changelogs found in DocDir.
func installedChangelog(bins []Package, order func([]string) []string) ([]ChangelogEntry, string, error) {
	names := make([]string, 0, len(bins))
	for _, pk := range bins {
		names = append(names, pk.Name)
	}
	for _, n := range order(names) {
		for _, f := range []string{"changelog.Debian.gz", "changelog.gz"} {
			p := filepath.Join(DocDir, n, f)
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			e, err := parseGzChangelog(bytes.NewReader(b))
			if err == nil {
				return e, p, nil
			}
		}
	}
	return nil, "", fmt.Errorf("%w in %s", errNoChangelog, DocDir)
}

var errNoChangelog = errors.New("no changelog")

const maxChangelog = 32 << 20

func parseGzChangelog(r io.Reader) ([]ChangelogEntry, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	return ParseChangelog(io.LimitReader(zr, maxChangelog))
}

// fetchChangelog returns the changelog of the first of pkgs (name=version)
// whose .deb has one, from the cache or by downloading it.
func fetchChangelog(ctx context.Context, pkgs []string, cache string, used map[string]bool) ([]ChangelogEntry, string, error) {
	var errs []error
	for i, p := range pkgs {
		if i == 3 {
			break
		}
		key := url.PathEscape(p) + ".json"
		used[key] = true
		path := filepath.Join(cache, key)
		if b, err := os.ReadFile(path); err == nil {
			var e []ChangelogEntry
			if json.Unmarshal(b, &e) == nil {
				if len(e) > 0 {
					return e, p, nil
				}
				// Cached as having none: don't download it again.
				errs = append(errs, fmt.Errorf("%s: %w in the package", p, errNoChangelog))
				continue
			}
		}
		e, err := downloadChangelog(ctx, p, cache)
		if errors.Is(err, errNoChangelog) {
			os.WriteFile(path, []byte("[]"), 0o644)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		if b, err := json.Marshal(e); err == nil {
			os.WriteFile(path, b, 0o644)
		}
		return e, p, nil
	}
	if len(errs) == 0 {
		return nil, "", errors.New("no package to download")
	}
	return nil, "", errors.Join(errs...)
}

// downloadChangelog fetches pkg (name=version) with apt-get download and
// reads the changelog from its data archive.
func downloadChangelog(ctx context.Context, pkg, cache string) ([]ChangelogEntry, error) {
	tmp, err := os.MkdirTemp(cache, "download-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	// As root, apt hands the download to the _apt user, which needs to be
	// able to write here; otherwise it warns and downloads as root.
	os.Chmod(tmp, 0o777)
	if _, err := runx.Run(ctx, runx.Cmd{Name: "apt-get", Args: []string{"download", "-qq", pkg}, Dir: tmp, Timeout: 5 * time.Minute}); err != nil {
		return nil, err
	}
	debs, _ := filepath.Glob(filepath.Join(tmp, "*.deb"))
	if len(debs) != 1 {
		return nil, fmt.Errorf("apt-get download left %d .deb files", len(debs))
	}
	return debChangelog(ctx, debs[0])
}

// debChangelog streams a .deb's data archive through dpkg-deb and parses
// the first changelog in it.
func debChangelog(ctx context.Context, deb string) ([]ChangelogEntry, error) {
	bin, err := runx.LookPath("dpkg-deb")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--fsys-tarfile", deb)
	cmd.Env = []string{"PATH=" + runx.Path, "LC_ALL=C"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	e, perr := tarChangelog(out)
	cancel() // done reading: don't wait for the rest of the archive
	werr := cmd.Wait()
	if perr != nil {
		if werr != nil && ctx.Err() == nil {
			return nil, fmt.Errorf("dpkg-deb: %v: %s", werr, strings.TrimSpace(stderr.String()))
		}
		return nil, perr
	}
	return e, nil
}

// tarChangelog finds usr/share/doc/*/changelog.Debian.gz (or, for a
// native package, changelog.gz) in a tar stream. Symlinks to another
// package's directory don't count.
func tarChangelog(r io.Reader) ([]ChangelogEntry, error) {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%w in the package", errNoChangelog)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(h.Name, "./")
		dir, file := filepath.Split(name)
		if filepath.Dir(filepath.Clean(dir)) != "usr/share/doc" || (file != "changelog.Debian.gz" && file != "changelog.gz") {
			continue
		}
		if e, err := parseGzChangelog(tr); err == nil {
			return e, nil
		}
	}
}
