package collect

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"aptwatch/internal/debver"
)

// Repository origins whose packages the distributions' CVE data covers.
var officialOrigins = []string{"Ubuntu", "UbuntuESM", "UbuntuESMApps", "Debian", "Debian Backports"}

// listRepo is one apt repository, from its Release file in the lists dir.
type listRepo struct {
	prefix   string // file name prefix shared by its index files
	name     string // e.g. "packages.sury.org/php"
	official bool
}

// availVer is one version of a package that a repository offers.
type availVer struct {
	version string
	repo    *listRepo
}

// AddRepos sets Repo, ThirdParty, InDistro and Local on pkgs from the
// repositories' Release and Packages files in dir (/var/lib/apt/lists).
//
// The installed version is looked up in every repository's index. When no
// repository has it (the usual case once an update has superseded it), the
// package counts as third-party if a third-party repository offers it and
// its version is above every version the distribution offers: a PPA build
// of php8.3 (8.3.36-1+…) is newer than Ubuntu's (8.3.6-0ubuntu0.24.04.13).
func AddRepos(dir string, pkgs []Package) error {
	repos, err := readRepos(dir)
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		return fmt.Errorf("%s: no Release files", dir)
	}
	want := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		want[p.Name] = true
	}
	avail := map[string][]availVer{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []string
	for _, e := range ents {
		name := e.Name()
		if !isPackagesIndex(name) {
			continue
		}
		r := repoFor(repos, name)
		if r == nil {
			continue
		}
		if err := readPackagesIndex(filepath.Join(dir, name), r, want, avail); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	for i := range pkgs {
		classify(&pkgs[i], avail[pkgs[i].Name])
		if len(errs) > 0 {
			pkgs[i].Local = false // may be in an index we couldn't read
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("reading package indexes: %s", strings.Join(errs, "; "))
	}
	return nil
}

func classify(p *Package, avail []availVer) {
	var official, third *listRepo
	var bestOfficial string
	for _, a := range avail {
		if a.repo.official {
			p.InDistro = true
			if bestOfficial == "" || debver.Compare(a.version, bestOfficial) > 0 {
				bestOfficial = a.version
			}
		}
		if a.version != p.Version {
			continue
		}
		if a.repo.official && official == nil {
			official = a.repo
		} else if !a.repo.official && third == nil {
			third = a.repo
		}
	}
	switch {
	case official != nil:
		p.Repo = official.name
	case third != nil:
		p.Repo, p.ThirdParty = third.name, true
	case len(avail) == 0:
		p.Local = true
	default:
		// Superseded: judge by the repository that offers the name.
		for _, a := range avail {
			if !a.repo.official && (bestOfficial == "" || debver.Compare(p.Version, bestOfficial) > 0) {
				p.Repo, p.ThirdParty = a.repo.name, true
				return
			}
		}
		for _, a := range avail {
			if a.repo.official {
				p.Repo = a.repo.name
				return
			}
		}
	}
}

// readRepos reads the InRelease and Release files in dir.
func readRepos(dir string) ([]*listRepo, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var repos []*listRepo
	for _, e := range ents {
		name := e.Name()
		prefix, ok := strings.CutSuffix(name, "InRelease")
		if !ok {
			if prefix, ok = strings.CutSuffix(name, "Release"); !ok {
				continue
			}
		}
		if slices.ContainsFunc(repos, func(r *listRepo) bool { return r.prefix == prefix }) {
			continue // both InRelease and Release
		}
		origin, err := releaseOrigin(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		repos = append(repos, &listRepo{
			prefix:   prefix,
			name:     repoName(prefix),
			official: slices.Contains(officialOrigins, origin),
		})
	}
	// Longest prefix first, so repoFor finds the most specific match.
	slices.SortFunc(repos, func(a, b *listRepo) int { return len(b.prefix) - len(a.prefix) })
	return repos, nil
}

func releaseOrigin(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" && sc.Err() == nil {
			continue // InRelease: blank line after the PGP header
		}
		if v, ok := strings.CutPrefix(line, "Origin:"); ok {
			return strings.TrimSpace(v), nil
		}
		if strings.HasPrefix(line, "SHA256:") || strings.HasPrefix(line, "MD5Sum:") {
			break // the header fields are over
		}
	}
	return "", sc.Err()
}

// repoName turns a lists file prefix into a readable repository name:
// "packages.sury.org_php_dists_noble_" → "packages.sury.org/php". apt
// escapes "_" in the URL as %5f, so every "_" is a "/".
func repoName(prefix string) string {
	s := strings.TrimSuffix(prefix, "_")
	if i := strings.Index(s, "_dists_"); i >= 0 {
		s = s[:i]
	}
	s = strings.ReplaceAll(s, "_", "/")
	return strings.NewReplacer("%5f", "_", "%5F", "_", "%40", "@", "%3a", ":", "%3A", ":").Replace(s)
}

func repoFor(repos []*listRepo, file string) *listRepo {
	for _, r := range repos {
		if strings.HasPrefix(file, r.prefix) {
			return r
		}
	}
	return nil
}

func isPackagesIndex(name string) bool {
	return strings.HasSuffix(name, "_Packages") || strings.HasSuffix(name, "_Packages.gz")
}

// readPackagesIndex adds the versions in one Packages file of the packages
// in want to avail.
func readPackagesIndex(path string, r *listRepo, want map[string]bool, avail map[string][]availVer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var rd io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		rd = gz
	}
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var pkg string
	for sc.Scan() {
		line := sc.Bytes()
		switch {
		case len(line) == 0:
			pkg = ""
		case bytes.HasPrefix(line, []byte("Package: ")):
			pkg = string(bytes.TrimSpace(line[len("Package: "):]))
		case pkg != "" && bytes.HasPrefix(line, []byte("Version: ")):
			if want[pkg] {
				avail[pkg] = append(avail[pkg], availVer{string(bytes.TrimSpace(line[len("Version: "):])), r})
			}
		}
	}
	return sc.Err()
}
