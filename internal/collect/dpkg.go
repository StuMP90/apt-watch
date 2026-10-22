// Package collect gathers the facts aptwatch works from: installed
// packages, available updates and system state.
package collect

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

const DpkgStatusPath = "/var/lib/dpkg/status"

// Package is one installed binary package.
type Package struct {
	Name          string `json:"name"`
	Arch          string `json:"arch"`
	Version       string `json:"version"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
	Hold          bool   `json:"hold,omitempty"`
	// From the apt lists (AddRepos). Repo is the repository the installed
	// version comes from; ThirdParty means it isn't the distribution's, so
	// the distribution's CVE data doesn't cover it; InDistro means the
	// distribution has a package of that name; Local means no repository
	// offers the package at all.
	Repo       string `json:"repo,omitempty"`
	ThirdParty bool   `json:"third_party,omitempty"`
	InDistro   bool   `json:"in_distro,omitempty"`
	Local      bool   `json:"local,omitempty"`
}

// ReadDpkgStatus parses the dpkg status database at path.
func ReadDpkgStatus(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pkgs, err := ParseDpkgStatus(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pkgs, nil
}

// ParseDpkgStatus returns the installed packages in a dpkg status file.
func ParseDpkgStatus(r io.Reader) ([]Package, error) {
	var pkgs []Package
	fields := map[string]string{}
	flush := func() {
		defer clear(fields)
		status := strings.Fields(fields["Status"])
		if len(status) != 3 || status[2] != "installed" || fields["Package"] == "" {
			return
		}
		p := Package{
			Name:    fields["Package"],
			Arch:    fields["Architecture"],
			Version: fields["Version"],
			Hold:    status[0] == "hold",
		}
		p.Source, p.SourceVersion = p.Name, p.Version
		if src := fields["Source"]; src != "" {
			name, ver, found := strings.Cut(src, " ")
			p.Source = name
			if found {
				p.SourceVersion = strings.Trim(strings.TrimSpace(ver), "()")
			}
		}
		pkgs = append(pkgs, p)
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case line[0] == ' ' || line[0] == '\t':
			// Continuation of a multi-line field; nothing we need.
		default:
			k, v, ok := strings.Cut(line, ":")
			if ok {
				fields[k] = strings.TrimSpace(v)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return pkgs, nil
}
