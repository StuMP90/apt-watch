package collect

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"time"

	"aptwatch/internal/runx"
)

// Held is a package on hold (apt-mark hold), which apt won't upgrade.
// Candidate is set when a newer version is available; Suites are the
// archive suites it is in.
type Held struct {
	Package   string   `json:"package"`
	Arch      string   `json:"arch"`
	Installed string   `json:"installed"`
	Candidate string   `json:"candidate,omitempty"`
	Suites    []string `json:"suites,omitempty"`
	Security  bool     `json:"security,omitempty"`
}

// HeldPackages returns the installed packages on hold, with the update
// each is held back from, from apt-cache policy.
func (h Host) HeldPackages(ctx context.Context, pkgs []Package) ([]Held, error) {
	var held []Held
	args := []string{"policy"}
	for _, p := range pkgs {
		if p.Hold {
			held = append(held, Held{Package: p.Name, Arch: p.Arch, Installed: p.Version})
			args = append(args, p.Name+":"+p.Arch)
		}
	}
	if len(held) == 0 {
		return nil, nil
	}
	res, err := h.run(ctx, runx.Cmd{Name: "apt-cache", Args: args, Timeout: 2 * time.Minute})
	if err != nil && len(res.Stdout) == 0 {
		return held, err
	}
	pol, err := ParseAptCachePolicy(bytes.NewReader(res.Stdout))
	if err != nil {
		return held, err
	}
	for i := range held {
		hd := &held[i]
		c, ok := pol[hd.Package+":"+hd.Arch]
		if !ok {
			c, ok = pol[hd.Package]
		}
		if !ok || c.Candidate == "" || c.Candidate == "(none)" || c.Candidate == hd.Installed {
			continue
		}
		hd.Candidate, hd.Suites = c.Candidate, c.Suites
		hd.Security = slices.ContainsFunc(c.Suites, func(s string) bool { return IsSecurityOrigin(Origin{Suite: s}) })
	}
	return held, nil
}

// AptPolicy is one package's apt-cache policy: its candidate version and
// the suites (e.g. bookworm-security) that offer it.
type AptPolicy struct {
	Candidate string
	Suites    []string
}

// ParseAptCachePolicy parses apt-cache policy output, keyed by the
// package name as apt prints it (with ":arch" when asked for one).
func ParseAptCachePolicy(r io.Reader) (map[string]AptPolicy, error) {
	out := map[string]AptPolicy{}
	var name, ver string
	var p AptPolicy
	flush := func() {
		if name != "" {
			out[name] = p
		}
		name, ver, p = "", "", AptPolicy{}
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case line[0] != ' ':
			flush()
			name = strings.TrimSuffix(line, ":")
		case f[0] == "Candidate:" && len(f) == 2:
			p.Candidate = f[1]
		case f[0] == "Installed:" || f[0] == "Version" || f[0] == "Pinned":
		case f[0] == "***" && len(f) >= 2:
			ver = f[1]
		case len(f) == 2 && !strings.HasPrefix(f[1], "/") && !strings.Contains(f[1], "://"):
			ver = f[0] // a version line: "VERSION PRIORITY"
		case len(f) >= 3 && ver == p.Candidate && strings.Contains(f[1], "://"):
			// "PRIORITY URL SUITE/COMPONENT ARCH Packages"
			suite, _, _ := strings.Cut(f[2], "/")
			if !slices.Contains(p.Suites, suite) {
				p.Suites = append(p.Suites, suite)
			}
		}
	}
	flush()
	return out, sc.Err()
}
