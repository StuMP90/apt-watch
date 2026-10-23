package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aptwatch/internal/runx"
)

const AptListsDir = "/var/lib/apt/lists"

// Origin is one "Origin:Version/Suite" label from an apt Inst line. apt
// writes "Origin:Suite" when the repository's Release file has no Version.
type Origin struct {
	Origin  string `json:"origin"`
	Version string `json:"version,omitempty"`
	Suite   string `json:"suite,omitempty"`
}

func (o Origin) String() string {
	switch {
	case o.Suite == "":
		return o.Origin
	case o.Version == "":
		return o.Origin + ":" + o.Suite
	}
	return o.Origin + ":" + o.Version + "/" + o.Suite
}

// Update is one package apt would install or upgrade.
type Update struct {
	Package   string `json:"package"`
	Arch      string `json:"arch"`
	Installed string `json:"installed,omitempty"` // empty for new installs
	Candidate string `json:"candidate"`
	// Source package and version of the candidate, from apt-cache.
	Source        string   `json:"source,omitempty"`
	SourceVersion string   `json:"source_version,omitempty"`
	Origins       []Origin `json:"origins"`
	Security      bool     `json:"security"`
	ESM           bool     `json:"esm,omitempty"`    // needs Ubuntu Pro
	Phased        bool     `json:"phased,omitempty"` // held back by Ubuntu's phased rollout
}

// Simulation is the parsed output of apt-get -s dist-upgrade.
type Simulation struct {
	Updates  []Update `json:"updates"`
	Removals []string `json:"removals,omitempty"`
	Phased   []string `json:"phased,omitempty"` // names apt is deferring due to phasing
}

// IsSecurityOrigin reports whether an origin label is a security archive.
func IsSecurityOrigin(o Origin) bool {
	return strings.HasSuffix(o.Suite, "-security") || o.Origin == "Debian-Security"
}

// IsESMOrigin reports whether an origin is Ubuntu ESM (requires Pro).
func IsESMOrigin(o Origin) bool {
	return strings.HasPrefix(o.Origin, "UbuntuESM")
}

const phasingHeader = "The following upgrades have been deferred due to phasing:"

// ParseSimulation parses apt-get -s output.
func ParseSimulation(r io.Reader) (*Simulation, error) {
	sim := &Simulation{}
	inPhased := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if inPhased {
			if strings.HasPrefix(line, " ") {
				sim.Phased = append(sim.Phased, strings.Fields(line)...)
				continue
			}
			inPhased = false
		}
		switch {
		case line == phasingHeader:
			inPhased = true
		case strings.HasPrefix(line, "Inst "):
			u, err := parseInst(line[len("Inst "):])
			if err != nil {
				return nil, err
			}
			sim.Updates = append(sim.Updates, u)
		case strings.HasPrefix(line, "Remv "):
			if f := strings.Fields(line); len(f) > 1 {
				sim.Removals = append(sim.Removals, f[1])
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	phased := make(map[string]bool, len(sim.Phased))
	for _, p := range sim.Phased {
		phased[p] = true
	}
	for i := range sim.Updates {
		u := &sim.Updates[i]
		u.Phased = phased[u.Package] || phased[u.Package+":"+u.Arch]
	}
	return sim, nil
}

// parseInst parses the part of an Inst line after "Inst ":
//
//	pkg[:arch] [old] (new Origin:Ver/suite[, Origin:Ver/suite...] [arch]) [broken...]
func parseInst(s string) (Update, error) {
	bad := func() (Update, error) { return Update{}, fmt.Errorf("unrecognised Inst line: %q", s) }
	var u Update
	name, rest, ok := strings.Cut(s, " ")
	if !ok {
		return bad()
	}
	u.Package, u.Arch, _ = strings.Cut(name, ":")
	if strings.HasPrefix(rest, "[") {
		old, after, ok := strings.Cut(rest[1:], "] ")
		if !ok {
			return bad()
		}
		u.Installed, rest = old, after
	}
	open, close := strings.IndexByte(rest, '('), strings.LastIndexByte(rest, ')')
	if open != 0 || close < 0 {
		return bad()
	}
	inner := rest[1:close]
	cand, labels, _ := strings.Cut(inner, " ")
	u.Candidate = cand
	if i := strings.LastIndex(labels, " ["); i >= 0 && strings.HasSuffix(labels, "]") {
		if u.Arch == "" {
			u.Arch = labels[i+2 : len(labels)-1]
		}
		labels = labels[:i]
	}
	for _, l := range strings.Split(labels, ", ") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		var o Origin
		left, suite, hasSuite := cutLast(l, "/")
		if hasSuite {
			o.Suite = suite
			o.Origin, o.Version, _ = cutLast(left, ":")
		} else {
			o.Origin, o.Suite, _ = cutLast(l, ":")
		}
		u.Origins = append(u.Origins, o)
		u.Security = u.Security || IsSecurityOrigin(o)
		u.ESM = u.ESM || IsESMOrigin(o)
	}
	if u.Package == "" || u.Candidate == "" {
		return bad()
	}
	return u, nil
}

func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// SimulateUpgrade runs apt-get -s dist-upgrade twice: once with phased
// updates included (to get their versions), once without (to learn which
// ones apt is deferring). Needs no root.
func SimulateUpgrade(ctx context.Context) (*Simulation, error) {
	base := []string{"-s", "-q", "-o", "Debug::NoLocking=true"}
	run := func(extra ...string) (*Simulation, error) {
		args := append(append(append([]string{}, base...), extra...), "dist-upgrade")
		res, err := runx.Run(ctx, runx.Cmd{Name: "apt-get", Args: args, Timeout: 5 * time.Minute})
		if err != nil {
			return nil, err
		}
		return ParseSimulation(bytes.NewReader(res.Stdout))
	}
	all, err := run("-o", "APT::Get::Always-Include-Phased-Updates=true")
	if err != nil {
		return nil, err
	}
	normal, err := run()
	if err != nil {
		return nil, err
	}
	return MergePhased(all, normal), nil
}

// MergePhased marks the updates in all, the run including phased updates,
// that normal, the run without them, defers: those under its phasing
// header, and those it doesn't install at all. apt before 2.8 has no
// phasing header and lists phased updates as kept back, so only the
// second test finds them there.
func MergePhased(all, normal *Simulation) *Simulation {
	phased := map[string]bool{}
	for _, p := range normal.Phased {
		phased[p] = true
	}
	installs := map[string]bool{}
	for _, u := range normal.Updates {
		installs[u.Package+":"+u.Arch] = true
	}
	all.Phased = append([]string(nil), normal.Phased...)
	for i := range all.Updates {
		u := &all.Updates[i]
		u.Phased = phased[u.Package] || phased[u.Package+":"+u.Arch]
		if !u.Phased && !installs[u.Package+":"+u.Arch] {
			u.Phased = true
			all.Phased = append(all.Phased, u.Package)
		}
	}
	return all
}

// ResolveSources fills in Source and SourceVersion of each update from
// apt-cache show. Updates it can't resolve are left empty.
func ResolveSources(ctx context.Context, updates []Update) error {
	if len(updates) == 0 {
		return nil
	}
	args := []string{"show", "--no-all-versions"}
	for _, u := range updates {
		args = append(args, u.Package+":"+u.Arch+"="+u.Candidate)
	}
	res, err := runx.Run(ctx, runx.Cmd{Name: "apt-cache", Args: args, Timeout: 2 * time.Minute})
	// apt-cache fails only when none of the packages is found.
	if err != nil && len(res.Stdout) == 0 {
		return err
	}
	srcs, err := ParseAptCacheShow(bytes.NewReader(res.Stdout))
	if err != nil {
		return err
	}
	for i := range updates {
		u := &updates[i]
		if s, ok := srcs[u.Package+"="+u.Candidate]; ok {
			u.Source, u.SourceVersion = s[0], s[1]
		}
	}
	return nil
}

// ParseAptCacheShow maps "package=version" to its source name and version
// from apt-cache show output.
func ParseAptCacheShow(r io.Reader) (map[string][2]string, error) {
	out := map[string][2]string{}
	var pkg, ver, src string
	flush := func() {
		if pkg != "" && ver != "" {
			name, sver := pkg, ver
			if src != "" {
				n, v, found := strings.Cut(src, " ")
				name = n
				if found {
					sver = strings.Trim(strings.TrimSpace(v), "()")
				}
			}
			out[pkg+"="+ver] = [2]string{name, sver}
		}
		pkg, ver, src = "", "", ""
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || line[0] == ' ' {
			continue
		}
		switch k {
		case "Package":
			pkg = strings.TrimSpace(v)
		case "Version":
			ver = strings.TrimSpace(v)
		case "Source":
			src = strings.TrimSpace(v)
		}
	}
	flush()
	return out, sc.Err()
}

// RefreshLists runs apt-get update. Requires root.
func RefreshLists(ctx context.Context, lockTimeout time.Duration) error {
	_, err := runx.Run(ctx, runx.Cmd{
		Name:    "apt-get",
		Args:    []string{"update", "-qq", "-o", fmt.Sprintf("DPkg::Lock::Timeout=%d", int(lockTimeout.Seconds()))},
		Timeout: lockTimeout + 10*time.Minute,
	})
	return err
}

// ListsUpdated returns the newest modification time of the apt lists.
func ListsUpdated(dir string) (time.Time, error) {
	var newest time.Time
	entries, err := os.ReadDir(dir)
	if err != nil {
		return newest, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || e.Name() == "lock" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return newest, err
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if newest.IsZero() {
		return newest, &fs.PathError{Op: "scan", Path: filepath.Clean(dir), Err: fs.ErrNotExist}
	}
	return newest, nil
}
