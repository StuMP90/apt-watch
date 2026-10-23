package collect

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"aptwatch/internal/debver"
)

// Restart is a systemd service still running code from files that a
// package upgrade has since replaced.
type Restart struct {
	Unit     string       `json:"unit"`
	Files    []string     `json:"files"`
	Packages []RestartPkg `json:"packages,omitempty"`
}

// RestartPkg is a package that owns one of a Restart's files. Previous is
// the oldest version it was upgraded from in the current dpkg logs: what
// the service may still be running.
type RestartPkg struct {
	Name     string `json:"name"`
	Previous string `json:"previous,omitempty"`
}

// codeDirs are where packaged executables and libraries live.
var codeDirs = []string{"/usr/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/bin/", "/sbin/"}

// Restarts finds the system services that map deleted executables or
// libraries, by scanning /proc/PID/maps, and the packages that own those
// files. Processes outside a system service (user sessions, containers,
// scopes) are left out. unreadable counts the processes whose maps it
// couldn't read, which is all but its own unless run as root.
func (h Host) Restarts() (rs []Restart, unreadable int, err error) {
	pids, err := filepath.Glob(h.path("/proc") + "/[0-9]*")
	if err != nil {
		return nil, 0, err
	}
	files := map[string]map[string]bool{} // unit → deleted files
	for _, dir := range pids {
		deleted, err := deletedCode(dir + "/maps")
		if errors.Is(err, fs.ErrPermission) {
			unreadable++
			continue
		}
		if err != nil || len(deleted) == 0 { // exited, or a kernel thread
			continue
		}
		unit := serviceUnit(dir + "/cgroup")
		if unit == "" {
			continue
		}
		if files[unit] == nil {
			files[unit] = map[string]bool{}
		}
		for _, f := range deleted {
			files[unit][f] = true
		}
	}
	if len(files) == 0 {
		return nil, unreadable, nil
	}

	var all []string
	for unit, fset := range files {
		r := Restart{Unit: unit}
		for f := range fset {
			r.Files = append(r.Files, f)
			all = append(all, f)
		}
		slices.Sort(r.Files)
		rs = append(rs, r)
	}
	slices.SortFunc(rs, func(a, b Restart) int { return strings.Compare(a.Unit, b.Unit) })

	owners, err := FileOwners(h.path("/var/lib/dpkg/info"), all)
	if err != nil {
		return rs, unreadable, fmt.Errorf("package files: %w", err)
	}
	prev := UpgradedFrom(h.path("/var/log/dpkg.log.1"), h.path("/var/log/dpkg.log"))
	for i := range rs {
		r := &rs[i]
		var names []string
		for _, f := range r.Files {
			if o := owners[f]; o != "" && !slices.Contains(names, o) {
				names = append(names, o)
			}
		}
		slices.Sort(names)
		for _, n := range names {
			r.Packages = append(r.Packages, RestartPkg{Name: n, Previous: prev[n]})
		}
	}
	return rs, unreadable, nil
}

// deletedCode returns the deleted executables and libraries mapped in a
// /proc/PID/maps file: executable mappings of files under codeDirs whose
// path ends " (deleted)".
func deletedCode(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		// address perms offset dev inode path
		line, ok := strings.CutSuffix(sc.Text(), " (deleted)")
		if !ok {
			continue
		}
		fields := strings.SplitN(line, " ", 6)
		if len(fields) < 6 || !strings.Contains(fields[1], "x") {
			continue
		}
		p := strings.TrimLeft(fields[5], " ")
		if slices.ContainsFunc(codeDirs, func(d string) bool { return strings.HasPrefix(p, d) }) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, sc.Err()
}

// serviceUnit returns the system service a process belongs to, from its
// /proc/PID/cgroup file: the last *.service element of its systemd
// cgroup path, or "" if it isn't in one or is in a user session.
func serviceUnit(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var cg string
	for line := range strings.Lines(string(b)) {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" { // cgroup v2
			cg = parts[2]
			break
		}
		if parts[1] == "name=systemd" { // cgroup v1
			cg = parts[2]
		}
	}
	elems := strings.Split(cg, "/")
	if slices.Contains(elems, "user.slice") {
		return ""
	}
	for i := len(elems) - 1; i >= 0; i-- {
		if strings.HasSuffix(elems[i], ".service") {
			return elems[i]
		}
	}
	return ""
}

// FileOwners maps each of paths to the package whose dpkg file list (in
// dir, /var/lib/dpkg/info) contains it. On a merged-/usr system a file
// may be listed under /lib rather than /usr/lib, or the reverse, so both
// spellings are tried.
func FileOwners(dir string, paths []string) (map[string]string, error) {
	want := map[string]string{} // spelling → path
	for _, p := range paths {
		want[p] = p
		if r, ok := strings.CutPrefix(p, "/usr"); ok {
			want[r] = p
		} else {
			want["/usr"+p] = p
		}
	}
	lists, err := filepath.Glob(dir + "/*.list")
	if err != nil {
		return nil, err
	}
	if len(lists) == 0 {
		return nil, fmt.Errorf("no package file lists in %s", dir)
	}
	owners := map[string]string{}
	for _, l := range lists {
		pkg, _, _ := strings.Cut(strings.TrimSuffix(filepath.Base(l), ".list"), ":")
		f, err := os.Open(l)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if p, ok := want[sc.Text()]; ok && owners[p] == "" {
				owners[p] = pkg
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", l, err)
		}
	}
	return owners, nil
}

// UpgradedFrom reads dpkg logs, oldest first, and returns for each
// upgraded package the oldest version it was upgraded from. Missing logs
// are skipped.
func UpgradedFrom(logs ...string) map[string]string {
	out := map[string]string{}
	for _, l := range logs {
		f, err := os.Open(l)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// 2026-10-20 06:12:01 upgrade libssl3:amd64 3.0.17-1~deb12u2 3.0.17-1~deb12u3
			fields := strings.Fields(sc.Text())
			if len(fields) != 6 || fields[2] != "upgrade" || fields[4] == "<none>" {
				continue
			}
			pkg, _, _ := strings.Cut(fields[3], ":")
			if old, ok := out[pkg]; !ok || debver.Compare(fields[4], old) < 0 {
				out[pkg] = fields[4]
			}
		}
		f.Close()
	}
	return out
}
