package collect

import (
	"context"
	"fmt"
	"os"

	"aptwatch/internal/runx"
)

// Inventory is everything collected in one run.
type Inventory struct {
	Packages   []Package   `json:"-"`
	Simulation *Simulation `json:"simulation"`
	System     System      `json:"system"`
	// Changelogs of the third-party source packages (AddChangelogs).
	Changelogs map[string]*Changelog `json:"-"`
}

// Host is where Collect reads the system from. The zero Host is the
// running system; tests point it at synthetic files and a fake apt.
type Host struct {
	Root     string                                               // prefix of the system files; "" for /
	Run      func(context.Context, runx.Cmd) (runx.Result, error) // runs apt-get and apt-cache; nil for runx.Run
	Hostname string                                               // "" for os.Hostname
}

func (h Host) path(p string) string { return h.Root + p }

func (h Host) run(ctx context.Context, c runx.Cmd) (runx.Result, error) {
	if h.Run == nil {
		return runx.Run(ctx, c)
	}
	return h.Run(ctx, c)
}

// OSRelease reads the host's /etc/os-release.
func (h Host) OSRelease() (OSRelease, error) {
	return ReadOSRelease(h.path("/etc/os-release"))
}

// Collect gathers the inventory. Only failing to read the dpkg database
// is fatal; other problems are returned as warnings.
func (h Host) Collect(ctx context.Context) (*Inventory, []string, error) {
	var warnings []string
	warn := func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }

	pkgs, err := ReadDpkgStatus(h.path(DpkgStatusPath))
	if err != nil {
		return nil, nil, fmt.Errorf("reading package database: %w", err)
	}
	inv := &Inventory{Packages: pkgs}

	if inv.Simulation, err = h.SimulateUpgrade(ctx); err != nil {
		warn("apt simulation failed: %v", err)
		inv.Simulation = &Simulation{}
	} else if err := h.ResolveSources(ctx, inv.Simulation.Updates); err != nil {
		warn("resolving source packages of updates: %v", err)
	}
	if err := AddRepos(h.path(AptListsDir), inv.Packages); err != nil {
		warn("package repositories: %v", err)
	}

	sys := &inv.System
	if sys.Hostname = h.Hostname; sys.Hostname == "" {
		sys.Hostname, _ = os.Hostname()
	}
	if sys.OS, err = h.OSRelease(); err != nil {
		warn("os-release: %v", err)
	}
	if sys.OS.Codename != "" {
		if sys.EOL, err = LookupEOL(h.path("/usr/share/distro-info"), sys.OS.ID, sys.OS.Codename); err != nil {
			warn("end-of-life lookup: %v", err)
		}
	}
	if sys.Reboot, err = ReadReboot(h.path("/run/reboot-required")); err != nil {
		warn("reboot-required: %v", err)
	}
	if sys.Kernel.Running, err = RunningKernel(h.path("/proc/sys/kernel/osrelease")); err != nil {
		warn("running kernel: %v", err)
	} else {
		sys.Kernel.Newest = NewestKernel(pkgs, sys.Kernel.Running)
	}
	if sys.OS.ID == "ubuntu" {
		if sys.Livepatch, err = h.Livepatch(ctx); err != nil {
			warn("livepatch: %v", err)
		}
	}
	rs, unreadable, err := h.Restarts()
	if err != nil {
		warn("service restart check: %v", err)
	}
	if unreadable > 0 {
		warn("service restart check incomplete: can't read the memory maps of %d processes (needs root)", unreadable)
	}
	sys.Restarts = rs
	if sys.Held, err = h.HeldPackages(ctx, pkgs); err != nil {
		warn("held packages: %v", err)
	}
	if sys.ListsUpdated, err = ListsUpdated(h.path(AptListsDir)); err != nil {
		warn("apt lists: %v", err)
	}
	return inv, warnings, nil
}

// SourceOf maps binary package names to their source package.
func SourceOf(pkgs []Package) map[string]string {
	m := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		m[p.Name] = p.Source
	}
	return m
}
