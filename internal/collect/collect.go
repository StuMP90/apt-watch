package collect

import (
	"context"
	"fmt"
	"os"
)

// Inventory is everything collected in one run.
type Inventory struct {
	Packages   []Package   `json:"-"`
	Simulation *Simulation `json:"simulation"`
	System     System      `json:"system"`
	// Changelogs of the third-party source packages (AddChangelogs).
	Changelogs map[string]*Changelog `json:"-"`
}

// Collect gathers the inventory. Only failing to read the dpkg database
// is fatal; other problems are returned as warnings.
func Collect(ctx context.Context) (*Inventory, []string, error) {
	var warnings []string
	warn := func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }

	pkgs, err := ReadDpkgStatus(DpkgStatusPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading package database: %w", err)
	}
	inv := &Inventory{Packages: pkgs}

	if inv.Simulation, err = SimulateUpgrade(ctx); err != nil {
		warn("apt simulation failed: %v", err)
		inv.Simulation = &Simulation{}
	} else if err := ResolveSources(ctx, inv.Simulation.Updates); err != nil {
		warn("resolving source packages of updates: %v", err)
	}
	if err := AddRepos(AptListsDir, inv.Packages); err != nil {
		warn("package repositories: %v", err)
	}

	sys := &inv.System
	sys.Hostname, _ = os.Hostname()
	if sys.OS, err = ReadOSRelease("/etc/os-release"); err != nil {
		warn("os-release: %v", err)
	}
	if sys.OS.Codename != "" {
		if sys.EOL, err = LookupEOL("/usr/share/distro-info", sys.OS.ID, sys.OS.Codename); err != nil {
			warn("end-of-life lookup: %v", err)
		}
	}
	if sys.Reboot, err = ReadReboot("/run/reboot-required"); err != nil {
		warn("reboot-required: %v", err)
	}
	if sys.Kernel.Running, err = RunningKernel(); err != nil {
		warn("running kernel: %v", err)
	} else {
		sys.Kernel.Newest = NewestKernel(pkgs, sys.Kernel.Running)
	}
	if sys.ListsUpdated, err = ListsUpdated(AptListsDir); err != nil {
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
