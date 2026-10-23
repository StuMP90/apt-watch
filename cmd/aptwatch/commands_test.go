package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/report"
	"aptwatch/internal/risk"
	"aptwatch/internal/runx"
)

// A synthetic Debian 12 host: openssl and libssl3 have a security update
// that fixes CVE-2026-0001; CVE-2026-0002 has no fix yet; CVE-2026-0003
// was fixed before the installed version.
const (
	testDpkgStatus = `Package: base-files
Status: install ok installed
Architecture: amd64
Version: 12.4+deb12u11

Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.17-1~deb12u2

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.17-1~deb12u2

Package: linux-image-6.1.0-41-amd64
Status: install ok installed
Architecture: amd64
Source: linux-signed-amd64
Version: 6.1.158-1
`
	testAptSim = `Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages will be upgraded:
  base-files libssl3 openssl
3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst base-files [12.4+deb12u11] (12.4+deb12u12 Debian:12.12/stable [amd64])
Inst libssl3 [3.0.17-1~deb12u2] (3.0.17-1~deb12u3 Debian-Security:12/stable-security [amd64])
Inst openssl [3.0.17-1~deb12u2] (3.0.17-1~deb12u3 Debian-Security:12/stable-security [amd64])
Conf base-files (12.4+deb12u12 Debian:12.12/stable [amd64])
Conf libssl3 (3.0.17-1~deb12u3 Debian-Security:12/stable-security [amd64])
Conf openssl (3.0.17-1~deb12u3 Debian-Security:12/stable-security [amd64])
`
	testTracker = `{
  "openssl": {
    "CVE-2026-0001": {"description": "openssl: buffer overflow", "releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.17-1~deb12u3", "urgency": "high"}}},
    "CVE-2026-0002": {"description": "openssl: timing leak", "releases": {"bookworm": {"status": "open", "urgency": "low"}}},
    "CVE-2026-0003": {"description": "openssl: old bug", "releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.11-1~deb12u1", "urgency": "medium"}}}
  }
}`
)

// fakeApt answers apt-get -s dist-upgrade with testAptSim, and apt-cache
// show with each package's source.
func fakeApt(_ context.Context, c runx.Cmd) (runx.Result, error) {
	switch c.Name {
	case "apt-get":
		return runx.Result{Stdout: []byte(testAptSim)}, nil
	case "apt-cache":
		var b strings.Builder
		for _, a := range c.Args[2:] {
			pkg, ver, _ := strings.Cut(a, "=")
			pkg, _, _ = strings.Cut(pkg, ":")
			fmt.Fprintf(&b, "Package: %s\nVersion: %s\n", pkg, ver)
			if pkg == "libssl3" {
				b.WriteString("Source: openssl\n")
			}
			b.WriteString("\n")
		}
		return runx.Result{Stdout: []byte(b.String())}, nil
	}
	return runx.Result{}, fmt.Errorf("unexpected command %s", c.Name)
}

// testHost sets up the synthetic host, its cached vulnerability data and a
// config, points the commands at them, and returns the config path and
// the state file.
func testHost(t *testing.T) (cfgPath, stateFile string) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	lists := root + collect.AptListsDir
	files := map[string]string{
		root + collect.DpkgStatusPath:                                              "\n" + testDpkgStatus,
		root + "/etc/os-release":                                                   "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n",
		root + "/usr/share/distro-info/debian.csv":                                 "version,codename,series,created,release,eol,eol-lts,eol-elts\n12,Bookworm,bookworm,2021-08-14,2023-06-10,2026-06-10,2028-06-30,2033-06-30\n",
		root + "/proc/sys/kernel/osrelease":                                        "6.1.0-41-amd64\n",
		lists + "/deb.debian.org_debian_dists_bookworm_InRelease":                  "Origin: Debian\nSuite: stable\nSHA256:\n",
		lists + "/deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages": "Package: base-files\nVersion: 12.4+deb12u11\n\nPackage: libssl3\nVersion: 3.0.17-1~deb12u2\n\nPackage: openssl\nVersion: 3.0.17-1~deb12u2\n\nPackage: linux-image-6.1.0-41-amd64\nVersion: 6.1.158-1\n",
	}
	cache := filepath.Join(dir, "cache")
	meta, _ := json.Marshal(map[string]any{"url": "https://security-tracker.debian.org/tracker/data/json", "fetched": time.Now(), "checked": time.Now()})
	files[cache+"/debian-tracker.json"] = testTracker
	files[cache+"/debian-tracker.json.meta.json"] = string(meta)
	stateFile = filepath.Join(dir, "state.json")
	cfgPath = filepath.Join(dir, "config.yaml")
	files[cfgPath] = fmt.Sprintf(`lock_file: %s
state:
  file: %s
apt:
  refresh_lists: false
vulndb:
  cache_dir: %s
  sources: [debian-tracker]
  kev: false
  epss: false
  changelogs: false
`, filepath.Join(dir, "lock"), stateFile, cache)
	for p, body := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	old := sys
	sys = collect.Host{Root: root, Run: fakeApt, Hostname: "web01.example.org"}
	t.Cleanup(func() { sys = old })
	setNagios(t, false)
	return cfgPath, stateFile
}

// execute runs aptwatch with args and returns its output and exit code.
func execute(t *testing.T, args ...string) (string, int) {
	t.Helper()
	root := newRoot()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs(append(args, "--log-level", "error"))
	err := root.ExecuteContext(context.Background())
	return out.String(), code(t, err)
}

func decode[T any](t *testing.T, out string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return v
}

func findingKeys(r report.Report) []string {
	var keys []string
	for _, f := range r.Findings {
		keys = append(keys, f.Key)
	}
	return keys
}

func checkReport(t *testing.T, r report.Report) {
	t.Helper()
	if r.Host != "web01" || r.System.OS.Codename != "bookworm" {
		t.Errorf("host %q, OS %+v", r.Host, r.System.OS)
	}
	if len(r.Warnings) > 0 {
		t.Errorf("warnings: %q", r.Warnings)
	}
	if r.VulnDB == nil {
		t.Error("no vulnerability data")
	}
	i := slices.IndexFunc(r.Updates, func(u collect.Update) bool { return u.Package == "libssl3" })
	if i < 0 || !r.Updates[i].Security || r.Updates[i].Source != "openssl" {
		t.Errorf("updates: %+v", r.Updates)
	}
	cve := slices.ContainsFunc(r.Findings, func(f risk.Finding) bool {
		return f.Kind == risk.KindCVEFixAvailable && slices.ContainsFunc(f.CVEs, func(c risk.CVERef) bool { return c.ID == "CVE-2026-0001" })
	})
	if !cve {
		t.Errorf("no %s finding for CVE-2026-0001; findings: %q", risk.KindCVEFixAvailable, findingKeys(r))
	}
}

func TestRunCommand(t *testing.T) {
	cfg, stateFile := testHost(t)

	out, c := execute(t, "run", "--config", cfg, "--no-refresh", "--format", "json")
	if c != exitFindings {
		t.Errorf("first run: exit %d, want %d\n%s", c, exitFindings, out)
	}
	r := decode[report.Report](t, out)
	checkReport(t, r)
	if r.Diff == nil || !r.Diff.FirstRun || len(r.Diff.New) == 0 {
		t.Errorf("first run diff: %+v", r.Diff)
	}
	if _, err := os.Stat(stateFile); err != nil {
		t.Fatalf("state not saved: %v", err)
	}

	out, c = execute(t, "run", "--config", cfg, "--no-refresh", "--format", "json")
	if c != exitFindings {
		t.Errorf("second run: exit %d, want %d", c, exitFindings)
	}
	r2 := decode[report.Report](t, out)
	if r2.Diff == nil || r2.Diff.FirstRun || len(r2.Diff.New) > 0 || len(r2.Diff.Persisting) != len(r.Diff.New) {
		t.Errorf("second run diff: %+v, first run new: %q", r2.Diff, r.Diff.New)
	}

	out, c = execute(t, "run", "--config", cfg, "--no-refresh", "--nagios")
	if c != nagiosCritical && c != nagiosWarning || !strings.Contains(out, "web01") {
		t.Errorf("nagios: exit %d, %q", c, out)
	}
}

func TestRunDryRun(t *testing.T) {
	cfg, stateFile := testHost(t)
	out, c := execute(t, "run", "--config", cfg, "--dry-run", "--format", "text")
	if c != exitFindings || !strings.Contains(out, "CVE-2026-0001") {
		t.Errorf("exit %d\n%s", c, out)
	}
	if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
		t.Errorf("dry run saved the state: %v", err)
	}
}

func TestScanCommand(t *testing.T) {
	cfg, stateFile := testHost(t)
	out, c := execute(t, "scan", "--config", cfg, "--no-refresh", "--format", "json")
	if c != exitFindings {
		t.Errorf("exit %d, want %d", c, exitFindings)
	}
	r := decode[report.Report](t, out)
	checkReport(t, r)
	if r.Diff != nil {
		t.Errorf("scan has a diff: %+v", r.Diff)
	}
	if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
		t.Errorf("scan saved the state: %v", err)
	}
}

func TestCVECommand(t *testing.T) {
	cfg, _ := testHost(t)
	tests := []struct {
		id     string
		status string
		exit   int
	}{
		{"CVE-2026-0001", risk.StatusPending, exitFindings},
		{"cve-2026-0002", risk.StatusNoFix, exitFindings},
		{"CVE-2026-0003", risk.StatusFixed, exitOK},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			out, c := execute(t, "cve", tt.id, "--config", cfg, "--no-refresh", "--format", "json")
			r := decode[report.CVEReport](t, out)
			if len(r.Checks) != 1 || r.Checks[0].Status != tt.status || c != tt.exit {
				t.Errorf("exit %d, want %d; checks %+v, want status %s", c, tt.exit, r.Checks, tt.status)
			}
			if len(r.Warnings) > 0 {
				t.Errorf("warnings: %q", r.Warnings)
			}
		})
	}
}
