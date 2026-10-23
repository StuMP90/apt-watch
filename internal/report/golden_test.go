package report

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/risk"
	"aptwatch/internal/state"
)

// Regenerate with: go test ./internal/report -update
var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

var goldenNow = time.Date(2026, 10, 22, 6, 0, 0, 0, time.UTC)

func ago(d time.Duration) time.Time { return goldenNow.Add(-d) }

const day = 24 * time.Hour

func date(s string) risk.Date {
	var d risk.Date
	if err := d.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return d
}

// goldenReport is a synthetic report that reaches every section of the
// full report.
func goldenReport() *Report {
	var libs []risk.PkgRef
	for _, n := range []string{"libexample1", "libexample-dev", "libexample-doc", "libexample-tools",
		"libexample-utils", "python3-example", "example-bin", "example-common", "example-data", "example-l10n"} {
		libs = append(libs, risk.PkgRef{Name: n, Installed: "2.4.1-1ubuntu0.1"})
	}
	r := &Report{
		Schema: SchemaVersion, Tool: "aptwatch test", Host: "web01", Generated: goldenNow,
		Findings: []risk.Finding{
			{Key: "cve:CVE-2026-10001:openssl", Kind: risk.KindCVEFixAvailable, Severity: risk.Critical,
				Title: "CVE-2026-10001 in openssl: fix available", Source: "openssl", FixAvail: true,
				Since: ago(9 * day), FirstSeen: ago(9 * day),
				Detail:   "Remote code execution in the TLS handshake <and> heap overflow.",
				Packages: []risk.PkgRef{{Name: "libssl3t64", Installed: "3.0.13-0ubuntu3.5"}, {Name: "openssl", Installed: "3.0.13-0ubuntu3.5"}},
				CVEs: []risk.CVERef{{ID: "CVE-2026-10001", Priority: "high", Fixed: "3.0.13-0ubuntu3.6", KEV: true, EPSS: 0.42,
					URL: "https://ubuntu.com/security/CVE-2026-10001"}}},
			{Key: "cve:CVE-2026-10002:example", Kind: risk.KindCVEFixAvailable, Severity: risk.High,
				Title: "2 CVEs in example: fix available", Source: "example", FixAvail: true,
				Since: ago(2 * day), Packages: libs,
				CVEs: []risk.CVERef{
					{ID: "CVE-2026-10002", Priority: "medium", EPSS: 0.12, URL: "https://ubuntu.com/security/CVE-2026-10002"},
					{ID: "CVE-2026-10003", Priority: "low"},
				}},
			{Key: "held-security-update:example-server", Kind: risk.KindHeldSecurity, Severity: risk.High,
				Title: "Security update for example-server (1.4-2ubuntu0.2) is held back", FixAvail: true,
				Detail:   "The package is on hold (apt-mark hold), so apt won't upgrade it",
				Packages: []risk.PkgRef{{Name: "example-server", Installed: "1.4-2ubuntu0.1", Candidate: "1.4-2ubuntu0.2", Origin: "noble-security"}}},
			{Key: "service-restart-needed:example.service", Kind: risk.KindRestart, Severity: risk.High,
				Title: "example.service is running replaced code and needs a restart", FixAvail: true,
				Detail:   "Uses deleted /usr/lib/x86_64-linux-gnu/libssl.so.3",
				Packages: []risk.PkgRef{{Name: "libssl3t64", Installed: "3.0.13-0ubuntu3.4"}},
				CVEs: []risk.CVERef{{ID: "CVE-2026-09998", Priority: "high", Fixed: "3.0.13-0ubuntu3.5",
					URL: "https://ubuntu.com/security/CVE-2026-09998"}}},
			{Key: risk.KindReboot, Kind: risk.KindReboot, Severity: risk.Medium,
				Title: "Reboot required", Since: ago(3 * day)},
			{Key: risk.KindStaleLists, Kind: risk.KindStaleLists, Severity: risk.Medium,
				Title: "apt lists last updated 4 days ago", Since: ago(4 * day),
				Detail: "Run apt-get update, or check the apt-daily timer."},
			{Key: "kernel-not-running:6.8.0-91-generic", Kind: risk.KindKernel, Severity: risk.Low,
				Title: "Newer kernel installed but not running", FixAvail: true,
				Detail: "Running 6.8.0-90-generic, newest installed 6.8.0-91-generic; Livepatch has patched the running kernel (patch 118.1)"},
			{Key: "service-restart-needed:dbus.service", Kind: risk.KindRestart, Severity: risk.Low,
				Title: "dbus.service is running replaced code and needs a restart", FixAvail: true,
				Detail:   "Uses deleted /usr/lib/x86_64-linux-gnu/libexpat.so.1.9.1",
				Packages: []risk.PkgRef{{Name: "libexpat1", Installed: "2.6.1-2ubuntu0.2"}}},
			{Key: "held-update:example-tools", Kind: risk.KindHeld, Severity: risk.Info,
				Title: "Update for example-tools (2.0-1ubuntu0.1) is held back", FixAvail: true,
				Detail:   "The package is on hold (apt-mark hold), so apt won't upgrade it",
				Packages: []risk.PkgRef{{Name: "example-tools", Installed: "2.0-1", Candidate: "2.0-1ubuntu0.1", Origin: "noble-updates"}}},
			{Key: "cve-unfixed:CVE-2026-10004:zlib", Kind: risk.KindCVEUnfixed, Severity: risk.Low,
				Title: "CVE-2026-10004 in zlib: no fix yet", Source: "zlib", FirstSeen: ago(30 * day),
				CVEs: []risk.CVERef{{ID: "CVE-2026-10004", Priority: "low"}}},
			{Key: risk.KindCVEUnfixedSummary, Kind: risk.KindCVEUnfixedSummary, Severity: risk.Info,
				Title:  "14 CVEs with no fix yet affect 6 installed source packages",
				Detail: "zlib (5), example (4), imagelib (2), and 3 more"},
			{Key: "changelog-cves:example-php", Kind: risk.KindCVEFixedThirdParty, Severity: risk.Info,
				Title: "example-php 8.3.12 fixes 2 recent CVEs",
				CVEs: []risk.CVERef{
					{ID: "CVE-2026-10005", Priority: "critical", KEV: true, URL: "https://ubuntu.com/security/CVE-2026-10005"},
					{ID: "CVE-2026-10006"},
				}},
			{Key: "cve:CVE-2026-10007:curl", Kind: risk.KindCVEFixAvailable, Severity: risk.High,
				Title: "CVE-2026-10007 in curl: fix available", Source: "curl", FixAvail: true,
				Suppressed: &risk.Suppression{Rule: "CVE-2026-10007", Reason: "not reachable from our services",
					Until: date("2026-12-31")}},
			{Key: "update:vim", Kind: risk.KindUpdate, Severity: risk.Low, Title: "vim: update pending",
				Suppressed: &risk.Suppression{Rule: "package vim* (update-pending)", Reason: "pinned"}},
		},
		Diff: &state.Diff{
			New:       []string{"cve:CVE-2026-10002:example"},
			Escalated: []string{"cve:CVE-2026-10001:openssl"},
			Resolved: []state.Resolved{{Key: "cve:CVE-2026-09999:sudo", Entry: state.Entry{
				Kind: risk.KindCVEFixAvailable, Title: "CVE-2026-09999 in sudo: fix available", Severity: risk.High,
				FirstSeen: ago(10 * day), LastSeen: ago(day), ResolvedAt: goldenNow}}},
		},
		Updates: []collect.Update{
			{Package: "openssl", Arch: "amd64", Installed: "3.0.13-0ubuntu3.5", Candidate: "3.0.13-0ubuntu3.6",
				Source: "openssl", SourceVersion: "3.0.13-0ubuntu3.6", Security: true,
				Origins: []collect.Origin{{Origin: "Ubuntu", Version: "24.04", Suite: "noble-security"}}},
			{Package: "libssl3t64", Arch: "amd64", Installed: "3.0.13-0ubuntu3.5", Candidate: "3.0.13-0ubuntu3.6",
				Source: "openssl", SourceVersion: "3.0.13-0ubuntu3.6", Security: true,
				Origins: []collect.Origin{{Origin: "Ubuntu", Version: "24.04", Suite: "noble-security"}}},
			{Package: "python3-example", Arch: "all", Installed: "2.4.1-1ubuntu0.1", Candidate: "2.4.1-1ubuntu0.1+esm1",
				Source: "example", Security: true, ESM: true,
				Origins: []collect.Origin{{Origin: "UbuntuESMApps", Version: "24.04", Suite: "noble-apps-security"}}},
			{Package: "tzdata", Arch: "all", Installed: "2026a-0ubuntu0.24.04", Candidate: "2026b-0ubuntu0.24.04",
				Origins: []collect.Origin{{Origin: "Ubuntu", Version: "24.04", Suite: "noble-updates"}}, Phased: true},
			{Package: "linux-image-6.8.0-92-generic", Arch: "amd64", Candidate: "6.8.0-92.92",
				Origins: []collect.Origin{{Origin: "Ubuntu", Version: "24.04", Suite: "noble-updates"}}},
		},
		VulnDB: &VulnDB{Sources: []string{"ubuntu-cve-tracker"}, Fetched: ago(5 * time.Hour), KEV: 1400, EPSS: 280000},
		Expired: []risk.IgnoreRule{
			{CVE: "CVE-2026-09000", Reason: "waiting for vendor", Until: date("2026-10-01")},
			{Package: "nginx*", Kinds: []string{risk.KindUpdate}, Reason: "held for testing", Until: date("2026-10-15")},
		},
		Warnings: []string{"epss: feed unavailable, using cached scores from 2026-10-20"},
	}
	r.System = collect.System{
		Hostname: "web01",
		OS:       collect.OSRelease{ID: "ubuntu", VersionID: "24.04", Codename: "noble", PrettyName: "Ubuntu 24.04.3 LTS"},
		EOL: &collect.EOL{SecurityEnd: time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC),
			ExtendedEnd: time.Date(2034, 4, 30, 0, 0, 0, 0, time.UTC), Note: "ESM with Ubuntu Pro until 2034-04-30"},
		Reboot:    collect.Reboot{Required: true, Since: ago(3 * day), Packages: []string{"linux-image-6.8.0-91-generic", "libc6"}},
		Kernel:    collect.Kernel{Running: "6.8.0-90-generic", Newest: "6.8.0-91-generic"},
		Livepatch: &collect.Livepatch{Kernel: "6.8.0-90.90-generic", State: "applied", Version: "118.1"},
		Restarts: []collect.Restart{
			{Unit: "dbus.service", Files: []string{"/usr/lib/x86_64-linux-gnu/libexpat.so.1.9.1"},
				Packages: []collect.RestartPkg{{Name: "libexpat1", Previous: "2.6.1-2ubuntu0.2"}}},
			{Unit: "example.service", Files: []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"},
				Packages: []collect.RestartPkg{{Name: "libssl3t64", Previous: "3.0.13-0ubuntu3.4"}}},
		},
		Held: []collect.Held{
			{Package: "example-server", Arch: "amd64", Installed: "1.4-2ubuntu0.1", Candidate: "1.4-2ubuntu0.2",
				Suites: []string{"noble-security"}, Security: true},
			{Package: "example-tools", Arch: "amd64", Installed: "2.0-1", Candidate: "2.0-1ubuntu0.1", Suites: []string{"noble-updates"}},
			{Package: "example-legacy", Arch: "amd64", Installed: "0.8-1"},
		},
		ListsUpdated: ago(4 * day),
	}
	return r
}

// goldenCVEReport is a synthetic aptwatch cve result with every status.
func goldenCVEReport() *CVEReport {
	ubuntu := func(id string) string { return "https://ubuntu.com/security/" + id }
	return &CVEReport{
		Schema: SchemaVersion, Tool: "aptwatch test", Host: "web01", Generated: goldenNow,
		Checks: []risk.CVECheck{
			{ID: "CVE-2026-20001", Status: risk.StatusUnreachable, Known: true, Priority: "high", URL: ubuntu("CVE-2026-20001"),
				Desc: "Heap overflow in the example parser.",
				Packages: []risk.CVEPackage{{Source: "example", Status: risk.StatusUnreachable, Repo: "noble-proposed",
					Installed: "1.2-1", Fixed: "1.2-2", Binaries: []string{"libexample1", "example-bin"},
					Note: "the fix is only in a suite apt doesn't use"}}},
			{ID: "CVE-2026-20002", Status: risk.StatusPro, Known: true, Priority: "medium", URL: ubuntu("CVE-2026-20002"),
				Published: ago(40 * day),
				Packages: []risk.CVEPackage{{Source: "imagelib", Status: risk.StatusPro, Repo: "esm-apps",
					Installed: "0.9-3", Fixed: "0.9-3ubuntu0.1~esm1", Binaries: []string{"libimage0"},
					Note: "fixed in Ubuntu Pro (esm-apps)", Command: "sudo pro attach"}}},
			{ID: "CVE-2026-20003", Status: risk.StatusPending, Known: true, Priority: "high", URL: ubuntu("CVE-2026-20003"),
				Published: ago(12 * day), KEV: true, KEVAdded: ago(5 * day), EPSS: 0.87,
				Desc: "Authentication bypass in the <admin> interface & API.",
				Packages: []risk.CVEPackage{
					{Source: "openssl", Status: risk.StatusPending, Repo: "noble-security", Installed: "3.0.13-0ubuntu3.5",
						Candidate: "3.0.13-0ubuntu3.6", Fixed: "3.0.13-0ubuntu3.6", Binaries: []string{"libssl3t64", "openssl"},
						Command: "sudo apt-get install --only-upgrade libssl3t64 openssl"},
					{Source: "openssl-compat", Status: risk.StatusFixed, Repo: "noble-updates", Installed: "1.1-2ubuntu1",
						Fixed: "1.1-2ubuntu1", Binaries: []string{"libssl1.1"}},
				},
				NotInstalled: []string{"openssl1.0", "edk2"}},
			{ID: "CVE-2026-20004", Status: risk.StatusRebootPending, Known: true, Priority: "medium", URL: ubuntu("CVE-2026-20004"),
				Packages: []risk.CVEPackage{{Source: "linux", Status: risk.StatusRebootPending, Repo: "noble-security",
					Installed: "6.8.0-91.91", Fixed: "6.8.0-91.91", Binaries: []string{"linux-image-6.8.0-91-generic"},
					Note: "running kernel 6.8.0-90-generic is older than the fix", Command: "sudo reboot"}}},
			{ID: "CVE-2026-20005", Status: risk.StatusNoFix, Known: true, Priority: "low", URL: ubuntu("CVE-2026-20005"),
				EPSS: 0.004,
				Packages: []risk.CVEPackage{{Source: "zlib", Status: risk.StatusNoFix, Installed: "1:1.3.dfsg-3.1ubuntu2",
					Binaries: []string{"zlib1g"}}}},
			{ID: "CVE-2026-20006", Status: risk.StatusUnconfirmed, Known: true, Priority: "medium",
				Packages: []risk.CVEPackage{{Source: "example-php", Status: risk.StatusUnconfirmed, Repo: "ppa:example/php",
					Installed: "8.3.12-1+ubuntu24.04.1", Binaries: []string{"example-php8.3-cli"},
					Note: "fixed by Ubuntu in 8.3.6-0ubuntu0.24.04.3; the third-party changelog doesn't name it"}}},
			{ID: "CVE-2026-20007", Status: risk.StatusUnknown},
			{ID: "CVE-2026-20008", Status: risk.StatusUnknown, Known: true, Priority: "unknown",
				Packages: []risk.CVEPackage{{Source: "localtool", Status: risk.StatusUnknown, Repo: "local",
					Installed: "0.1", Binaries: []string{"localtool"}, Note: "not from a known archive"}}},
			{ID: "CVE-2026-20009", Status: risk.StatusFixed, Known: true, Priority: "high", URL: ubuntu("CVE-2026-20009"),
				Published: ago(90 * day),
				Packages: []risk.CVEPackage{{Source: "sudo", Status: risk.StatusFixed, Repo: "noble-security",
					Installed: "1.9.15p5-3ubuntu5.24.04.1", Fixed: "1.9.15p5-3ubuntu5.24.04.1", Binaries: []string{"sudo"}}}},
			{ID: "CVE-2026-20010", Status: risk.StatusNotAffected, Known: true, Priority: "medium", URL: ubuntu("CVE-2026-20010"),
				Packages: []risk.CVEPackage{}, NotInstalled: []string{"nginx"}},
			{ID: "CVE-2026-20011", Status: risk.StatusNotAffected, Known: true, Packages: []risk.CVEPackage{}},
		},
		VulnDB:   &VulnDB{Sources: []string{"ubuntu-cve-tracker"}, Fetched: ago(5 * time.Hour), KEV: 1400, EPSS: 280000},
		Warnings: []string{"kev: catalogue is 3 days old"},
	}
}

// TestGolden compares each rendered format with its file in testdata/golden.
func TestGolden(t *testing.T) {
	saved := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = saved })

	r, c := goldenReport(), goldenCVEReport()
	for _, tc := range []struct {
		name   string
		render func(io.Writer) error
	}{
		{"report.txt", r.Text},
		{"report.html", r.HTML},
		{"report.json", r.JSON},
		{"cve.txt", c.Text},
		{"cve.html", c.HTML},
		{"cve.json", c.JSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got bytes.Buffer
			if err := tc.render(&got); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "golden", tc.name)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/report -update)", err)
			}
			if d := firstDiff(string(want), got.String()); d != "" {
				t.Errorf("%s differs from the golden file (go test ./internal/report -update to accept):\n%s", tc.name, d)
			}
		})
	}
}

// firstDiff describes the first line that differs, or returns "".
func firstDiff(want, got string) string {
	if want == got {
		return ""
	}
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < max(len(w), len(g)); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return fmt.Sprintf("line %d:\n  want: %q\n  got:  %q", i+1, wl, gl)
		}
	}
	return "files differ"
}
