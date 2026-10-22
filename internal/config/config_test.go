package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aptwatch/internal/risk"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30s": 30 * time.Second, "7d": 7 * 24 * time.Hour, "1d12h": 36 * time.Hour,
	} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("%s = %v, %v", in, got, err)
		}
	}
	if _, err := ParseDuration("7days"); err == nil {
		t.Error("7days accepted")
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"1GiB": 1 << 30, "500MB": 500e6, "1024": 1024, "2 KiB": 2048} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%s = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSize("1GB2"); err == nil {
		t.Error("1GB2 accepted")
	}
}

func TestLoad(t *testing.T) {
	p := write(t, `
host_label: web1
state: {file: state.json}
apt: {lock_timeout: 5m}
vulndb: {cache_dir: cache, sources: [osv-ubuntu], max_size: 500MiB, epss: false}
policy: {report_unfixed_cves: full}
ignore:
  - {cve: cve-2025-12345, reason: not built, until: 2026-12-31}
  - {package: "linux-image-*", kinds: [update-pending], reason: "monthly window", until: "2027-01-31"}
report: {format: html}
notify:
  - name: desk
    type: desktop
`)
	c, warn, err := Load(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.State.File != filepath.Join(filepath.Dir(p), "state.json") {
		t.Errorf("state file %s", c.State.File)
	}
	if c.Apt.LockTimeout.D() != 5*time.Minute || c.Apt.StaleAfter.D() != 48*time.Hour {
		t.Errorf("apt %+v", c.Apt)
	}
	v := c.VulndbOptions()
	if v.Dir != filepath.Join(filepath.Dir(p), "cache") || v.MaxSize != 500<<20 || v.EPSS || !v.KEV || v.MaxAge != 20*time.Hour {
		t.Errorf("vulndb %+v", v)
	}
	if rp := c.RiskPolicy(); rp.ReportUnfixed != "full" || rp.EPSSBump != 0.5 {
		t.Errorf("policy %+v", rp)
	}
	if len(c.Ignore) != 2 || c.Ignore[0].CVE != "CVE-2025-12345" || c.Ignore[1].Until.Month() != time.January {
		t.Errorf("ignore %+v", c.Ignore)
	}
	if len(warn) != 1 {
		t.Errorf("warnings %v", warn)
	}
	if c.Report.Format != "html" {
		t.Errorf("report format %q", c.Report.Format)
	}
}

func TestLoadErrors(t *testing.T) {
	for body, want := range map[string]string{
		"bogus: 1\n":                                         "bogus",
		"report: {format: pdf}\n":                            "format",
		"apt: {lock_timeout: soon}\n":                        "invalid duration",
		"vulndb: {sources: [nvd]}\n":                         "unknown source",
		"vulndb: {max_size: lots}\n":                         "invalid size",
		"policy: {report_unfixed_cves: some}\n":              "report_unfixed_cves",
		"policy: {epss_bump: 2}\n":                           "epss_bump",
		"ignore: [{cve: CVE-2025-1}]\n":                      "needs a reason",
		"ignore: [{reason: x}]\n":                            "needs a cve or a package",
		"ignore: [{cve: x, reason: x}]\n":                    "not a CVE ID",
		"ignore: [{package: a, reason: x, kinds: [nope]}]\n": "unknown kind",
		"ignore: [{package: a, reason: x, until: soon}]\n":   "invalid date",
		"ignore: [{package: \"[\", reason: x}]\n":            "invalid package glob",
	} {
		_, _, err := Load(write(t, body), true)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", body, err, want)
		}
	}
	if _, _, err := Load("/nonexistent/config.yaml", true); err == nil {
		t.Error("missing explicit config accepted")
	}
	if c, _, err := Load("/nonexistent/config.yaml", false); err != nil || c.Policy.ExitThreshold != risk.High || c.Report.Format != "text" {
		t.Errorf("default load: %v", err)
	}
}
