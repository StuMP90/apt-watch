package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"aptwatch/internal/config"
	"aptwatch/internal/report"
	"aptwatch/internal/risk"
	"aptwatch/internal/vulndb"
)

var now = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

func finding(sev risk.Severity, suppressed bool) risk.Finding {
	f := risk.Finding{Key: "k", Kind: risk.KindUpdate, Severity: sev, Title: "openssl: update pending"}
	if suppressed {
		f.Suppressed = &risk.Suppression{Rule: "package openssl", Reason: "testing"}
	}
	return f
}

// code returns the exit code an error from a command gives.
func code(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var e exitError
	if !errors.As(err, &e) {
		t.Fatalf("not an exitError: %v", err)
	}
	return e.code
}

func setNagios(t *testing.T, on bool) {
	t.Helper()
	old := g.nagios
	g.nagios = on
	t.Cleanup(func() { g.nagios = old })
}

func TestExitFor(t *testing.T) {
	tests := []struct {
		name      string
		findings  []risk.Finding
		warnings  []string
		threshold risk.Severity
		want      int
		nagios    int
		line      string
	}{
		{"clean", nil, nil, risk.High, exitOK, nagiosOK, "OK - web01: no risks found — up to date"},
		{"info only", []risk.Finding{finding(risk.Info, false)}, nil, risk.High, exitOK, nagiosOK, "OK - "},
		{"below threshold", []risk.Finding{finding(risk.Medium, false)}, nil, risk.High, exitOK, nagiosWarning, "WARNING - web01: 1 MEDIUM"},
		{"at threshold", []risk.Finding{finding(risk.High, false)}, nil, risk.High, exitFindings, nagiosCritical, "CRITICAL - web01: 1 HIGH"},
		{"above threshold", []risk.Finding{finding(risk.Critical, false)}, nil, risk.High, exitFindings, nagiosCritical, "CRITICAL - "},
		{"lower threshold", []risk.Finding{finding(risk.Medium, false)}, nil, risk.Medium, exitFindings, nagiosCritical, "CRITICAL - "},
		{"suppressed", []risk.Finding{finding(risk.Critical, true)}, nil, risk.High, exitOK, nagiosOK, "OK - web01: no risks found"},
		{"warnings", nil, []string{"apt lists are stale", "second"}, risk.High, exitWarnings, nagiosWarning,
			"WARNING - web01: no risks found — up to date — 2 warnings: apt lists are stale"},
		{"findings beat warnings", []risk.Finding{finding(risk.High, false)}, []string{"w"}, risk.High, exitFindings, nagiosCritical,
			"CRITICAL - web01: 1 HIGH — up to date — 1 warning: w"},
		{"warnings below threshold", []risk.Finding{finding(risk.Low, false)}, []string{"w"}, risk.High, exitWarnings, nagiosWarning, "WARNING - "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Policy.ExitThreshold = tc.threshold
			rep := &report.Report{Host: "web01", Generated: now, Findings: tc.findings, Warnings: tc.warnings}

			setNagios(t, false)
			var out bytes.Buffer
			if got := code(t, exitFor(&out, cfg, rep)); got != tc.want {
				t.Errorf("exit code = %d, want %d", got, tc.want)
			}
			if out.Len() > 0 {
				t.Errorf("printed %q without --nagios", out.String())
			}

			setNagios(t, true)
			out.Reset()
			if got := code(t, exitFor(&out, cfg, rep)); got != tc.nagios {
				t.Errorf("nagios exit code = %d, want %d", got, tc.nagios)
			}
			line := out.String()
			if !strings.HasPrefix(line, tc.line) || strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
				t.Errorf("nagios printed %q, want one line starting %q", line, tc.line)
			}
		})
	}
}

func TestPrintReport(t *testing.T) {
	rep := &report.Report{Schema: report.SchemaVersion, Host: "web01", Generated: now}
	for format, want := range map[string]string{
		"text":   "web01",
		"json":   `"schema"`,
		"html":   "<html",
		"nagios": "",
	} {
		var out bytes.Buffer
		if err := printReport(&out, rep, format); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if want == "" && out.Len() > 0 || !strings.Contains(out.String(), want) {
			t.Errorf("%s: printed %.80q, want it to contain %q", format, out.String(), want)
		}
	}
}

func TestReportFormat(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		config string
		nagios bool
		want   string
		err    bool
	}{
		{"config", nil, "html", false, "html", false},
		{"flag beats config", []string{"--format", "json"}, "html", false, "json", false},
		{"nagios beats flag", []string{"--format", "json"}, "html", true, "nagios", false},
		{"invalid flag", []string{"--format", "xml"}, "text", false, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setNagios(t, tc.nagios)
			cmd := &cobra.Command{}
			cmd.Flags().String("format", "", "")
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			cfg := config.Default()
			cfg.Report.Format = tc.config
			got, err := reportFormat(cmd, cfg)
			if (err != nil) != tc.err || got != tc.want {
				t.Errorf("reportFormat = %q, %v; want %q, error %v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestFeedProblem(t *testing.T) {
	failed := now.Add(-time.Hour)
	tests := []struct {
		name string
		f    vulndb.FeedStatus
		want string
	}{
		{"ok", vulndb.FeedStatus{Cached: true, Checked: now.Add(-time.Hour)}, ""},
		{"not downloaded", vulndb.FeedStatus{}, "not downloaded yet (run aptwatch db update)"},
		{"never downloaded", vulndb.FeedStatus{Error: "404", ErrorAt: failed}, "never downloaded; failed 2026-05-01 11:00: 404"},
		{"refresh failed", vulndb.FeedStatus{Cached: true, Checked: now.Add(-time.Hour), Error: "timeout", ErrorAt: failed},
			"refresh failed 2026-05-01 11:00: timeout"},
		{"stale", vulndb.FeedStatus{Cached: true, Checked: now.Add(-4 * 24 * time.Hour)}, "stale: 4d old"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := feedProblem(tc.f, 72*time.Hour, now); got != tc.want {
				t.Errorf("feedProblem = %q, want %q", got, tc.want)
			}
		})
	}
	if got := feedProblem(vulndb.FeedStatus{Cached: true, Checked: now.AddDate(-1, 0, 0)}, 0, now); got != "" {
		t.Errorf("with no stale_after: %q, want no problem", got)
	}
}

func TestPrintFeeds(t *testing.T) {
	cfg := config.Default()
	cfg.Vulndb.CacheDir = "/var/cache/aptwatch"
	cfg.Vulndb.StaleAfter = config.Duration(72 * time.Hour)
	fs := []vulndb.FeedStatus{
		{Name: "ubuntu-oval", Cached: true, Fetched: now.AddDate(0, 0, -2), Checked: now.Add(-3 * time.Hour), Size: 5 << 20},
		{Name: "kev"},
	}
	var out bytes.Buffer
	if err := printFeeds(&out, cfg, vulndb.OS{ID: "ubuntu", VersionID: "24.04"}, fs, now); err != nil {
		t.Fatal(err)
	}
	want := `Vulnerability data in /var/cache/aptwatch for ubuntu 24.04

FEED         CHECKED                    CHANGED     SIZE    STATUS
ubuntu-oval  2026-05-01 09:00 (3h ago)  2026-04-29  5.0 MB  ok
kev          -                          -           -       not downloaded yet (run aptwatch db update)
`
	if out.String() != want {
		t.Errorf("printFeeds printed\n%s\nwant\n%s", out.String(), want)
	}
}

func TestHumanSize(t *testing.T) {
	for n, want := range map[int64]string{
		0: "0 B", 1023: "1023 B", 1024: "1 KB", 1536: "2 KB",
		5 << 20: "5.0 MB", 3<<30 + 1<<29: "3.5 GB",
	} {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPlural(t *testing.T) {
	if plural(0) != "s" || plural(1) != "" || plural(2) != "s" {
		t.Error("plural: want s for 0 and 2, nothing for 1")
	}
}

func TestLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aptwatch.lock")
	unlock, err := lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock(path); err == nil || !strings.Contains(err.Error(), "another aptwatch run holds") {
		t.Errorf("second lock: %v, want another run holds it", err)
	}
	unlock()
	unlock, err = lock(path)
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock()

	if _, err := lock(filepath.Join(t.TempDir(), "missing", "aptwatch.lock")); err == nil {
		t.Error("lock in a missing directory: no error")
	}
}
