package report

import (
	"strings"
	"testing"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/risk"
	"aptwatch/internal/state"
)

func sample() *Report {
	now := time.Date(2026, 10, 22, 6, 0, 0, 0, time.UTC)
	r := &Report{
		Schema: SchemaVersion, Tool: "aptwatch test", Host: "web1", Generated: now,
		Findings: []risk.Finding{
			{Key: "cve:CVE-1:pkg", Kind: risk.KindCVEFixAvailable, Severity: risk.High, Title: "CVE-1 in <script>alert(1)</script>",
				Detail: "a & b", Since: now.Add(-48 * time.Hour), Packages: []risk.PkgRef{{Name: "pkg"}},
				CVEs: []risk.CVERef{{ID: "CVE-1", Priority: "high", KEV: true, URL: "https://example.org/CVE-1"}}},
			{Key: "changelog-cves:php", Kind: risk.KindCVEFixedThirdParty, Severity: risk.Info, Title: "php fixes 1 recent CVE",
				CVEs: []risk.CVERef{{ID: "CVE-2", Priority: "critical"}}},
		},
		Updates: []collect.Update{
			{Package: "pkg", Installed: "1-1", Candidate: "1-2", Security: true, Origins: []collect.Origin{{Suite: "noble-security"}}},
			{Package: "other", Candidate: "2-1", Phased: true},
		},
		Diff:     &state.Diff{New: []string{"cve:CVE-1:pkg"}},
		Warnings: []string{"vulndb: stale"},
	}
	r.System.Hostname = "web1"
	r.System.OS.PrettyName = "Ubuntu 24.04 LTS"
	r.System.Kernel.Running = "6.8.0-1"
	return r
}

func TestFormats(t *testing.T) {
	r := sample()
	var text, html strings.Builder
	if err := r.Text(&text); err != nil {
		t.Fatal(err)
	}
	if err := r.HTML(&html); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"web1: 1 HIGH — 2 updates pending (1 security, 1 phased)",
		"Changes since last run", "NEW", "Findings (1)",
		"Recent CVEs fixed in installed third-party packages",
		"Pending updates (2)", "Security (1)", "Other (1)", "noble-security", "(new)", "phased",
		"sudo apt-get install --only-upgrade pkg", "vulndb: stale",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text: missing %q", want)
		}
		if !strings.Contains(html.String(), want) {
			t.Errorf("html: missing %q", want)
		}
	}
	if !strings.Contains(text.String(), "CVE-2 (critical)") {
		t.Error("text: missing CVE-2 (critical)")
	}
	h := html.String()
	for _, want := range []string{
		`CVE-2</span> <span>(critical)</span>`,
		"<!doctype html>", `<a href="https://example.org/CVE-1">CVE-1</a>`, `class="kev"`,
		"&lt;script&gt;alert(1)&lt;/script&gt;", "a &amp; b", `class="top high"`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("html: missing %q", want)
		}
	}
	for _, bad := range []string{"<script>", "http://", "src="} {
		if strings.Contains(h, bad) {
			t.Errorf("html: contains %q", bad)
		}
	}
}

func TestFirstRun(t *testing.T) {
	r := sample()
	r.Diff.FirstRun = true
	var text, html strings.Builder
	if err := r.Text(&text); err != nil {
		t.Fatal(err)
	}
	if err := r.HTML(&html); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": text.String(), "html": html.String()} {
		if !strings.Contains(out, firstRunLine) {
			t.Errorf("%s: missing %q", name, firstRunLine)
		}
		if strings.Contains(out, "NEW") {
			t.Errorf("%s: lists findings as NEW on a first run", name)
		}
	}
}

func TestSuppressed(t *testing.T) {
	r := sample()
	r.Findings[0].Suppressed = &risk.Suppression{Rule: "CVE-1", Reason: "not exposed", Until: risk.Date{Time: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)}}
	var until risk.Date
	_ = until.UnmarshalText([]byte("2026-10-01"))
	r.Expired = []risk.IgnoreRule{{CVE: "CVE-9", Reason: "old reason", Until: until}}
	if got := r.Summary(); !strings.HasPrefix(got, "web1: no risks found") {
		t.Errorf("Summary counts a suppressed finding: %q", got)
	}
	if r.Highest() != risk.Info {
		t.Errorf("Highest = %v", r.Highest())
	}
	var text, html strings.Builder
	if err := r.Text(&text); err != nil {
		t.Fatal(err)
	}
	if err := r.HTML(&html); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Suppressed findings (1)", "ignored (CVE-1, until 2026-12-31): not exposed",
		"ignore rule CVE-9 expired on 2026-10-01 (old reason)",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text: missing %q\n%s", want, text.String())
		}
		if !strings.Contains(html.String(), want) {
			t.Errorf("html: missing %q", want)
		}
	}
	if !strings.Contains(text.String(), "\nFindings (0)\n  none") {
		t.Error("text lists the suppressed finding as active")
	}
}
