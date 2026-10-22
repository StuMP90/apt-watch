package risk

import (
	"strings"
	"testing"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/vulndb"
)

func TestChangelogFindings(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	days := func(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }
	inv := &collect.Inventory{
		Packages: []collect.Package{
			{Name: "php9-cli", Version: "9.1-1+sury1", Source: "php9", SourceVersion: "9.1-1+sury1", Repo: "ppa:example/php", ThirdParty: true, InDistro: true},
			{Name: "tool", Version: "2-1", Source: "tool", SourceVersion: "2-1", Repo: "apt.example.net", ThirdParty: true},
		},
		Simulation: &collect.Simulation{Updates: []collect.Update{
			{Package: "tool", Installed: "2-1", Candidate: "3-1", Source: "tool", SourceVersion: "3-1"},
		}},
		Changelogs: map[string]*collect.Changelog{
			"php9": {Source: "php9", Installed: "9.1-1+sury1", Fixed: []string{"CVE-A", "CVE-B", "CVE-OLD", "CVE-UNKNOWN"}},
			"tool": {Source: "tool", Installed: "2-1", Candidate: "3-1", Pending: []string{"CVE-T"}},
		},
	}
	inv.System.OS.ID = "ubuntu"
	db := &vulndb.DB{
		Sources: []string{vulndb.SourceUbuntu},
		Advisories: map[string][]vulndb.Advisory{
			"php9": {
				{CVE: "CVE-A", Fixed: "9.0-0ubuntu1", Priority: "critical", Published: days(1)},
				{CVE: "CVE-OLD", Fixed: "8.0-0ubuntu1", Priority: "high", Published: days(400)},
				{CVE: "CVE-GAP", Fixed: "9.0-0ubuntu2", Priority: "high", Published: days(10)},
				{CVE: "CVE-GAPOLD", Fixed: "9.0-0ubuntu2", Priority: "high", Published: days(200)},
				{CVE: "CVE-UNFIXED", Priority: "high", Published: days(5)},
			},
			"php8": {{CVE: "CVE-B", Fixed: "8.9-0ubuntu1", Priority: "medium", Published: days(2)}},
			"tool": {{CVE: "CVE-T", Priority: "low", Published: days(3)}},
		},
		KEV: map[string]time.Time{"CVE-T": {}},
	}
	p := DefaultPolicy()
	got := map[string]Finding{}
	for _, f := range changelogFindings(inv, db, p, now) {
		got[f.Key] = f
	}
	if len(got) != 3 {
		t.Errorf("got %d findings: %v", len(got), got)
	}
	if f := got["cve:CVE-T:tool"]; f.Kind != KindCVEFixAvailable || f.Severity != Critical || !f.FixAvail || f.CVEs[0].Fixed != "3-1" ||
		f.Title != "CVE-T in tool 2-1: fixed by pending update 3-1" {
		t.Errorf("pending: %+v", f)
	}
	if f := got["changelog-cves:php9"]; f.Kind != KindCVEFixedThirdParty || f.Severity != Info || len(f.CVEs) != 2 ||
		f.Title != "php9 9.1-1+sury1 from ppa:example/php fixes 2 recent CVEs: CVE-A (critical), CVE-B (medium)" {
		t.Errorf("fixed: %+v", f)
	}
	if f := got["cve-gap:CVE-GAP:php9"]; f.Kind != KindCVEThirdPartyGap || f.Severity != Medium || f.CVEs[0].Fixed != "9.0-0ubuntu2" ||
		!strings.Contains(f.Title, "Ubuntu fixed it in 9.0-0ubuntu2; ppa:example/php's changelog doesn't mention it") {
		t.Errorf("gap: %+v", f)
	}

	p.ThirdPartyGaps = false
	p.RecentCVEs = 0
	for _, f := range changelogFindings(inv, db, p, now) {
		if f.Kind != KindCVEFixAvailable {
			t.Errorf("with gaps and recent CVEs off: %s", f.Key)
		}
	}

	// A changelog that names no CVEs gives no gap findings.
	inv.Changelogs["php9"].Fixed = nil
	for _, f := range changelogFindings(inv, db, DefaultPolicy(), now) {
		if f.Kind == KindCVEThirdPartyGap {
			t.Errorf("gap from a changelog without CVEs: %s", f.Key)
		}
	}

	refs := []CVERef{{ID: "a", Priority: "critical"}, {ID: "b", Priority: "medium"}, {ID: "c", Priority: "medium"}, {ID: "d", KEV: true}}
	if s := cveSummary(refs); s != "4 recent CVEs (1 exploited, 1 critical, 2 medium)" {
		t.Errorf("cveSummary: %q", s)
	}

	note := thirdPartyFindings(inv)[1].Detail
	if !strings.Contains(note, "reads the CVEs named in its changelog") {
		t.Errorf("third-party note: %q", note)
	}
}
