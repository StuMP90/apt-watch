package risk

import (
	"strings"
	"testing"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/vulndb"
)

func TestCheckCVE(t *testing.T) {
	inv := &collect.Inventory{
		Packages: []collect.Package{
			{Name: "libfoo1", Version: "1.0-1", Source: "foo", SourceVersion: "1.0-1"},
			{Name: "foo-bin", Version: "1.0-1", Source: "foo", SourceVersion: "1.0-1"},
			{Name: "bar", Version: "2.0-1", Source: "bar", SourceVersion: "2.0-1"},
			{Name: "baz", Version: "3.0-1", Source: "baz", SourceVersion: "3.0-1"},
			{Name: "libqux1", Version: "4.0-2", Source: "qux", SourceVersion: "4.0-2"},
			{Name: "php9-cli", Version: "9.1-1+sury1", Source: "php9", SourceVersion: "9.1-1+sury1", Repo: "ppa:example/php", ThirdParty: true, InDistro: true},
			{Name: "tool", Version: "2-1", Source: "tool", SourceVersion: "2-1", Repo: "apt.example.net", ThirdParty: true},
			{Name: "nocl", Version: "1-1", Source: "nocl", SourceVersion: "1-1", Repo: "apt.example.net", ThirdParty: true},
		},
		Simulation: &collect.Simulation{Updates: []collect.Update{
			{Package: "libfoo1", Installed: "1.0-1", Candidate: "1.0-2", Source: "foo", SourceVersion: "1.0-2"},
			{Package: "foo-bin", Installed: "1.0-1", Candidate: "1.0-2", Source: "foo", SourceVersion: "1.0-2"},
			{Package: "tool", Installed: "2-1", Candidate: "3-1", Source: "tool", SourceVersion: "3-1"},
		}},
		Changelogs: map[string]*collect.Changelog{
			"php9": {Source: "php9", Installed: "9.1-1+sury1", Fixed: []string{"CVE-2026-0001"}},
			"tool": {Source: "tool", Installed: "2-1", Candidate: "3-1", Pending: []string{"CVE-2026-0007"}},
		},
	}
	inv.System.OS.ID = "ubuntu"
	inv.System.Reboot = collect.Reboot{Required: true, Packages: []string{"libqux1"}}
	added := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	db := &vulndb.DB{
		Sources: []string{vulndb.SourceUbuntu},
		Advisories: map[string][]vulndb.Advisory{
			"foo":    {{CVE: "CVE-2026-0001", Fixed: "1.0-2", Priority: "critical", Desc: "Foo overflow."}},
			"php9":   {{CVE: "CVE-2026-0001", Fixed: "9.0-0ubuntu1", Priority: "critical"}, {CVE: "CVE-2026-0002", Fixed: "9.0-0ubuntu2"}},
			"bar":    {{CVE: "CVE-2026-0002", Fixed: "2.0-1"}, {CVE: "CVE-2026-0003", Fixed: "2.1-1", Pro: true}},
			"baz":    {{CVE: "CVE-2026-0003", Fixed: "3.5-1"}, {CVE: "CVE-2026-0004"}},
			"absent": {{CVE: "CVE-2026-0005", Fixed: "1-1"}},
			"qux":    {{CVE: "CVE-2026-0006", Fixed: "4.0-2"}},
			"nocl":   {{CVE: "CVE-2026-0008", Fixed: "1-2"}},
		},
		KEV: map[string]time.Time{"CVE-2026-0001": added},
	}

	type pkg struct{ src, status string }
	for _, tc := range []struct {
		id     string
		status string
		pkgs   []pkg
	}{
		{"CVE-2026-0001", StatusPending, []pkg{{"foo", StatusPending}, {"php9", StatusFixed}}},
		{"CVE-2026-0002", StatusUnconfirmed, []pkg{{"bar", StatusFixed}, {"php9", StatusUnconfirmed}}},
		{"CVE-2026-0003", StatusUnreachable, []pkg{{"bar", StatusPro}, {"baz", StatusUnreachable}}},
		{"CVE-2026-0004", StatusNoFix, []pkg{{"baz", StatusNoFix}}},
		{"CVE-2026-0005", StatusNotAffected, nil},
		{"CVE-2026-0006", StatusRebootPending, []pkg{{"qux", StatusRebootPending}}},
		{"CVE-2026-0007", StatusPending, []pkg{{"tool", StatusPending}}},
		{"CVE-2026-0008", StatusUnknown, []pkg{{"nocl", StatusUnknown}}},
		{"CVE-2026-9999", StatusUnknown, nil},
	} {
		c := CheckCVE(inv, db, tc.id)
		var got []pkg
		for _, p := range c.Packages {
			got = append(got, pkg{p.Source, p.Status})
		}
		if c.Status != tc.status || len(got) != len(tc.pkgs) {
			t.Errorf("%s: %s %v, want %s %v", tc.id, c.Status, got, tc.status, tc.pkgs)
			continue
		}
		for i := range got {
			if got[i] != tc.pkgs[i] {
				t.Errorf("%s: %v, want %v", tc.id, got, tc.pkgs)
			}
		}
	}

	c := CheckCVE(inv, db, "CVE-2026-0001")
	if !c.Known || !c.KEV || !c.KEVAdded.Equal(added) || c.Priority != "critical" || c.Desc != "Foo overflow." {
		t.Errorf("details: %+v", c)
	}
	if p := c.Packages[0]; p.Command != "sudo apt-get install --only-upgrade libfoo1 foo-bin" || p.Fixed != "1.0-2" {
		t.Errorf("foo: %+v", p)
	}
	if c := CheckCVE(inv, db, "CVE-2026-0005"); !c.Known || len(c.NotInstalled) != 1 {
		t.Errorf("not installed: %+v", c)
	}
	if c := CheckCVE(inv, db, "CVE-2026-0002"); !strings.Contains(c.Packages[1].Note, "Ubuntu fixed it in 9.0-0ubuntu2") {
		t.Errorf("unconfirmed note: %q", c.Packages[1].Note)
	}
	if c := CheckCVE(inv, db, "CVE-2026-9999"); c.Known {
		t.Error("unknown CVE known")
	}
	// Without vulnerability data, the changelogs still count.
	if c := CheckCVE(inv, nil, "CVE-2026-0007"); c.Status != StatusPending {
		t.Errorf("no db: %+v", c)
	}

	for in, want := range map[string]string{"cve-2026-12345": "CVE-2026-12345", " CVE-2024-0001 ": "CVE-2024-0001", "CVE-24-1": "", "USN-1-1": ""} {
		got, err := NormCVE(in)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("NormCVE(%q) = %q, %v", in, got, err)
		}
	}
	if !NeedsAction(StatusNoFix) || NeedsAction(StatusUnknown) || NeedsAction(StatusFixed) {
		t.Error("NeedsAction")
	}
}
