package risk

import (
	"slices"
	"testing"
	"time"

	"aptwatch/internal/collect"
	"aptwatch/internal/vulndb"
)

func testInventory() *collect.Inventory {
	return &collect.Inventory{
		Packages: []collect.Package{
			{Name: "libfoo1", Version: "1.0-1+b1", Source: "foo", SourceVersion: "1.0-1"},
			{Name: "foo-bin", Version: "1.0-1", Source: "foo", SourceVersion: "1.0-1"},
			{Name: "bar", Version: "2.0-1", Source: "bar", SourceVersion: "2.0-1"},
			{Name: "baz", Version: "3.0-1", Source: "baz", SourceVersion: "3.0-1"},
		},
		Simulation: &collect.Simulation{Updates: []collect.Update{
			{Package: "libfoo1", Installed: "1.0-1+b1", Candidate: "1.0-2+b1", Source: "foo", SourceVersion: "1.0-2", Security: true},
			{Package: "foo-bin", Installed: "1.0-1", Candidate: "1.0-2", Security: true}, // unresolved: falls back
		}},
	}
}

func testDB() *vulndb.DB {
	return &vulndb.DB{
		Sources: []string{vulndb.SourceUbuntu},
		Advisories: map[string][]vulndb.Advisory{
			"foo": {
				{CVE: "CVE-1", Fixed: "1.0-2", Priority: "high"},       // fixed by update
				{CVE: "CVE-2", Fixed: "1.0-0", Priority: "critical"},   // already fixed
				{CVE: "CVE-3", Fixed: "1.0-3", Priority: "low"},        // beyond the candidate
				{CVE: "CVE-4", Priority: "medium"},                     // unfixed
				{CVE: "CVE-5", Fixed: "1.0-2", Priority: "negligible"}, // fixed, EPSS bump
			},
			"bar": {
				{CVE: "CVE-6", Fixed: "2.0-1ubuntu0.1+esm1", Priority: "medium", Pro: true},
				{CVE: "CVE-7", Priority: "low"}, // unfixed, in KEV
				{CVE: "CVE-8", Priority: "low"},
			},
			"notinstalled": {{CVE: "CVE-9", Fixed: "9", Priority: "critical"}},
		},
		KEV:  map[string]time.Time{"CVE-7": {}},
		EPSS: map[string]float64{"CVE-5": 0.9},
	}
}

func TestCVEFindings(t *testing.T) {
	p := DefaultPolicy()
	fs := CVEFindings(testInventory(), testDB(), p)
	got := map[string]Finding{}
	for _, f := range fs {
		got[f.Key] = f
	}
	want := map[string]struct {
		kind string
		sev  Severity
	}{
		"cve:CVE-1:foo":       {KindCVEFixAvailable, High},
		"cve:CVE-3:foo":       {KindCVEFixUnreachable, Medium},
		"cve:CVE-5:foo":       {KindCVEFixAvailable, Medium},
		"cve:CVE-6:bar":       {KindCVEFixUnreachable, High},
		"cve:CVE-7:bar":       {KindCVEUnfixed, High},
		KindCVEUnfixedSummary: {KindCVEUnfixedSummary, Info},
	}
	if len(got) != len(want) {
		t.Errorf("got %d findings, want %d: %v", len(got), len(want), fs)
	}
	for k, w := range want {
		f, ok := got[k]
		if !ok {
			t.Errorf("missing %s", k)
			continue
		}
		if f.Kind != w.kind || f.Severity != w.sev {
			t.Errorf("%s: got %s/%s, want %s/%s", k, f.Kind, f.Severity, w.kind, w.sev)
		}
	}
	if s := got[KindCVEUnfixedSummary]; s.Title != "2 CVEs with no fix yet affect 2 installed source packages" {
		t.Errorf("summary title %q", s.Title)
	}
	if f := got["cve:CVE-1:foo"]; len(f.Packages) != 2 || f.CVEs[0].URL != "https://ubuntu.com/security/CVE-1" {
		t.Errorf("CVE-1 finding: %+v", f)
	}

	p.ReportUnfixed = UnfixedNone
	for _, f := range CVEFindings(testInventory(), testDB(), p) {
		if f.Kind == KindCVEUnfixedSummary {
			t.Error("summary with report_unfixed_cves: none")
		}
	}
	p.ReportUnfixed = UnfixedFull
	n := 0
	for _, f := range CVEFindings(testInventory(), testDB(), p) {
		if f.Kind == KindCVEUnfixed {
			n++
		}
	}
	if n != 3 {
		t.Errorf("full: %d unfixed findings, want 3", n)
	}
}

func TestAddCVEFindingsDropsCoveredUpdates(t *testing.T) {
	inv := testInventory()
	fs := Evaluate(inv, DefaultPolicy(), time.Now())
	fs = AddCVEFindings(fs, inv, testDB(), DefaultPolicy(), time.Now())
	for _, f := range fs {
		if f.Kind == KindSecurityUpdate {
			t.Errorf("security update finding kept: %s", f.Key)
		}
	}
}

func TestOtherKernels(t *testing.T) {
	pk := func(name, src string) collect.Package {
		return collect.Package{Name: name, Version: "1", Source: src, SourceVersion: "1"}
	}
	ubuntu := []collect.Package{
		pk("linux-image-6.17.0-40-generic", "linux-signed-hwe-6.17"),
		pk("linux-modules-6.17.0-40-generic", "linux-hwe-6.17"),
		pk("linux-image-7.0.0-38-generic", "linux-signed-hwe-7.0"),
		pk("linux-modules-7.0.0-38-generic", "linux-hwe-7.0"),
		pk("linux-headers-7.0.0-38-generic", "linux-hwe-7.0"),
		pk("linux-libc-dev", "linux"),
		pk("linux-firmware", "linux-firmware"),
	}
	debian := []collect.Package{
		pk("linux-image-6.1.0-17-amd64", "linux-signed-amd64"),
		pk("linux-image-6.1.0-18-amd64", "linux-signed-amd64"),
		pk("linux-libc-dev", "linux"),
	}
	trixie := []collect.Package{
		pk("linux-image-6.12.43+deb13-amd64", "linux-signed-amd64"),
		pk("linux-image-6.12.48+deb13-amd64", "linux-signed-amd64"),
		pk("linux-libc-dev", "linux"),
	}
	for _, tc := range []struct {
		name            string
		pkgs            []collect.Package
		running, newest string
		want            []string
	}{
		{"ubuntu", ubuntu, "7.0.0-38-generic", "", []string{"linux", "linux-hwe-6.17", "linux-signed-hwe-6.17", "linux-signed-hwe-7.0"}},
		{"ubuntu newest", ubuntu, "6.17.0-40-generic", "7.0.0-38-generic", []string{"linux", "linux-hwe-6.17", "linux-signed-hwe-6.17", "linux-signed-hwe-7.0"}},
		{"debian", debian, "6.1.0-18-amd64", "", []string{"linux-signed-amd64"}},
		{"debian 13", trixie, "6.12.43+deb13-amd64", "6.12.48+deb13-amd64", []string{"linux-signed-amd64"}},
		{"unknown kernel", ubuntu, "5.0.0-1-generic", "", nil},
	} {
		inv := &collect.Inventory{Packages: tc.pkgs, Simulation: &collect.Simulation{}}
		inv.System.Kernel = collect.Kernel{Running: tc.running, Newest: tc.newest}
		got := otherKernels(inv, installedSources(inv))
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestThirdParty(t *testing.T) {
	inv := testInventory()
	inv.System.OS.ID = "ubuntu"
	// A PPA build of foo: its version means nothing to Ubuntu's advisories.
	for i := range inv.Packages {
		if inv.Packages[i].Source == "foo" {
			inv.Packages[i].Repo, inv.Packages[i].ThirdParty, inv.Packages[i].InDistro = "ppa.example.org/foo", true, true
		}
	}
	inv.Packages = append(inv.Packages,
		collect.Package{Name: "tool", Version: "1", Source: "tool", SourceVersion: "1", Repo: "apt.example.net", ThirdParty: true})
	for _, f := range CVEFindings(inv, testDB(), DefaultPolicy()) {
		if f.Source == "foo" {
			t.Errorf("CVE finding for third-party source: %s", f.Key)
		}
	}
	got := map[string]Finding{}
	for _, f := range thirdPartyFindings(inv) {
		got[f.Key] = f
	}
	if f := got["third-party:ppa.example.org/foo"]; f.Severity != Low || len(f.Packages) != 2 || !f.FixAvail ||
		f.Title != "2 packages from ppa.example.org/foo (foo-bin, libfoo1) aren't covered by Ubuntu's CVE data" {
		t.Errorf("ppa finding: %+v", f)
	}
	if f := got["third-party:apt.example.net"]; f.Severity != Info || f.FixAvail {
		t.Errorf("non-replacing finding: %+v", f)
	}

	// One distro binary keeps the source in the CVE match.
	inv.Packages[1].ThirdParty = false
	if !slices.ContainsFunc(CVEFindings(inv, testDB(), DefaultPolicy()), func(f Finding) bool { return f.Source == "foo" }) {
		t.Error("mixed source skipped")
	}
}
