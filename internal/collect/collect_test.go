package collect

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func openFixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseDpkgStatus(t *testing.T) {
	pkgs, err := ParseDpkgStatus(openFixture(t, "dpkg-status-small"))
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{Name: "libssl3t64", Arch: "amd64", Version: "3.0.13-0ubuntu3.4", Source: "openssl", SourceVersion: "3.0.13-0ubuntu3.4"},
		{Name: "openssl", Arch: "amd64", Version: "3.0.13-0ubuntu3.4", Source: "openssl", SourceVersion: "3.0.13-0ubuntu3.4"},
		{Name: "libglib2.0-0t64", Arch: "amd64", Version: "2.80.0-6ubuntu3.9", Source: "glib2.0", SourceVersion: "2.80.0-6ubuntu3.9"},
		{Name: "libc6", Arch: "i386", Version: "2.39-0ubuntu8.4", Source: "glibc", SourceVersion: "2.39-0ubuntu8.4"},
		{Name: "linux-image-6.8.0-90-generic", Arch: "amd64", Version: "6.8.0-90.91", Source: "linux-signed", SourceVersion: "6.8.0-90.91", Hold: true},
	}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("got  %+v\nwant %+v", pkgs, want)
	}
}

func TestParseSimulationMixed(t *testing.T) {
	sim, err := ParseSimulation(openFixture(t, "apt-sim-mixed.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sim.Phased, []string{"cloud-init", "libglib2.0-0t64"}; !reflect.DeepEqual(got, want) {
		t.Errorf("phased = %v, want %v", got, want)
	}
	if got, want := sim.Removals, []string{"oldlib"}; !reflect.DeepEqual(got, want) {
		t.Errorf("removals = %v, want %v", got, want)
	}
	type row struct {
		pkg, arch, old, cand string
		sec, esm             bool
		origins              int
	}
	want := []row{
		{"libssl3t64", "amd64", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5", true, false, 2},
		{"openssl", "amd64", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5", true, false, 2},
		{"linux-image-6.8.0-91-generic", "amd64", "", "6.8.0-91.92", false, false, 1},
		{"libc6", "i386", "2.39-0ubuntu8.4", "2.39-0ubuntu8.5", true, true, 1},
		{"google-chrome-stable", "amd64", "140.0.1-1", "141.0.2-1", false, false, 1},
		{"libgnutls30", "amd64", "3.7.9-2+deb12u3", "3.7.9-2+deb12u4", true, false, 1},
		{"localpkg", "amd64", "1.0", "1.1", false, false, 1},
	}
	if len(sim.Updates) != len(want) {
		t.Fatalf("got %d updates, want %d: %+v", len(sim.Updates), len(want), sim.Updates)
	}
	for i, w := range want {
		u := sim.Updates[i]
		got := row{u.Package, u.Arch, u.Installed, u.Candidate, u.Security, u.ESM, len(u.Origins)}
		if got != w {
			t.Errorf("update %d: got %+v, want %+v", i, got, w)
		}
	}
	if o := sim.Updates[4].Origins[0]; o.Origin != "Google LLC" || o.Version != "1.0" || o.Suite != "stable" {
		t.Errorf("origin with space parsed as %+v", o)
	}
	if o := sim.Updates[0].Origins[1]; o.String() != "Ubuntu:24.04/noble-security" {
		t.Errorf("origin String() = %q", o.String())
	}
}

func TestParseSimulationRealNoble(t *testing.T) {
	deferred, err := ParseSimulation(openFixture(t, "apt-sim-noble-phased.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(deferred.Updates) != 0 || len(deferred.Phased) != 9 {
		t.Errorf("deferred run: %d updates, %d phased; want 0, 9", len(deferred.Updates), len(deferred.Phased))
	}
	all, err := ParseSimulation(openFixture(t, "apt-sim-noble-include-phased.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Updates) != 9 {
		t.Fatalf("include-phased run: %d updates, want 9", len(all.Updates))
	}
	for _, u := range all.Updates {
		if u.Security || u.Installed == "" || u.Origins[0].Suite != "noble-updates" {
			t.Errorf("unexpected update %+v", u)
		}
	}
}

func TestParseInstErrors(t *testing.T) {
	for _, s := range []string{"", "foo", "foo [1.0 (2.0 x/y [amd64])", "foo [1.0] 2.0"} {
		if _, err := parseInst(s); err == nil {
			t.Errorf("parseInst(%q) succeeded, want error", s)
		}
	}
}

func TestParseDistroInfo(t *testing.T) {
	ubuntu := "version,codename,series,created,release,eol,eol-server,eol-esm,eol-legacy\n" +
		"22.04 LTS,Jammy Jellyfish,jammy,2021-10-14,2022-04-21,2027-06-01,2027-06-01,2032-04-09,2037-04-09\n" +
		"24.04 LTS,Noble Numbat,noble,2023-10-12,2024-04-25,2029-05-31,2029-05-31,2034-04-25,2039-04-28\n"
	e, err := ParseDistroInfo(strings.NewReader(ubuntu), "ubuntu", "noble")
	if err != nil {
		t.Fatal(err)
	}
	if e.SecurityEnd != date("2029-05-31") || e.ExtendedEnd != date("2034-04-25") {
		t.Errorf("ubuntu noble: %+v", e)
	}

	debian := "version,codename,series,created,release,eol,eol-lts,eol-elts\n" +
		"12,Bookworm,bookworm,2021-08-14,2023-06-10,2026-07-11,2028-06-30,2033-06-30\n" +
		"14,Forky,forky,2025-08-09\n"
	e, err = ParseDistroInfo(strings.NewReader(debian), "debian", "bookworm")
	if err != nil {
		t.Fatal(err)
	}
	if e.SecurityEnd != date("2028-06-30") || !strings.Contains(e.Note, "2026-07-11") {
		t.Errorf("debian bookworm: %+v", e)
	}
	if e, err = ParseDistroInfo(strings.NewReader(debian), "debian", "forky"); err != nil || e != nil {
		t.Errorf("forky: got %+v, %v; want nil, nil", e, err)
	}
	if _, err = ParseDistroInfo(strings.NewReader(debian), "debian", "nonesuch"); err == nil {
		t.Error("missing codename: want error")
	}
}

func TestNewestKernel(t *testing.T) {
	pkgs := []Package{
		{Name: "linux-image-generic", Version: "6.8.0-91.92"},
		{Name: "linux-image-6.8.0-90-generic", Version: "6.8.0-90.91"},
		{Name: "linux-image-6.8.0-91-generic", Version: "6.8.0-91.92"},
		{Name: "linux-image-unsigned-6.8.0-100-lowlatency", Version: "6.8.0-100.100"},
		{Name: "linux-image-6.8.0-9-generic", Version: "6.8.0-9.9"},
	}
	if got := NewestKernel(pkgs, "6.8.0-90-generic"); got != "6.8.0-91-generic" {
		t.Errorf("NewestKernel = %q", got)
	}
	if got := NewestKernel(pkgs, "6.8.0-1-lowlatency"); got != "6.8.0-100-lowlatency" {
		t.Errorf("NewestKernel lowlatency = %q", got)
	}
}

func TestParseOSRelease(t *testing.T) {
	o, err := ParseOSRelease(strings.NewReader("PRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nUBUNTU_CODENAME=noble\n"))
	if err != nil {
		t.Fatal(err)
	}
	if o != (OSRelease{ID: "ubuntu", VersionID: "24.04", Codename: "noble", PrettyName: "Ubuntu 24.04.5 LTS"}) {
		t.Errorf("got %+v", o)
	}
}

func date(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}

func TestParseAptCacheShow(t *testing.T) {
	in := `Package: libfoo1
Source: foo (1.2-3)
Version: 1.2-3+b1
Description: x
 Source: not a field

Package: foo-data
Source: foo
Architecture: all
Version: 1.2-3

Package: bar
Version: 2.0-1
`
	got, err := ParseAptCacheShow(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"libfoo1=1.2-3+b1": {"foo", "1.2-3"},
		"foo-data=1.2-3":   {"foo", "1.2-3"},
		"bar=2.0-1":        {"bar", "2.0-1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
