package collect

import (
	"os"
	"reflect"
	"slices"
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
		{"examplepkg", "amd64", "2.0-1", "2.1-1", false, false, 1},
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
	if o := sim.Updates[7].Origins[0]; o.Origin != "Example" || o.Version != "" || o.Suite != "stable" || o.String() != "Example:stable" {
		t.Errorf("origin without version parsed as %+v", o)
	}
	if o := sim.Updates[0].Origins[1]; o.String() != "Ubuntu:24.04/noble-security" {
		t.Errorf("origin String() = %q", o.String())
	}
}

// TestParseSimulationReleases runs the parser over synthetic apt-get -s
// output in each supported release's format: name.txt from the normal run
// and name-all.txt from the one including phased updates. apt 2.8 and later
// list deferred updates under a phasing header; apt 2.4 lists them as kept
// back, with unrelated holds. Debian doesn't phase, so its runs are the same.
func TestParseSimulationReleases(t *testing.T) {
	for _, tc := range []struct {
		name, all     string
		updates       int
		header        []string // listed under the phasing header
		phased        []string
		security, esm []string
	}{
		{name: "jammy", all: "jammy-all", updates: 10,
			phased:   []string{"cloud-init", "python3-software-properties", "software-properties-common"},
			security: []string{"libavcodec58", "libssl3", "linux-generic", "linux-image-5.15.0-130-generic", "linux-image-generic", "linux-modules-5.15.0-130-generic", "openssl"},
			esm:      []string{"libavcodec58"}},
		{name: "noble", all: "noble-all", updates: 6,
			header:   []string{"cloud-init", "libglib2.0-0t64", "libglib2.0-bin", "libglib2.0-data"},
			phased:   []string{"cloud-init", "libglib2.0-0t64", "libglib2.0-bin", "libglib2.0-data"},
			security: []string{"libssl3t64", "openssl"}},
		{name: "resolute", all: "resolute-all", updates: 5,
			header:   []string{"libsystemd0", "systemd"},
			phased:   []string{"libsystemd0", "systemd"},
			security: []string{"libssl3t64", "libxml2-16", "openssl"},
			esm:      []string{"libxml2-16"}},
		{name: "bookworm", all: "bookworm", updates: 8,
			security: []string{"libssl3", "linux-image-6.1.0-42-amd64", "linux-image-amd64", "openssl"}},
		{name: "trixie", all: "trixie", updates: 6,
			security: []string{"libssl3t64", "linux-image-6.12.48+deb13-amd64", "linux-image-amd64", "openssl", "openssl-provider-legacy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			normal, err := ParseSimulation(openFixture(t, "apt-sim-"+tc.name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(normal.Phased, tc.header) {
				t.Errorf("phasing header = %v, want %v", normal.Phased, tc.header)
			}
			all, err := ParseSimulation(openFixture(t, "apt-sim-"+tc.all+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			sim := MergePhased(all, normal)
			if len(sim.Updates) != tc.updates {
				t.Fatalf("%d updates, want %d", len(sim.Updates), tc.updates)
			}
			var phased, sec, esm []string
			for _, u := range sim.Updates {
				if u.Candidate == "" || u.Arch == "" || len(u.Origins) == 0 {
					t.Errorf("incomplete update %+v", u)
				}
				if u.Phased {
					phased = append(phased, u.Package)
				}
				if u.Security {
					sec = append(sec, u.Package)
				}
				if u.ESM {
					esm = append(esm, u.Package)
				}
			}
			for _, l := range [][]string{phased, sec, esm, sim.Phased} {
				slices.Sort(l)
			}
			for _, c := range []struct {
				what      string
				got, want []string
			}{{"phased", phased, tc.phased}, {"Simulation.Phased", sim.Phased, tc.phased}, {"security", sec, tc.security}, {"esm", esm, tc.esm}} {
				if !slices.Equal(c.got, c.want) {
					t.Errorf("%s = %v, want %v", c.what, c.got, c.want)
				}
			}
		})
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

	pkgs = []Package{
		{Name: "linux-image-6.8.0-91-generic", Version: "6.8.0-91.92"},
		{Name: "linux-image-6.8.0-90-generic-64k", Version: "6.8.0-90.91"},
		{Name: "linux-image-6.1.0-40-amd64", Version: "6.1.153-1"},
		{Name: "linux-image-6.1.0-41-cloud-amd64", Version: "6.1.158-1"},
		{Name: "linux-image-6.1.0-42-amd64-unsigned", Version: "6.1.159-1"},
		{Name: "linux-image-6.12.43+deb13-amd64", Version: "6.12.43-1"},
		{Name: "linux-image-6.12.48+deb13-amd64", Version: "6.12.48-1"},
		{Name: "linux-image-amd64", Version: "6.12.48-1"},
	}
	for _, tc := range []struct{ running, want string }{
		{"6.8.0-88-generic", "6.8.0-91-generic"},
		{"6.8.0-88-generic-64k", "6.8.0-90-generic-64k"},
		{"6.1.0-40-cloud-amd64", "6.1.0-41-cloud-amd64"},
		{"6.12.43+deb13-amd64", "6.12.48+deb13-amd64"},
		{"6.8.0-1012-aws", ""},
	} {
		if got := NewestKernel(pkgs, tc.running); got != tc.want {
			t.Errorf("NewestKernel(%q) = %q, want %q", tc.running, got, tc.want)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want OSRelease
	}{
		{"PRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=jammy\n",
			OSRelease{ID: "ubuntu", VersionID: "22.04", Codename: "jammy", PrettyName: "Ubuntu 22.04.5 LTS"}},
		{"PRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nUBUNTU_CODENAME=noble\n",
			OSRelease{ID: "ubuntu", VersionID: "24.04", Codename: "noble", PrettyName: "Ubuntu 24.04.5 LTS"}},
		{"PRETTY_NAME=\"Ubuntu 26.04 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"26.04\"\nVERSION_CODENAME=resolute\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=resolute\n",
			OSRelease{ID: "ubuntu", VersionID: "26.04", Codename: "resolute", PrettyName: "Ubuntu 26.04 LTS"}},
		{"PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\n",
			OSRelease{ID: "debian", VersionID: "12", Codename: "bookworm", PrettyName: "Debian GNU/Linux 12 (bookworm)"}},
		{"PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION=\"13 (trixie)\"\nVERSION_CODENAME=trixie\nID=debian\n",
			OSRelease{ID: "debian", VersionID: "13", Codename: "trixie", PrettyName: "Debian GNU/Linux 13 (trixie)"}},
	} {
		o, err := ParseOSRelease(strings.NewReader(tc.in))
		if err != nil {
			t.Fatal(err)
		}
		if o != tc.want {
			t.Errorf("got %+v, want %+v", o, tc.want)
		}
	}
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

func date(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}
