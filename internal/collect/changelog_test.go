package collect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const testChangelog = `foo (1.3-1+0~20260101.5+ubuntu24.04~1.gbp1) unstable; urgency=medium

  ** SNAPSHOT build @1 **

  * New upstream version 1.3

 -- Builder <b@example.org>  Thu, 01 Jan 2026 10:00:00 +0000

foo (1.3-1) unstable; urgency=medium

  * New upstream version 1.3
    + CVE-2026-0003: overflow
    + CVE-2026-0004 (also see CVE-2026-0003)

 -- Builder <b@example.org>  Thu, 01 Jan 2026 09:00:00 +0000

foo (1.2-1) unstable; urgency=high

  * Fix CVE-2026-0002.
  * Not a CVE: CVE-26-1.

 -- Builder <b@example.org>  Mon, 01 Dec 2025 09:00:00 +0000

foo (1.1-1) unstable; urgency=low

  * Fix CVE-2025-12345 and CVE-2026-0002 properly.

 -- Builder <b@example.org>  Sat, 01 Nov 2025 09:00:00 +0000
`

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(s))
	zw.Close()
	return b.Bytes()
}

func TestParseChangelog(t *testing.T) {
	got, err := ParseChangelog(strings.NewReader(testChangelog))
	if err != nil {
		t.Fatal(err)
	}
	want := []ChangelogEntry{
		{Version: "1.3-1+0~20260101.5+ubuntu24.04~1.gbp1"},
		{Version: "1.3-1", CVEs: []string{"CVE-2026-0003", "CVE-2026-0004"}},
		{Version: "1.2-1", CVEs: []string{"CVE-2026-0002"}},
		{Version: "1.1-1", CVEs: []string{"CVE-2025-12345", "CVE-2026-0002"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if _, err := ParseChangelog(strings.NewReader("Version 1.3: fixed CVE-2026-0003\n")); err == nil {
		t.Error("no error for an upstream changelog")
	}
}

func TestSplitChangelog(t *testing.T) {
	e, _ := ParseChangelog(strings.NewReader(testChangelog))
	for _, tc := range []struct {
		installed, candidate string
		fixed, pending       []string
	}{
		{"1.3-1+ubuntu24.04.1+deb.sury.org+1", "", []string{"CVE-2025-12345", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}, nil},
		{"1.1-1+ubuntu24.04.1", "1.3-1+ubuntu24.04.1", []string{"CVE-2025-12345", "CVE-2026-0002"}, []string{"CVE-2026-0003", "CVE-2026-0004"}},
		{"1.1-1", "1.2-1", []string{"CVE-2025-12345", "CVE-2026-0002"}, nil},
		{"1.0-1", "1.2-1", nil, []string{"CVE-2025-12345", "CVE-2026-0002"}},
	} {
		fixed, pending := SplitChangelog(e, tc.installed, tc.candidate)
		if !slices.Equal(fixed, tc.fixed) || !slices.Equal(pending, tc.pending) {
			t.Errorf("%s → %s: got %v / %v, want %v / %v", tc.installed, tc.candidate, fixed, pending, tc.fixed, tc.pending)
		}
	}
}

func TestTarChangelog(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	add := func(h *tar.Header, body []byte) {
		h.Size = int64(len(body))
		tw.WriteHeader(h)
		tw.Write(body)
	}
	add(&tar.Header{Name: "./usr/share/doc/foo-cli", Typeflag: tar.TypeSymlink, Linkname: "foo-common"}, nil)
	add(&tar.Header{Name: "./usr/share/doc/foo-common/changelog.gz", Typeflag: tar.TypeReg}, gz(t, "upstream notes\n"))
	add(&tar.Header{Name: "./usr/share/doc/foo-common/changelog.Debian.gz", Typeflag: tar.TypeReg}, gz(t, testChangelog))
	tw.Close()
	e, err := tarChangelog(&b)
	if err != nil || len(e) != 4 {
		t.Errorf("got %v, %v", e, err)
	}

	b.Reset()
	tw = tar.NewWriter(&b)
	add(&tar.Header{Name: "./usr/share/doc/foo-cli", Typeflag: tar.TypeSymlink, Linkname: "foo-common"}, nil)
	tw.Close()
	if _, err := tarChangelog(&b); err == nil {
		t.Error("no error for a .deb without a changelog")
	}
}

func TestAddChangelogsInstalled(t *testing.T) {
	doc := t.TempDir()
	old := DocDir
	DocDir = doc
	t.Cleanup(func() { DocDir = old })
	os.MkdirAll(filepath.Join(doc, "foo-common"), 0o755)
	os.WriteFile(filepath.Join(doc, "foo-common", "changelog.Debian.gz"), gz(t, testChangelog), 0o644)
	os.Symlink("foo-common", filepath.Join(doc, "foo-cli"))

	inv := &Inventory{
		Packages: []Package{
			{Name: "foo-cli", Version: "1.3-1+ppa1", Source: "foo", SourceVersion: "1.3-1+ppa1", ThirdParty: true},
			{Name: "foo-common", Version: "1.3-1+ppa1", Source: "foo", SourceVersion: "1.3-1+ppa1", ThirdParty: true},
			{Name: "bar", Version: "1", Source: "bar", SourceVersion: "1"},
		},
		Simulation: &Simulation{},
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "changelogs"), 0o755)
	os.WriteFile(filepath.Join(dir, "changelogs", "old.json"), []byte("[]"), 0o644)
	if w := AddChangelogs(context.Background(), inv, dir); len(w) != 0 {
		t.Errorf("warnings: %v", w)
	}
	cl := inv.Changelogs["foo"]
	if cl == nil || len(cl.Fixed) != 4 || cl.Pending != nil || cl.From != filepath.Join(doc, "foo-common", "changelog.Debian.gz") {
		t.Errorf("foo: %+v", cl)
	}
	if len(inv.Changelogs) != 1 {
		t.Errorf("changelogs: %v", inv.Changelogs)
	}
	if _, err := os.Stat(filepath.Join(dir, "changelogs", "old.json")); err == nil {
		t.Error("unused cache entry kept")
	}
}

func TestFetchChangelogCached(t *testing.T) {
	cache := t.TempDir()
	os.WriteFile(filepath.Join(cache, "foo-common=1.4-1.json"), []byte(`[{"version":"1.4-1","cves":["CVE-2026-0009"]}]`), 0o644)
	used := map[string]bool{}
	e, from, err := fetchChangelog(context.Background(), []string{"foo-common=1.4-1"}, cache, used)
	if err != nil || from != "foo-common=1.4-1" || len(e) != 1 || !used["foo-common=1.4-1.json"] {
		t.Errorf("got %v %q %v %v", e, from, err, used)
	}
}

func TestFetchChangelogCachedNone(t *testing.T) {
	cache := t.TempDir()
	os.WriteFile(filepath.Join(cache, "foo-bin=2-1.json"), []byte("[]"), 0o644)
	_, _, err := fetchChangelog(context.Background(), []string{"foo-bin=2-1"}, cache, map[string]bool{})
	if !errors.Is(err, errNoChangelog) {
		t.Errorf("got %v", err)
	}
}
