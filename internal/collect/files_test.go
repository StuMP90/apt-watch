package collect

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The Read* and Lookup* functions open the files the Parse* functions
// read; these tests run them on temporary files.

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadDpkgStatus(t *testing.T) {
	pkgs, err := ReadDpkgStatus("../../testdata/dpkg-status-small")
	if err != nil || len(pkgs) != 5 {
		t.Errorf("got %d packages, %v; want 5", len(pkgs), err)
	}
	if _, err := ReadDpkgStatus(filepath.Join(t.TempDir(), "status")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v, want not exist", err)
	}
	path := filepath.Join(t.TempDir(), "status")
	writeFile(t, path, "Package: x\nDescription: "+strings.Repeat("a", 5<<20)+"\n")
	if _, err := ReadDpkgStatus(path); err == nil || !strings.HasPrefix(err.Error(), path+": ") {
		t.Errorf("over-long line: %v, want an error naming the file", err)
	}
}

func TestReadOSRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	writeFile(t, path, "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n")
	got, err := ReadOSRelease(path)
	want := OSRelease{ID: "debian", VersionID: "13", Codename: "trixie", PrettyName: "Debian GNU/Linux 13 (trixie)"}
	if err != nil || got != want {
		t.Errorf("got %+v, %v; want %+v", got, err, want)
	}
	if _, err := ReadOSRelease(filepath.Join(t.TempDir(), "os-release")); err == nil {
		t.Error("missing file: no error")
	}
}

func TestLookupEOL(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "ubuntu.csv"), "version,codename,series,created,release,eol,eol-server,eol-esm\n"+
		"24.04 LTS,Noble Numbat,noble,2023-10-12,2024-04-25,2029-05-31,2029-05-31,2034-04-25\n")
	e, err := LookupEOL(dir, "ubuntu", "noble")
	if err != nil || e == nil || e.SecurityEnd != date("2029-05-31") {
		t.Errorf("got %+v, %v", e, err)
	}
	if _, err := LookupEOL(dir, "debian", "trixie"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing CSV: %v, want not exist", err)
	}
}

func TestReadReboot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reboot-required")
	if r, err := ReadReboot(path); err != nil || r.Required {
		t.Errorf("no file: got %+v, %v; want not required", r, err)
	}

	writeFile(t, path, "*** System restart required ***\n")
	since := time.Date(2026, 4, 28, 6, 30, 0, 0, time.UTC)
	if err := os.Chtimes(path, since, since); err != nil {
		t.Fatal(err)
	}
	r, err := ReadReboot(path)
	if err != nil || !r.Required || !r.Since.Equal(since) || r.Packages != nil {
		t.Errorf("without .pkgs: got %+v, %v", r, err)
	}

	writeFile(t, path+".pkgs", "linux-base\nlibc6\nlinux-base\n")
	r, err = ReadReboot(path)
	if want := []string{"linux-base", "libc6"}; err != nil || !reflect.DeepEqual(r.Packages, want) {
		t.Errorf("with .pkgs: got %q, %v; want %q", r.Packages, err, want)
	}
}

func TestListsUpdated(t *testing.T) {
	dir := t.TempDir()
	if _, err := ListsUpdated(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("empty directory: %v, want not exist", err)
	}
	if _, err := ListsUpdated(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing directory: no error")
	}

	older := time.Date(2026, 4, 29, 0, 0, 0, 0, time.UTC)
	newer := older.Add(36 * time.Hour)
	for name, mtime := range map[string]time.Time{
		"archive.ubuntu.com_ubuntu_dists_noble_InRelease":                  older,
		"archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages": newer,
		"lock": newer.Add(time.Hour), // apt touches it without updating the lists
	} {
		path := filepath.Join(dir, name)
		writeFile(t, path, "")
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "partial"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := ListsUpdated(dir); err != nil || !got.Equal(newer) {
		t.Errorf("got %v, %v; want %v", got, err, newer)
	}
}
