//go:build genman

package main

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestGenMan(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1792713600") // 2026-10-22
	dir := t.TempDir()
	root := newRoot()
	root.SetArgs([]string{"genman", dir})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	for _, n := range []string{"aptwatch.8.gz", "aptwatch-run.8.gz", "aptwatch-db-update.8.gz", "aptwatch-config-check.8.gz"} {
		if !slices.Contains(names, n) {
			t.Errorf("no %s in %v", n, names)
		}
	}
	for _, n := range names {
		if strings.Contains(n, "genman") || strings.Contains(n, "completion") || strings.Contains(n, "help") {
			t.Errorf("unexpected page %s", n)
		}
	}

	f, err := os.Open(filepath.Join(dir, "aptwatch.8.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	if strings.Contains(page, "completion") {
		t.Error("aptwatch.8 refers to the completion command")
	}
	for _, want := range []string{`.TH "APTWATCH" "8" "Oct 2026"`, "/usr/share/doc/aptwatch/examples", "aptwatch-run(8)"} {
		if !strings.Contains(page, want) {
			t.Errorf("aptwatch.8 lacks %q:\n%s", want, page)
		}
	}
}
