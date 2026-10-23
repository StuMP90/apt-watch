//go:build integration

// Package integration runs the aptwatch binary in containers of each
// supported release, with an old package installed, and checks that the
// report shows its security update and a CVE fixed by it. It needs docker
// and internet access:
//
//	go test -tags integration ./integration
//
// Set APTWATCH_IMAGES to a comma-separated list to test only some images.
package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"aptwatch/internal/collect"
	"aptwatch/internal/report"
	"aptwatch/internal/risk"
)

var images = []string{"debian:12", "debian:13", "ubuntu:22.04", "ubuntu:24.04", "ubuntu:26.04"}

func TestReleases(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found")
	}
	if s := os.Getenv("APTWATCH_IMAGES"); s != "" {
		images = strings.Split(s, ",")
	}
	bin := filepath.Join(t.TempDir(), "aptwatch")
	build := exec.Command("go", "build", "-o", bin, "../cmd/aptwatch")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	script, err := filepath.Abs("run.sh")
	if err != nil {
		t.Fatal(err)
	}

	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			cmd := exec.Command("docker", "run", "--rm",
				"-v", bin+":/usr/local/bin/aptwatch:ro",
				"-v", script+":/run.sh:ro",
				"-v", out+":/out",
				image, "sh", "/run.sh")
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("container: %v\n%s", err, b)
			}
			check(t, image, out)
		})
	}
}

func check(t *testing.T, image, out string) {
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	picked := strings.Fields(read("picked"))
	pkg, old, fixed := picked[0], picked[1], picked[2]
	t.Logf("%s %s installed, %s in the security pocket", pkg, old, fixed)

	stderr := read("stderr")
	code, _ := strconv.Atoi(read("exit"))
	if code == 3 {
		t.Fatalf("exit 3\n%s", stderr)
	}
	var r report.Report
	if err := json.Unmarshal([]byte(read("report.json")), &r); err != nil {
		t.Fatalf("report.json: %v\n%s", err, stderr)
	}

	if want := strings.Split(image, ":")[0]; r.System.OS.ID != want {
		t.Errorf("OS ID = %q, want %q", r.System.OS.ID, want)
	}
	if r.VulnDB == nil {
		t.Errorf("no vulnerability data; warnings: %q", r.Warnings)
	}
	if r.Diff == nil || !r.Diff.FirstRun {
		t.Error("first run not marked")
	}

	i := slices.IndexFunc(r.Updates, func(u collect.Update) bool { return u.Package == pkg })
	switch {
	case i < 0:
		t.Errorf("%s not in pending updates", pkg)
	case !r.Updates[i].Security || r.Updates[i].Installed != old:
		t.Errorf("update = %+v, want security from %s", r.Updates[i], old)
	}

	cve := slices.ContainsFunc(r.Findings, func(f risk.Finding) bool {
		return f.Kind == risk.KindCVEFixAvailable && slices.ContainsFunc(f.Packages, func(p risk.PkgRef) bool {
			return p.Name == pkg && p.Installed == old
		})
	})
	if !cve {
		var keys []string
		for _, f := range r.Findings {
			keys = append(keys, f.Key)
		}
		t.Errorf("no %s finding for %s; findings: %q", risk.KindCVEFixAvailable, pkg, keys)
	}
	if t.Failed() {
		t.Logf("exit %d, stderr:\n%s", code, stderr)
	}
}
