package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aptwatch/internal/vulndb"
)

// setChecked rewrites the cached tracker's metadata as if last checked at
// the given time, and returns its path.
func setChecked(t *testing.T, cfgPath string, at time.Time) string {
	t.Helper()
	p := filepath.Join(filepath.Dir(cfgPath), "cache", "debian-tracker.json.meta.json")
	if err := os.WriteFile(p, []byte(trackerMeta(at)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDBStatus(t *testing.T) {
	cfg, _ := testHost(t)

	out, c := execute(t, "db", "status", "--config", cfg)
	if c != exitOK || !strings.Contains(out, "for debian 12") || !strings.Contains(out, "debian-tracker.json") || !strings.Contains(out, "ok") {
		t.Errorf("exit %d\n%s", c, out)
	}

	out, c = execute(t, "db", "status", "--config", cfg, "--json")
	fs := decode[[]vulndb.FeedStatus](t, out)
	if c != exitOK || len(fs) != 1 || fs[0].Name != "debian-tracker.json" || !fs[0].Cached || fs[0].Size != int64(len(testTracker)) {
		t.Errorf("exit %d, feeds %+v", c, fs)
	}

	setChecked(t, cfg, time.Now().Add(-4*24*time.Hour))
	out, c = execute(t, "db", "status", "--config", cfg)
	if c != exitWarnings || !strings.Contains(out, "stale: 4d old") {
		t.Errorf("stale: exit %d, want %d\n%s", c, exitWarnings, out)
	}
}

// A feed checked within vulndb.max_age isn't downloaded again.
func TestDBUpdateFresh(t *testing.T) {
	cfg, _ := testHost(t)
	meta := setChecked(t, cfg, time.Now().Add(-time.Hour))
	before, _ := os.ReadFile(meta)

	out, c := execute(t, "db", "update", "--config", cfg)
	if c != exitOK || !strings.Contains(out, "debian-tracker") {
		t.Errorf("exit %d\n%s", c, out)
	}
	if after, _ := os.ReadFile(meta); string(after) != string(before) {
		t.Errorf("feed refreshed: %s, was %s", after, before)
	}
}

func TestConfigCheck(t *testing.T) {
	cfg, _ := testHost(t)
	base, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	old := checkPerms
	checkPerms = func(string) error { return nil }
	t.Cleanup(func() { checkPerms = old })

	tests := []struct {
		name  string
		extra string
		exit  int
		want  string
	}{
		{"valid", "", exitOK, ": OK"},
		{"ignore rules", "ignore:\n  - {cve: CVE-2026-0002, reason: not exposed, until: 2099-12-31}\n  - {package: openssl, reason: old window, until: 2026-01-31}\n",
			exitWarnings, "2 ignore rules, 1 expired"},
		{"notify", "notify:\n  - {name: desk, type: desktop}\n", exitWarnings, "warning: notify:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(cfg, append(base, tt.extra...), 0o600); err != nil {
				t.Fatal(err)
			}
			out, c := execute(t, "config", "check", "--config", cfg)
			if c != tt.exit || !strings.Contains(out, tt.want) {
				t.Errorf("exit %d, want %d and %q\n%s", c, tt.exit, tt.want, out)
			}
		})
	}

	t.Run("invalid", func(t *testing.T) {
		if err := os.WriteFile(cfg, append(base, "colour: blue\n"...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := executeErr("config", "check", "--config", cfg); err == nil || !strings.Contains(err.Error(), "colour") {
			t.Errorf("err = %v, want the unknown key", err)
		}
	})
}

// The real permission check rejects a config file not owned by root.
func TestConfigCheckOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	cfg, _ := testHost(t)
	if _, err := executeErr("config", "check", "--config", cfg); err == nil || !strings.Contains(err.Error(), "must be owned by root") {
		t.Errorf("err = %v", err)
	}
}
