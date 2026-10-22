package state

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"aptwatch/internal/risk"
)

func TestLifecycle(t *testing.T) {
	day := 24 * time.Hour
	t0 := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	s := New()

	run := func(now time.Time, fs ...risk.Finding) Diff {
		s.Annotate(fs, now)
		return s.Update(fs, now, 30*day)
	}
	a := risk.Finding{Key: "a", Severity: risk.Medium}
	b := risk.Finding{Key: "b", Severity: risk.Low}

	d := run(t0, a, b)
	if !reflect.DeepEqual(d.New, []string{"a", "b"}) || len(d.Resolved) != 0 {
		t.Fatalf("run 1: %+v", d)
	}

	a.Severity = risk.High
	d = run(t0.Add(day), a)
	if !reflect.DeepEqual(d.Escalated, []string{"a"}) || len(d.Resolved) != 1 || d.Resolved[0].Key != "b" {
		t.Fatalf("run 2: %+v", d)
	}
	if got := s.Findings["a"].FirstSeen; !got.Equal(t0) {
		t.Errorf("FirstSeen = %v, want %v", got, t0)
	}

	// b comes back: it is new again, with a fresh FirstSeen.
	fs := []risk.Finding{a, b}
	s.Annotate(fs, t0.Add(2*day))
	d = s.Update(fs, t0.Add(2*day), 30*day)
	if !reflect.DeepEqual(d.New, []string{"b"}) || !reflect.DeepEqual(d.Persisting, []string{"a"}) {
		t.Fatalf("run 3: %+v", d)
	}
	if !fs[1].FirstSeen.Equal(t0.Add(2 * day)) {
		t.Errorf("reappeared FirstSeen = %v", fs[1].FirstSeen)
	}

	// Both resolve, then are pruned after keepResolved.
	run(t0.Add(3 * day))
	if len(s.Findings) != 2 {
		t.Fatalf("resolved entries kept: %d", len(s.Findings))
	}
	run(t0.Add(40 * day))
	if len(s.Findings) != 0 {
		t.Fatalf("after prune: %d entries", len(s.Findings))
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json")
	s := New()
	s.Annotate(nil, time.Now())
	s.Update([]risk.Finding{{Key: "k", Kind: "x", Severity: risk.High, Title: "T"}}, time.Now(), 0)
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Findings["k"].Severity != risk.High {
		t.Errorf("round trip lost data: %+v", got)
	}
	if s, err := Load(filepath.Join(t.TempDir(), "missing.json")); err != nil || len(s.Findings) != 0 {
		t.Errorf("missing file: %v, %v", s, err)
	}
}
