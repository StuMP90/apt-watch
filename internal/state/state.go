// Package state stores findings between runs, so each run can tell what
// is new, escalated or resolved.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"aptwatch/internal/risk"
)

const DefaultPath = "/var/lib/aptwatch/state.json"

const schemaVersion = 1

// Entry is the stored history of one finding.
type Entry struct {
	Kind       string        `json:"kind"`
	Title      string        `json:"title"`
	Severity   risk.Severity `json:"severity"`
	FirstSeen  time.Time     `json:"first_seen"`
	LastSeen   time.Time     `json:"last_seen"`
	ResolvedAt time.Time     `json:"resolved_at,omitzero"`
}

func (e *Entry) Resolved() bool { return !e.ResolvedAt.IsZero() }

type State struct {
	Version  int               `json:"version"`
	LastRun  time.Time         `json:"last_run,omitzero"`
	Findings map[string]*Entry `json:"findings"`
}

func New() *State {
	return &State{Version: schemaVersion, Findings: map[string]*Entry{}}
}

// Load reads the state file. A missing file gives an empty state.
func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, err
	}
	s := New()
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Version != schemaVersion {
		return nil, fmt.Errorf("%s: unsupported state version %d", path, s.Version)
	}
	if s.Findings == nil {
		s.Findings = map[string]*Entry{}
	}
	return s, nil
}

// Save writes the state atomically with mode 0600.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Annotate sets FirstSeen on each finding from stored history, or to now
// for findings not currently open in the state.
func (s *State) Annotate(fs []risk.Finding, now time.Time) {
	for i := range fs {
		if e := s.Findings[fs[i].Key]; e != nil && !e.Resolved() {
			fs[i].FirstSeen = e.FirstSeen
		} else {
			fs[i].FirstSeen = now
		}
	}
}

// Resolved is a finding that was open last run and is gone now.
type Resolved struct {
	Key string `json:"key"`
	Entry
}

// Diff is how the current findings compare with the previous run.
type Diff struct {
	New        []string   `json:"new"`
	Escalated  []string   `json:"escalated"`
	Resolved   []Resolved `json:"resolved"`
	Persisting []string   `json:"persisting"`
}

// IsNew reports whether key is in d.New.
func (d *Diff) IsNew(key string) bool { return slices.Contains(d.New, key) }

// IsEscalated reports whether key is in d.Escalated.
func (d *Diff) IsEscalated(key string) bool { return slices.Contains(d.Escalated, key) }

// Update records the current findings, marks missing ones resolved,
// prunes resolved entries older than keepResolved, and returns the diff.
// Call Annotate (and any escalation) first.
func (s *State) Update(fs []risk.Finding, now time.Time, keepResolved time.Duration) Diff {
	var d Diff
	current := make(map[string]bool, len(fs))
	for _, f := range fs {
		current[f.Key] = true
		e := s.Findings[f.Key]
		switch {
		case e == nil || e.Resolved():
			d.New = append(d.New, f.Key)
			e = &Entry{FirstSeen: f.FirstSeen}
			s.Findings[f.Key] = e
		case f.Severity > e.Severity:
			d.Escalated = append(d.Escalated, f.Key)
		default:
			d.Persisting = append(d.Persisting, f.Key)
		}
		e.Kind, e.Title, e.Severity, e.LastSeen = f.Kind, f.Title, f.Severity, now
	}
	for key, e := range s.Findings {
		switch {
		case current[key]:
		case !e.Resolved():
			e.ResolvedAt = now
			d.Resolved = append(d.Resolved, Resolved{Key: key, Entry: *e})
		case keepResolved > 0 && now.Sub(e.ResolvedAt) > keepResolved:
			delete(s.Findings, key)
		}
	}
	slices.SortFunc(d.Resolved, func(a, b Resolved) int {
		if a.Severity != b.Severity {
			return int(b.Severity - a.Severity)
		}
		if a.Key < b.Key {
			return -1
		}
		return 1
	})
	s.LastRun = now
	return d
}
