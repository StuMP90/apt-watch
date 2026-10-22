package risk

import (
	"encoding/json"
	"testing"
	"time"
)

func TestApplyIgnores(t *testing.T) {
	now := time.Date(2026, 10, 22, 6, 0, 0, 0, time.UTC)
	day := func(s string) Date { var d Date; _ = d.UnmarshalText([]byte(s)); return d }
	fs := []Finding{
		{Key: "a", Kind: KindCVEFixAvailable, Source: "foo", CVEs: []CVERef{{ID: "CVE-2026-0001"}}},
		{Key: "b", Kind: KindSecurityUpdate, Source: "foo", CVEs: []CVERef{{ID: "CVE-2026-0001"}, {ID: "CVE-2026-0002"}}},
		{Key: "c", Kind: KindUpdate, Source: "linux-meta", Packages: []PkgRef{{Name: "linux-headers-generic"}, {Name: "linux-image-generic"}}},
		{Key: "d", Kind: KindUpdate, Source: "bar", Packages: []PkgRef{{Name: "bar"}}},
		{Key: "e", Kind: KindCVEUnfixed, Source: "baz", CVEs: []CVERef{{ID: "CVE-2026-0003"}}},
		{Key: "f", Kind: KindSecurityUpdate, Source: "qux", CVEs: []CVERef{{ID: "CVE-2026-0004"}, {ID: "CVE-2026-0005"}}},
	}
	rules := []IgnoreRule{
		{CVE: "CVE-2026-0001", Reason: "not built", Until: day("2026-12-31")},
		{Package: "linux-image-*", Kinds: []string{KindUpdate}, Reason: "monthly window"},
		{Package: "linux-image-*", Kinds: []string{KindCVEUnfixed}, Reason: "wrong kind"},
		{CVE: "CVE-2026-0003", Reason: "old", Until: day("2026-10-21")},
		{CVE: "CVE-2026-0004", Reason: "r4"},
		{CVE: "CVE-2026-0005", Reason: "r5", Until: day("2026-11-30")},
	}
	expired := ApplyIgnores(fs, rules, now)
	if len(expired) != 1 || expired[0].CVE != "CVE-2026-0003" {
		t.Errorf("expired %+v", expired)
	}
	want := map[string]bool{"a": true, "b": false, "c": true, "d": false, "e": false, "f": true}
	for _, f := range fs {
		if (f.Suppressed != nil) != want[f.Key] {
			t.Errorf("%s suppressed = %+v", f.Key, f.Suppressed)
		}
	}
	if s := fs[0].Suppressed; s.Reason != "not built" || s.Until.Format(time.DateOnly) != "2026-12-31" {
		t.Errorf("a: %+v", s)
	}
	if s := fs[5].Suppressed; s.Reason != "r4; r5" || s.Until.Format(time.DateOnly) != "2026-11-30" {
		t.Errorf("f: %+v", s)
	}
	if len(Active(fs)) != 3 || len(Suppressed(fs)) != 3 {
		t.Error("Active/Suppressed")
	}
	// The last day still applies.
	if (IgnoreRule{Until: day("2026-10-22")}).Expired(now) {
		t.Error("expired on its last day")
	}
}

func TestDateJSON(t *testing.T) {
	var d Date
	if err := d.UnmarshalText([]byte("2026-10-01")); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(IgnoreRule{CVE: "CVE-2026-1", Reason: "r", Until: d})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"cve":"CVE-2026-1","reason":"r","until":"2026-10-01"}`; string(b) != want {
		t.Errorf("got %s, want %s", b, want)
	}
	var r IgnoreRule
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if !r.Until.Equal(d.Time) {
		t.Errorf("round trip: got %v, want %v", r.Until, d)
	}
	b, _ = json.Marshal(IgnoreRule{CVE: "CVE-2026-1", Reason: "r"})
	if want := `{"cve":"CVE-2026-1","reason":"r"}`; string(b) != want {
		t.Errorf("zero date: got %s, want %s", b, want)
	}
}
