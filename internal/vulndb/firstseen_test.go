package vulndb

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDatePublished(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	day1 := time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC)
	day2 := day1.AddDate(0, 0, 1)
	adv := func(cves ...string) map[string][]Advisory {
		m := map[string][]Advisory{}
		for _, c := range cves {
			m["foo"] = append(m["foo"], Advisory{CVE: c})
		}
		return m
	}

	// The first run records what is there without dates.
	a := adv("CVE-1", "CVE-2")
	if seed, err := datePublished(path, "trixie", a, day1); err != nil || !seed {
		t.Fatalf("first run: seed %v, err %v", seed, err)
	}
	for _, x := range a["foo"] {
		if !x.Published.IsZero() {
			t.Errorf("seeded %s dated %v", x.CVE, x.Published)
		}
	}

	// Later runs date the new ones by the day they appear, and keep it.
	for _, now := range []time.Time{day2, day2.AddDate(0, 0, 5)} {
		a = adv("CVE-1", "CVE-3")
		if seed, err := datePublished(path, "trixie", a, now); err != nil || seed {
			t.Fatalf("%v: seed %v, err %v", now, seed, err)
		}
		if p := a["foo"][0].Published; !p.IsZero() {
			t.Errorf("CVE-1 dated %v", p)
		}
		if p := a["foo"][1].Published; !p.Equal(time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("CVE-3 dated %v", p)
		}
	}

	// CVE-2 left the data but is remembered: coming back, it isn't new.
	a = adv("CVE-2")
	datePublished(path, "trixie", a, day2.AddDate(0, 0, 9))
	if p := a["foo"][0].Published; !p.IsZero() {
		t.Errorf("returning CVE-2 dated %v", p)
	}

	// A source date is kept.
	src := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	a = map[string][]Advisory{"foo": {{CVE: "CVE-4", Published: src}}}
	datePublished(path, "trixie", a, day2)
	if p := a["foo"][0].Published; !p.Equal(src) {
		t.Errorf("source date replaced by %v", p)
	}

	// A file for another release, or a corrupt one, starts again.
	if seed, _ := datePublished(path, "bookworm", adv("CVE-9"), day2); !seed {
		t.Error("another release didn't reseed")
	}
	os.WriteFile(path, []byte("{"), 0o644)
	if seed, _ := datePublished(path, "bookworm", adv("CVE-9"), day2); !seed {
		t.Error("corrupt file didn't reseed")
	}

	a = map[string][]Advisory{"foo": {{CVE: "CVE-K"}, {CVE: "CVE-L"}}}
	added := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	datedByKEV(a, map[string]time.Time{"CVE-K": added, "CVE-L": {}})
	if !a["foo"][0].Published.Equal(added) || !a["foo"][1].Published.IsZero() {
		t.Errorf("datedByKEV: %+v", a["foo"])
	}
}
