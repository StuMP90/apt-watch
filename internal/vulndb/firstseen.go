package vulndb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// The Debian tracker gives no publish dates, so for its CVEs aptwatch
// uses the day it first saw each one in the data (SPEC §6.2). The CVEs
// already there on the first run are recorded without a date: they were
// published at some unknown time before it, so none of them count as
// recent. Seen entries are kept when a CVE leaves the data, so that one
// that comes back isn't dated again.
type firstSeen struct {
	Release string            `json:"release"`
	Seeded  string            `json:"seeded"` // the day of the first run
	CVEs    map[string]string `json:"cves"`   // CVE → YYYY-MM-DD, "" if seen on the first run
}

// datePublished fills in Published from the first-seen file at path, for
// the advisories that lack it, adding the CVEs not seen before. It
// returns whether path was newly created (seeded).
func datePublished(path, release string, adv map[string][]Advisory, now time.Time) (bool, error) {
	var fsn firstSeen
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &fsn); err != nil || fsn.Release != release {
			fsn = firstSeen{} // corrupt, or another release: start again
		}
	case !errors.Is(err, fs.ErrNotExist):
		return false, err
	}
	seed := fsn.CVEs == nil
	if seed {
		fsn = firstSeen{Release: release, Seeded: now.Format(time.DateOnly), CVEs: map[string]string{}}
	}
	today := now.Format(time.DateOnly)
	changed := seed
	for src, as := range adv {
		for i := range as {
			a := &as[i]
			d, ok := fsn.CVEs[a.CVE]
			if !ok {
				if !seed {
					d = today
				}
				fsn.CVEs[a.CVE] = d
				changed = true
			}
			if a.Published.IsZero() && d != "" {
				a.Published, _ = time.ParseInLocation(time.DateOnly, d, time.UTC)
			}
		}
		adv[src] = as
	}
	if changed {
		b, err := json.Marshal(fsn)
		if err != nil {
			return seed, err
		}
		if err := writeAtomic(path, b); err != nil {
			return seed, fmt.Errorf("first-seen dates: %w", err)
		}
	}
	return seed, nil
}

// datedByKEV dates the advisories still without one by when CISA added
// the CVE to KEV: it was public by then at the latest.
func datedByKEV(adv map[string][]Advisory, kev map[string]time.Time) {
	for _, as := range adv {
		for i := range as {
			if t, ok := kev[as[i].CVE]; ok && as[i].Published.IsZero() && !t.IsZero() {
				as[i].Published = t
			}
		}
	}
}
