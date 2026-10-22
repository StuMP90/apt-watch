// Package vulndb downloads, caches and indexes vulnerability data: the
// distro's advisories (Ubuntu OSV or the Debian security tracker), CISA
// KEV and FIRST EPSS (SPEC §6).
package vulndb

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"aptwatch/internal/debver"
)

// Source names, as used in the config's vulndb.sources.
const (
	SourceAuto   = "auto"
	SourceUbuntu = "osv-ubuntu"
	SourceDebian = "debian-tracker"
)

// OS identifies the release to load advisories for.
type OS struct {
	ID        string // ubuntu, debian
	VersionID string // 24.04, 12
	Codename  string // noble, bookworm
}

// Advisory is one CVE affecting one source package in the host's release.
type Advisory struct {
	CVE      string
	Fixed    string // source version that fixes it; "" when there is no fix yet
	Priority string // critical, high, medium, low, negligible or unknown
	Pro      bool   // the fix is only available with Ubuntu Pro (ESM)
	Desc     string
	// Published is when the CVE was published; zero when the source
	// doesn't say (the Debian tracker).
	Published time.Time
}

// DB is the loaded data for one host.
type DB struct {
	Sources    []string
	Advisories map[string][]Advisory // by source package name
	KEV        map[string]time.Time  // CVE → date added to KEV
	EPSS       map[string]float64    // CVE → probability of exploitation
	Fetched    time.Time             // oldest fetch time of the advisory feeds

	byCVE map[string]Advisory // built by Lookup
}

// Lookup returns what db knows about a CVE whatever package it affects:
// for a third-party package named only in a changelog. Fixed is that of
// one of the distribution's packages.
func (db *DB) Lookup(cve string) (Advisory, bool) {
	if db.byCVE == nil {
		db.byCVE = map[string]Advisory{}
		for _, as := range db.Advisories {
			for _, a := range as {
				b, ok := db.byCVE[a.CVE]
				if !ok {
					db.byCVE[a.CVE] = a
					continue
				}
				if b.Priority == "" || b.Priority == "unknown" {
					b.Priority = a.Priority
				}
				if b.Published.IsZero() || (!a.Published.IsZero() && a.Published.Before(b.Published)) {
					b.Published = a.Published
				}
				if b.Desc == "" {
					b.Desc = a.Desc
				}
				db.byCVE[a.CVE] = b
			}
		}
	}
	a, ok := db.byCVE[cve]
	return a, ok
}

// URL links to the distro's page for a CVE.
func (db *DB) URL(cve string) string {
	if slices.Contains(db.Sources, SourceDebian) {
		return "https://security-tracker.debian.org/tracker/" + cve
	}
	return "https://ubuntu.com/security/" + cve
}

type Options struct {
	Dir        string
	Sources    []string
	KEV, EPSS  bool
	MaxAge     time.Duration // refresh feeds older than this
	StaleAfter time.Duration // warn when the data in use is older than this
	MaxSize    int64         // per download
	Refresh    bool          // false: use only what is cached
	UserAgent  string
}

// Open loads the vulnerability data, refreshing the cache as needed. It
// returns nil when no advisory data is available at all; problems are
// returned as warnings so that update reporting carries on.
func Open(ctx context.Context, o Options, os OS, now time.Time) (*DB, []string) {
	c, err := newCache(o)
	if err != nil {
		return nil, []string{"vulndb: " + err.Error() + "; CVE matching skipped"}
	}
	var warnings []string
	warn := func(format string, a ...any) { warnings = append(warnings, "vulndb: "+fmt.Sprintf(format, a...)) }

	sources, err := resolveSources(o.Sources, os)
	if err != nil {
		return nil, []string{"vulndb: " + err.Error() + "; CVE matching skipped"}
	}
	db := &DB{Sources: sources, Advisories: map[string][]Advisory{}}
	loaded := 0
	for _, s := range sources {
		f := advFeedFor(s, os)
		adv, fetched, ws, err := c.advisories(ctx, f, now)
		warnings = append(warnings, ws...)
		if err != nil {
			warn("%s: %v", s, err)
			continue
		}
		loaded++
		if s == SourceDebian {
			path := c.path(fmt.Sprintf("%s-%s-seen.json", f.Name, f.Release))
			if _, err := datePublished(path, f.Release, adv, now); err != nil {
				warn("%s: %v", s, err)
			}
		}
		for src, as := range adv {
			db.Advisories[src] = mergeAdvisories(append(db.Advisories[src], as...))
		}
		if db.Fetched.IsZero() || fetched.Before(db.Fetched) {
			db.Fetched = fetched
		}
	}
	if loaded == 0 {
		warn("no vulnerability data available; CVE matching skipped")
		return nil, warnings
	}
	if o.KEV {
		var ws []string
		if db.KEV, ws, err = loadFeed(ctx, c, kevFeed, now, parseKEV); err != nil {
			warn("kev: %v", err)
		}
		warnings = append(warnings, ws...)
		datedByKEV(db.Advisories, db.KEV)
	}
	if o.EPSS {
		var ws []string
		if db.EPSS, ws, err = loadFeed(ctx, c, epssFeed, now, parseEPSS); err != nil {
			warn("epss: %v", err)
		}
		warnings = append(warnings, ws...)
	}
	return db, warnings
}

func advFeedFor(source string, os OS) advFeed {
	if source == SourceDebian {
		return debianFeed(os)
	}
	return ubuntuFeed(os)
}

func resolveSources(names []string, os OS) ([]string, error) {
	if len(names) == 0 {
		names = []string{SourceAuto}
	}
	var out []string
	for _, n := range names {
		if n == SourceAuto {
			switch os.ID {
			case "ubuntu":
				n = SourceUbuntu
			case "debian":
				n = SourceDebian
			default:
				return nil, fmt.Errorf("no vulnerability source for OS %q", os.ID)
			}
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if slices.Contains(out, SourceUbuntu) && os.VersionID == "" {
		return nil, fmt.Errorf("%s needs VERSION_ID in os-release", SourceUbuntu)
	}
	if slices.Contains(out, SourceDebian) && os.Codename == "" {
		return nil, fmt.Errorf("%s needs VERSION_CODENAME in os-release", SourceDebian)
	}
	return out, nil
}

// mergeAdvisories keeps one advisory per CVE. When sources (or Ubuntu's
// standard and Pro ecosystems) disagree, the lowest fixed version wins,
// and a fix beats no fix.
func mergeAdvisories(as []Advisory) []Advisory {
	byCVE := map[string]int{}
	var out []Advisory
	for _, a := range as {
		i, ok := byCVE[a.CVE]
		if !ok {
			byCVE[a.CVE] = len(out)
			out = append(out, a)
			continue
		}
		b := &out[i]
		if a.Fixed != "" && (b.Fixed == "" || debver.Compare(a.Fixed, b.Fixed) < 0) {
			b.Fixed, b.Pro = a.Fixed, a.Pro
		}
		if b.Priority == "" || b.Priority == "unknown" {
			b.Priority = a.Priority
		}
		if b.Desc == "" {
			b.Desc = a.Desc
		}
		if b.Published.IsZero() || (!a.Published.IsZero() && a.Published.Before(b.Published)) {
			b.Published = a.Published
		}
	}
	return out
}

// NormPriority maps distro priorities and Debian urgencies to
// critical, high, medium, low, negligible or unknown.
func NormPriority(p string) string {
	p = strings.ToLower(strings.TrimRight(strings.TrimSpace(p), "*"))
	switch p {
	case "critical", "high", "medium", "low", "negligible":
		return p
	case "unimportant":
		return "negligible"
	}
	return "unknown"
}

// shorten trims a description to about n characters, at a word boundary.
func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	cut := strings.LastIndexByte(s[:n], ' ')
	if cut < n/2 {
		cut = n
	}
	return strings.TrimRight(s[:cut], " ,.;:") + "…"
}
