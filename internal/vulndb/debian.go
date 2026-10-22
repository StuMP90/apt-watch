package vulndb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const debianTrackerURL = "https://security-tracker.debian.org/tracker/data/json"

func debianFeed(os OS) advFeed {
	release := os.Codename
	return advFeed{
		feed:    feed{Name: "debian-tracker.json", URL: debianTrackerURL},
		Release: release,
		parse: func(_ context.Context, r io.Reader) (map[string][]Advisory, error) {
			return parseDebian(r, release)
		},
	}
}

type debianCVE struct {
	Description string `json:"description"`
	Releases    map[string]struct {
		Status       string `json:"status"`
		FixedVersion string `json:"fixed_version"`
		Urgency      string `json:"urgency"`
	} `json:"releases"`
}

// parseDebian reads the tracker's JSON ({source: {CVE: {...}}}), one
// source package at a time, keeping the entries for one release.
func parseDebian(r io.Reader, release string) (map[string][]Advisory, error) {
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	out := map[string][]Advisory{}
	pkgs := 0
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("debian tracker: %w", err)
		}
		src, _ := t.(string)
		var cves map[string]debianCVE
		if err := dec.Decode(&cves); err != nil {
			return nil, fmt.Errorf("debian tracker: %s: %w", src, err)
		}
		pkgs++
		for id, c := range cves {
			rel, ok := c.Releases[release]
			if !ok || !strings.HasPrefix(id, "CVE-") {
				continue
			}
			a := Advisory{CVE: id, Priority: NormPriority(rel.Urgency), Desc: shorten(c.Description, 200)}
			switch rel.Status {
			case "resolved":
				if rel.FixedVersion == "" || rel.FixedVersion == "0" {
					continue // not affected
				}
				a.Fixed = rel.FixedVersion
			case "open", "undetermined":
			default:
				continue
			}
			out[src] = append(out[src], a)
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, err
	}
	if pkgs == 0 {
		return nil, errors.New("debian tracker: no packages")
	}
	return out, nil
}

func expectDelim(dec *json.Decoder, d json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return fmt.Errorf("debian tracker: %w", err)
	}
	if t != d {
		return fmt.Errorf("debian tracker: expected %q, got %v", d, t)
	}
	return nil
}
