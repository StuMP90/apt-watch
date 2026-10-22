package vulndb

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"time"
)

// An advFeed is a distro advisory feed. Parsing one takes a while (the
// Ubuntu feed unpacks to 11 GB), so the advisories for the host's release
// are kept in a gob index next to it, rebuilt whenever the feed changes.
type advFeed struct {
	feed
	Release string
	parse   func(context.Context, io.Reader) (map[string][]Advisory, error)
}

// Bump when Advisory or the parsing changes, to rebuild old indexes.
const indexFormat = 2

type index struct {
	Format     int
	SHA256     string
	Release    string
	Advisories map[string][]Advisory
}

func (c *cache) advisories(ctx context.Context, f advFeed, now time.Time) (map[string][]Advisory, time.Time, []string, error) {
	var adv map[string][]Advisory
	var warnings []string
	idxPath := c.path(fmt.Sprintf("%s-%s.gob", f.Name, f.Release))
	m, ws, err := c.get(ctx, f.feed, now, func(path string, m meta) error {
		if x, err := readIndex(idxPath); err == nil && x.Format == indexFormat && x.SHA256 == m.SHA256 && x.Release == f.Release {
			adv = x.Advisories
			return nil
		}
		r, err := os.Open(path)
		if err != nil {
			return err
		}
		defer r.Close()
		a, err := f.parse(ctx, r)
		if err != nil {
			return err
		}
		if len(a) == 0 {
			return fmt.Errorf("no advisories for release %s", f.Release)
		}
		adv = a
		if err := writeIndex(idxPath, index{indexFormat, m.SHA256, f.Release, a}); err != nil {
			warnings = append(warnings, "vulndb: writing index: "+err.Error())
		}
		return nil
	})
	return adv, m.Checked, append(ws, warnings...), err
}

func readIndex(path string) (index, error) {
	var x index
	f, err := os.Open(path)
	if err != nil {
		return x, err
	}
	defer f.Close()
	err = gob.NewDecoder(f).Decode(&x)
	return x, err
}

func writeIndex(path string, x index) error {
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(x); err != nil {
		return err
	}
	return writeAtomic(path, b.Bytes())
}
