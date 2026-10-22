package vulndb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// A feed is one downloadable file, cached as <Name> in the cache dir.
type feed struct {
	Name string
	URL  string
}

// meta records what is known about a cached feed file (SPEC §6.3).
type meta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Fetched      time.Time `json:"fetched"` // when the content last changed
	Checked      time.Time `json:"checked"` // when it was last confirmed current
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	// The last refresh failure, cleared by the next success.
	Error   string    `json:"error,omitempty"`
	ErrorAt time.Time `json:"error_at,omitzero"`
}

type cache struct {
	dir    string
	o      Options
	client *http.Client
}

func newCache(o Options) (*cache, error) {
	if o.Dir == "" {
		return nil, errors.New("no cache_dir set")
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("cache dir: %w", err)
	}
	// Writable is needed both to refresh and to store the index.
	f, err := os.CreateTemp(o.Dir, ".probe-*")
	if err != nil {
		return nil, fmt.Errorf("cache dir %s is not writable (run as root, or set vulndb.cache_dir)", o.Dir)
	}
	f.Close()
	os.Remove(f.Name())
	if o.MaxSize <= 0 {
		o.MaxSize = 1 << 30
	}
	return &cache{dir: o.Dir, o: o, client: &http.Client{
		Timeout: 15 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-HTTPS URL %s", req.URL)
			}
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}}, nil
}

func (c *cache) path(name string) string { return filepath.Join(c.dir, name) }

// readMetaFile reads the meta file, which can exist without the feed
// file when the first download failed.
func (c *cache) readMetaFile(f feed) (meta, bool) {
	var m meta
	b, err := os.ReadFile(c.path(f.Name + ".meta.json"))
	if err != nil || json.Unmarshal(b, &m) != nil || m.URL != f.URL {
		return meta{}, false
	}
	return m, true
}

func (c *cache) readMeta(f feed) (meta, bool) {
	m, ok := c.readMetaFile(f)
	if !ok {
		return meta{}, false
	}
	if _, err := os.Stat(c.path(f.Name)); err != nil {
		return meta{}, false
	}
	return m, true
}

func (c *cache) writeMeta(f feed, m meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(c.path(f.Name+".meta.json"), b)
}

// get makes sure the feed is cached and as fresh as the options allow,
// then calls use with the path of the file to read. A download goes to a
// temporary file, and replaces the cached copy only when use accepts it,
// so bad data never replaces good. If the refresh fails, the cached copy
// is used, with a warning once it is older than StaleAfter.
func (c *cache) get(ctx context.Context, f feed, now time.Time, use func(path string, m meta) error) (meta, []string, error) {
	var warnings []string
	m, have := c.readMeta(f)
	useCached := func() (meta, []string, error) {
		if c.o.StaleAfter > 0 && now.Sub(m.Checked) > c.o.StaleAfter {
			warnings = append(warnings, fmt.Sprintf("vulndb: %s data is %s old", f.Name, age(now.Sub(m.Checked))))
		}
		return m, warnings, use(c.path(f.Name), m)
	}
	if have && (!c.o.Refresh || now.Sub(m.Checked) < c.o.MaxAge) {
		return useCached()
	}
	if !c.o.Refresh {
		return meta{}, nil, errors.New("not cached, and refreshing is off")
	}
	nm, tmp, err := c.download(ctx, f, m, have, now)
	if err == nil && tmp != "" {
		if err = use(tmp, nm); err != nil {
			err = fmt.Errorf("downloaded data rejected: %w", err)
		} else if err = os.Rename(tmp, c.path(f.Name)); err == nil {
			err = c.writeMeta(f, nm)
		}
		os.Remove(tmp)
		if err == nil {
			return nm, nil, nil
		}
	}
	if err == nil { // not modified
		m = nm
		if err := c.writeMeta(f, m); err != nil {
			warnings = append(warnings, "vulndb: "+err.Error())
		}
		return useCached()
	}
	// Record the failure for "db status".
	if have {
		m.Error, m.ErrorAt = err.Error(), now
		_ = c.writeMeta(f, m)
	} else {
		_ = c.writeMeta(f, meta{URL: f.URL, Error: err.Error(), ErrorAt: now})
		return meta{}, nil, err
	}
	warnings = append(warnings, fmt.Sprintf("vulndb: refreshing %s failed, using the copy from %s: %v", f.Name, m.Checked.Format("2006-01-02 15:04"), err))
	return useCached()
}

// download fetches f, conditionally when there is a cached copy. It
// returns the new meta and a temporary file, or no file when the cached
// copy is still current.
func (c *cache) download(ctx context.Context, f feed, old meta, have bool, now time.Time) (meta, string, error) {
	u, err := url.Parse(f.URL)
	if err != nil || u.Scheme != "https" {
		return meta{}, "", fmt.Errorf("%s: only HTTPS URLs are allowed", f.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return meta{}, "", err
	}
	if c.o.UserAgent != "" {
		req.Header.Set("User-Agent", c.o.UserAgent)
	}
	if have {
		if old.ETag != "" {
			req.Header.Set("If-None-Match", old.ETag)
		}
		if old.LastModified != "" {
			req.Header.Set("If-Modified-Since", old.LastModified)
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return meta{}, "", err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && have:
		old.Checked, old.Error, old.ErrorAt = now, "", time.Time{}
		return old, "", nil
	case resp.StatusCode != http.StatusOK:
		return meta{}, "", fmt.Errorf("GET %s: %s", f.URL, resp.Status)
	}

	tmp, err := os.CreateTemp(c.dir, f.Name+".tmp-*")
	if err != nil {
		return meta{}, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, c.o.MaxSize+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > c.o.MaxSize {
		err = fmt.Errorf("larger than max_size (%d bytes)", c.o.MaxSize)
	}
	if err == nil && resp.ContentLength > 0 && n != resp.ContentLength {
		err = fmt.Errorf("truncated: got %d of %d bytes", n, resp.ContentLength)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return meta{}, "", fmt.Errorf("GET %s: %w", f.URL, err)
	}
	return meta{
		URL:          f.URL,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		Fetched:      now,
		Checked:      now,
		Size:         n,
		SHA256:       hex.EncodeToString(h.Sum(nil)),
	}, tmp.Name(), nil
}

// loadFeed fetches a small feed and parses it.
func loadFeed[T any](ctx context.Context, c *cache, f feed, now time.Time, parse func(io.Reader) (T, error)) (T, []string, error) {
	var v T
	_, warnings, err := c.get(ctx, f, now, func(path string, _ meta) error {
		r, err := os.Open(path)
		if err != nil {
			return err
		}
		defer r.Close()
		v, err = parse(r)
		return err
	})
	return v, warnings, err
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

func age(d time.Duration) string {
	if d >= 48*time.Hour {
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
	return fmt.Sprintf("%d hours", int(d.Hours()))
}
