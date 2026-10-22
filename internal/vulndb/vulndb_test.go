package vulndb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func osvTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	return b.Bytes()
}

func TestParseOSVTar(t *testing.T) {
	tb := osvTar(t, map[string]string{
		"osv/cve/2024/UBUNTU-CVE-2024-0001.json": `{"id":"UBUNTU-CVE-2024-0001","upstream":["CVE-2024-0001"],"published":"2024-01-02T14:00:00Z",
			"details":"A  bug\nin foo.","severity":[{"type":"Ubuntu","score":"high"}],
			"affected":[
			 {"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"foo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0-2"}]}]},
			 {"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"foo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.9-1"}]}]},
			 {"package":{"ecosystem":"Ubuntu:Pro:FIPS-updates:24.04:LTS","name":"foo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0-1fips"}]}]}]}`,
		"osv/cve/2024/UBUNTU-CVE-2024-0002.json": `{"id":"UBUNTU-CVE-2024-0002","severity":[{"type":"Ubuntu","score":"medium"}],
			"affected":[
			 {"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"bar"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
			 {"package":{"ecosystem":"Ubuntu:Pro:24.04:LTS","name":"bar"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0+esm1"}]}],
			  "ecosystem_specific":{"availability":"Available with Ubuntu Pro: https://ubuntu.com/pro"}}]}`,
		"osv/cve/2024/UBUNTU-CVE-2024-0003.json": `{"id":"UBUNTU-CVE-2024-0003","withdrawn":"2024-02-01T00:00:00Z",
			"affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"foo"},"ranges":[{"events":[{"introduced":"0"}]}]}]}`,
		"osv/cve/2024/UBUNTU-CVE-2024-0004.json": `{"id":"UBUNTU-CVE-2024-0004",
			"affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"foo"},"ranges":[{"events":[{"introduced":"0"}]}]}]}`,
		"osv/usn/USN-1-1.json": `{"id":"USN-1-1","affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"foo"}}]}`,
	})
	got, err := parseOSVTar(bytes.NewReader(tb), "24.04")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]Advisory{
		"foo": {{CVE: "CVE-2024-0001", Fixed: "1.0-2", Priority: "high", Desc: "A bug in foo.", Published: time.Date(2024, 1, 2, 14, 0, 0, 0, time.UTC)}},
		"bar": {{CVE: "CVE-2024-0002", Fixed: "2.0+esm1", Priority: "medium", Pro: true}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if _, err := parseOSVTar(bytes.NewReader(osvTar(t, map[string]string{"x/readme.txt": "hi"})), "24.04"); err == nil {
		t.Error("no error for a tarball without CVE records")
	}
}

func TestParseDebian(t *testing.T) {
	in := `{
	 "foo": {
	  "CVE-2024-1": {"description":"d1","releases":{"bookworm":{"status":"resolved","fixed_version":"1.2-1","urgency":"high"},
	                                              "trixie":{"status":"resolved","fixed_version":"0","urgency":"not yet assigned"}}},
	  "CVE-2024-2": {"releases":{"bookworm":{"status":"open","urgency":"unimportant"}}},
	  "CVE-2024-3": {"releases":{"bookworm":{"status":"resolved","fixed_version":"0","urgency":"low"}}},
	  "TEMP-0000-1": {"releases":{"bookworm":{"status":"open","urgency":"low"}}}
	 },
	 "bar": {"CVE-2024-4": {"releases":{"trixie":{"status":"open"}}}}
	}`
	got, err := parseDebian(strings.NewReader(in), "bookworm")
	if err != nil {
		t.Fatal(err)
	}
	foo := got["foo"]
	if len(got) != 1 || len(foo) != 2 {
		t.Fatalf("got %+v", got)
	}
	m := map[string]Advisory{}
	for _, a := range foo {
		m[a.CVE] = a
	}
	if a := m["CVE-2024-1"]; a.Fixed != "1.2-1" || a.Priority != "high" || a.Desc != "d1" {
		t.Errorf("CVE-2024-1: %+v", a)
	}
	if a := m["CVE-2024-2"]; a.Fixed != "" || a.Priority != "negligible" {
		t.Errorf("CVE-2024-2: %+v", a)
	}
	if _, err := parseDebian(strings.NewReader(`[]`), "bookworm"); err == nil {
		t.Error("no error for wrong shape")
	}
}

func TestParseKEVAndEPSS(t *testing.T) {
	kev, err := parseKEV(strings.NewReader(`{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10"}]}`))
	if err != nil || !kev["CVE-2021-44228"].Equal(time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("kev: %v %v", kev, err)
	}
	if _, err := parseKEV(strings.NewReader(`{"vulnerabilities":[]}`)); err == nil {
		t.Error("kev: no error for empty catalogue")
	}

	gz := func(s string) *bytes.Reader {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write([]byte(s))
		w.Close()
		return bytes.NewReader(b.Bytes())
	}
	epss, err := parseEPSS(gz("#model_version:v2025.03.14,score_date:2026-10-21T00:00:00Z\ncve,epss,percentile\nCVE-1,0.94,0.99\nCVE-2,0.00043,0.1\n"))
	if err != nil || epss["CVE-1"] != 0.94 || epss["CVE-2"] != 0.00043 {
		t.Errorf("epss: %v %v", epss, err)
	}
	if _, err := parseEPSS(gz("a,b\n1,2\n")); err == nil {
		t.Error("epss: no error for bad header")
	}
}

func TestMergeAdvisories(t *testing.T) {
	got := mergeAdvisories([]Advisory{
		{CVE: "CVE-1", Priority: "unknown"},
		{CVE: "CVE-1", Fixed: "1.0-3+esm1", Priority: "high", Pro: true},
		{CVE: "CVE-1", Fixed: "1.0-2"},
		{CVE: "CVE-2", Fixed: "2.0-1"},
		{CVE: "CVE-2"},
	})
	want := []Advisory{
		{CVE: "CVE-1", Fixed: "1.0-2", Priority: "high"},
		{CVE: "CVE-2", Fixed: "2.0-1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestLookup(t *testing.T) {
	d := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	db := &DB{Advisories: map[string][]Advisory{
		"php8.3": {{CVE: "CVE-1", Fixed: "8.3.6-0ubuntu0.24.04.2", Priority: "unknown"}},
		"php8.4": {{CVE: "CVE-1", Priority: "critical", Published: d}},
	}}
	if a, ok := db.Lookup("CVE-1"); !ok || a.Priority != "critical" || !a.Published.Equal(d) {
		t.Errorf("CVE-1: %+v %v", a, ok)
	}
	if _, ok := db.Lookup("CVE-2"); ok {
		t.Error("CVE-2 found")
	}
}

func TestNormPriority(t *testing.T) {
	for in, want := range map[string]string{"High": "high", "medium**": "medium", "unimportant": "negligible", "not yet assigned": "unknown", "": "unknown"} {
		if got := NormPriority(in); got != want {
			t.Errorf("NormPriority(%q) = %q, want %q", in, got, want)
		}
	}
}

// testServer serves body (with an ETag) and counts requests; status, when
// set, overrides the response.
type testServer struct {
	body     atomic.Value // string
	status   atomic.Int32
	requests atomic.Int32
}

func newTestCache(t *testing.T, o Options) (*cache, *testServer, feed) {
	t.Helper()
	ts := &testServer{}
	ts.body.Store("v1")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.requests.Add(1)
		if s := ts.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		body := ts.body.Load().(string)
		etag := `"` + body + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	o.Dir = t.TempDir()
	c, err := newCache(o)
	if err != nil {
		t.Fatal(err)
	}
	c.client.Transport = srv.Client().Transport
	return c, ts, feed{Name: "test.dat", URL: srv.URL + "/test.dat"}
}

func read(t *testing.T, c *cache, f feed, now time.Time) (string, []string, error) {
	t.Helper()
	var got string
	_, ws, err := c.get(context.Background(), f, now, func(path string, _ meta) error {
		b, err := os.ReadFile(path)
		got = string(b)
		if got == "bad" {
			return errors.New("bad data")
		}
		return err
	})
	return got, ws, err
}

func TestCacheGet(t *testing.T) {
	c, ts, f := newTestCache(t, Options{Refresh: true, MaxAge: time.Hour, StaleAfter: 72 * time.Hour})
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	if got, ws, err := read(t, c, f, now); got != "v1" || err != nil || len(ws) != 0 {
		t.Fatalf("first get: %q %v %v", got, ws, err)
	}
	// Fresh: no request.
	read(t, c, f, now.Add(time.Minute))
	if n := ts.requests.Load(); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
	// Due a check, unchanged: 304.
	if got, _, err := read(t, c, f, now.Add(2*time.Hour)); got != "v1" || err != nil {
		t.Errorf("after 304: %q %v", got, err)
	}
	if n := ts.requests.Load(); n != 2 {
		t.Errorf("%d requests, want 2", n)
	}
	// Changed, but the new data is rejected: the old copy stays.
	ts.body.Store("bad")
	got, ws, err := read(t, c, f, now.Add(4*time.Hour))
	if err != nil || len(ws) != 1 || !strings.Contains(ws[0], "rejected") {
		t.Errorf("rejected download: %q %v %v", got, ws, err)
	}
	if b, _ := os.ReadFile(c.path(f.Name)); string(b) != "v1" {
		t.Errorf("cached copy replaced with %q", b)
	}
	// Server failing for days: stale warning.
	ts.status.Store(http.StatusInternalServerError)
	_, ws, err = read(t, c, f, now.Add(100*time.Hour))
	if err != nil || len(ws) != 2 || !strings.Contains(ws[0], "failed") || !strings.Contains(ws[1], "days old") {
		t.Errorf("stale: %v %v", ws, err)
	}
	if m, _ := c.readMeta(f); !strings.Contains(m.Error, "500") || !m.ErrorAt.Equal(now.Add(100*time.Hour)) {
		t.Errorf("error not recorded: %+v", m)
	}
	// New data accepted.
	ts.status.Store(0)
	ts.body.Store("v2")
	if got, ws, err := read(t, c, f, now.Add(101*time.Hour)); got != "v2" || err != nil || len(ws) != 0 {
		t.Errorf("v2: %q %v %v", got, ws, err)
	}
	if m, _ := c.readMeta(f); m.Error != "" || !m.ErrorAt.IsZero() {
		t.Errorf("error not cleared: %+v", m)
	}
	// Refresh off: cached copy, no request.
	c.o.Refresh = false
	n := ts.requests.Load()
	if got, _, _ := read(t, c, f, now.Add(500*time.Hour)); got != "v2" || ts.requests.Load() != n {
		t.Errorf("refresh off: %q", got)
	}
}

func TestCacheLimits(t *testing.T) {
	c, ts, f := newTestCache(t, Options{Refresh: true, MaxSize: 4})
	ts.body.Store("too large")
	if _, _, err := read(t, c, f, time.Now()); err == nil || !strings.Contains(err.Error(), "max_size") {
		t.Errorf("size limit: %v", err)
	}
	if m, ok := c.readMetaFile(f); !ok || !strings.Contains(m.Error, "max_size") {
		t.Errorf("first failure not recorded: %+v", m)
	}
	c.o.Refresh = false
	if _, _, err := read(t, c, f, time.Now()); err == nil {
		t.Error("no error for missing cache with refresh off")
	}
	if _, _, err := c.get(context.Background(), feed{Name: "x", URL: "http://example.com/x"}, time.Now(), nil); err == nil {
		t.Error("no error")
	}
	c.o.Refresh = true
	if _, _, err := c.get(context.Background(), feed{Name: "x", URL: "http://example.com/x"}, time.Now(), nil); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("plain HTTP: %v", err)
	}
}

func TestStatus(t *testing.T) {
	c, _, _ := newTestCache(t, Options{Refresh: true, MaxAge: time.Hour})
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	sys := OS{ID: "debian", VersionID: "13", Codename: "trixie"}
	// A cached tracker, and a KEV download that failed.
	deb := debianFeed(sys).feed
	os.WriteFile(c.path(deb.Name), []byte("{}"), 0o600)
	c.writeMeta(deb, meta{URL: deb.URL, Fetched: now, Checked: now, Size: 2})
	c.writeMeta(kevFeed, meta{URL: kevFeed.URL, Error: "GET: 503", ErrorAt: now})

	st, err := Status(Options{Dir: c.dir, KEV: true, EPSS: true}, sys)
	if err != nil || len(st) != 3 {
		t.Fatalf("%+v %v", st, err)
	}
	if s := st[0]; s.Name != deb.Name || !s.Cached || s.Size != 2 || s.Error != "" {
		t.Errorf("tracker: %+v", s)
	}
	if s := st[1]; s.Name != kevFeed.Name || s.Cached || s.Error != "GET: 503" {
		t.Errorf("kev: %+v", s)
	}
	if s := st[2]; s.Name != epssFeed.Name || s.Cached || s.Error != "" {
		t.Errorf("epss: %+v", s)
	}
}
