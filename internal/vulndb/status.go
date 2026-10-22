package vulndb

import "time"

// FeedStatus describes one cached feed, for "aptwatch db status".
type FeedStatus struct {
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Cached  bool      `json:"cached"`
	Fetched time.Time `json:"fetched,omitzero"` // when the content last changed
	Checked time.Time `json:"checked,omitzero"` // when it was last confirmed current
	Size    int64     `json:"size,omitempty"`
	Error   string    `json:"error,omitempty"` // the last refresh failure
	ErrorAt time.Time `json:"error_at,omitzero"`
}

// Status describes the feeds that Open would use, from the cache alone:
// it downloads nothing and writes nothing.
func Status(o Options, sys OS) ([]FeedStatus, error) {
	sources, err := resolveSources(o.Sources, sys)
	if err != nil {
		return nil, err
	}
	var feeds []feed
	for _, s := range sources {
		feeds = append(feeds, advFeedFor(s, sys).feed)
	}
	if o.KEV {
		feeds = append(feeds, kevFeed)
	}
	if o.EPSS {
		feeds = append(feeds, epssFeed)
	}
	c := &cache{dir: o.Dir, o: o}
	var out []FeedStatus
	for _, f := range feeds {
		st := FeedStatus{Name: f.Name, URL: f.URL}
		if m, ok := c.readMetaFile(f); ok {
			_, st.Cached = c.readMeta(f)
			st.Error, st.ErrorAt = m.Error, m.ErrorAt
			if st.Cached {
				st.Fetched, st.Checked, st.Size = m.Fetched, m.Checked, m.Size
			}
		}
		out = append(out, st)
	}
	return out, nil
}
