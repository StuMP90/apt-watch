package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"aptwatch/internal/runx"
)

// Livepatch is Canonical Livepatch's state for the running kernel.
type Livepatch struct {
	Kernel  string `json:"kernel"`
	State   string `json:"state"` // e.g. applied, nothing-to-apply, unapplied
	Version string `json:"version,omitempty"`
}

// Applied reports whether Livepatch has patched the running kernel.
func (l *Livepatch) Applied() bool { return l != nil && l.State == "applied" }

// Livepatch runs canonical-livepatch status. It returns nil, and no
// error, if the client isn't installed, isn't enabled or can't be run
// (it needs root): only output it can't understand is an error.
func (h Host) Livepatch(ctx context.Context) (*Livepatch, error) {
	res, err := h.run(ctx, runx.Cmd{Name: "canonical-livepatch", Args: []string{"status", "--format", "json"}, Timeout: 30 * time.Second})
	if err != nil {
		return nil, nil
	}
	return ParseLivepatch(res.Stdout)
}

// ParseLivepatch reads canonical-livepatch status --format json output.
func ParseLivepatch(b []byte) (*Livepatch, error) {
	var st struct {
		Status []struct {
			Kernel    string `json:"kernel"`
			Running   bool   `json:"running"`
			Livepatch struct {
				State   string `json:"state"`
				Version string `json:"version"`
			} `json:"livepatch"`
		} `json:"status"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("canonical-livepatch status: %w", err)
	}
	for _, s := range st.Status {
		if s.Running {
			return &Livepatch{Kernel: s.Kernel, State: s.Livepatch.State, Version: s.Livepatch.Version}, nil
		}
	}
	return nil, nil
}
