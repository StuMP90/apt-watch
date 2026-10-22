package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"aptwatch/internal/risk"
)

func TestCVEReport(t *testing.T) {
	now := time.Date(2026, 10, 22, 6, 0, 0, 0, time.UTC)
	r := &CVEReport{
		Schema: SchemaVersion, Tool: "aptwatch test", Host: "web01", Generated: now,
		Checks: []risk.CVECheck{
			{ID: "CVE-2026-0001", Status: risk.StatusFixed, Known: true, Priority: "high",
				Published: now.AddDate(0, 0, -2), Packages: []risk.CVEPackage{
					{Source: "foo", Status: risk.StatusFixed, Installed: "1.0-2", Fixed: "1.0-2", Binaries: []string{"foo"}},
				}},
			{ID: "CVE-2026-0002", Status: risk.StatusPending, Known: true, KEV: true, KEVAdded: now, EPSS: 0.42,
				Packages: []risk.CVEPackage{
					{Source: "php9", Status: risk.StatusPending, Repo: "ppa:example/php", Installed: "9.0-1", Candidate: "9.0-2",
						Binaries: []string{"php9-cli"}, Note: "named in the changelog of the pending update 9.0-2",
						Command: "sudo apt-get install --only-upgrade php9-cli"},
				}},
			{ID: "CVE-2026-9999", Status: risk.StatusUnknown, Packages: []risk.CVEPackage{}},
		},
	}
	if got, want := r.Summary(), "web01: 3 CVEs checked — 1 FIX PENDING, 1 UNKNOWN, 1 FIXED"; got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}
	if r.Highest() != risk.StatusPending {
		t.Errorf("Highest = %q", r.Highest())
	}

	var b bytes.Buffer
	if err := r.Text(&b); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"CVE-2026-0002  FIX PENDING", "9.0-1 → 9.0-2", "★ known exploited (CISA KEV) since 2026-10-22",
		"EPSS 42%", "sudo apt-get install --only-upgrade php9-cli", "published 2026-10-20", "Not in the vulnerability data"} {
		if !strings.Contains(b.String(), s) {
			t.Errorf("text lacks %q:\n%s", s, b.String())
		}
	}

	b.Reset()
	if err := r.HTML(&b); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`<div class="top high">`, `<span class="badge ok">FIXED</span>`, "php9-cli</pre>"} {
		if !strings.Contains(b.String(), s) {
			t.Errorf("html lacks %q", s)
		}
	}
	if strings.Contains(b.String(), "<script") {
		t.Error("html has a script")
	}

	b.Reset()
	if err := r.JSON(&b); err != nil {
		t.Fatal(err)
	}
	var back CVEReport
	if err := json.Unmarshal(b.Bytes(), &back); err != nil || len(back.Checks) != 3 || back.Checks[1].Status != risk.StatusPending {
		t.Errorf("json round trip: %v %+v", err, back)
	}

	one := &CVEReport{Host: "web01", Checks: r.Checks[:1]}
	if got := one.Summary(); got != "web01: CVE-2026-0001 FIXED" {
		t.Errorf("one Summary = %q", got)
	}
}
