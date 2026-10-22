package risk

import (
	"strings"
	"testing"
	"time"

	"aptwatch/internal/collect"
)

var now = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// systemFindings evaluates an inventory with no packages or updates, so
// only the system rules can fire.
func systemFindings(sys collect.System, p Policy) map[string]Finding {
	inv := &collect.Inventory{Simulation: &collect.Simulation{}, System: sys}
	got := map[string]Finding{}
	for _, f := range Evaluate(inv, p, now) {
		got[f.Kind] = f
	}
	return got
}

func TestEvaluateReboot(t *testing.T) {
	tests := []struct {
		name   string
		reboot collect.Reboot
		policy time.Duration
		want   Severity
		detail string
	}{
		{"recent", collect.Reboot{Required: true, Since: now.Add(-day), Packages: []string{"linux-base", "libc6"}}, 7 * day, Medium,
			"Requested by: linux-base, libc6"},
		{"at the limit", collect.Reboot{Required: true, Since: now.Add(-7 * day)}, 7 * day, High, ""},
		{"no date", collect.Reboot{Required: true}, 7 * day, Medium, ""},
		{"escalation off", collect.Reboot{Required: true, Since: now.AddDate(-1, 0, 0)}, 0, Medium, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultPolicy()
			p.RebootEscalateAfter = tc.policy
			f, ok := systemFindings(collect.System{Reboot: tc.reboot}, p)[KindReboot]
			if !ok {
				t.Fatal("no reboot finding")
			}
			if f.Severity != tc.want || f.Detail != tc.detail || !f.FixAvail {
				t.Errorf("got %v, %q, fix %v; want %v, %q, fix true", f.Severity, f.Detail, f.FixAvail, tc.want, tc.detail)
			}
		})
	}
	if _, ok := systemFindings(collect.System{}, DefaultPolicy())[KindReboot]; ok {
		t.Error("reboot finding when no reboot is required")
	}
}

func TestEvaluateKernel(t *testing.T) {
	f, ok := systemFindings(collect.System{Kernel: collect.Kernel{Running: "6.8.0-90-generic", Newest: "6.8.0-91-generic"}}, DefaultPolicy())[KindKernel]
	if !ok {
		t.Fatal("no kernel finding")
	}
	if f.Key != "kernel-not-running:6.8.0-91-generic" || f.Severity != Medium || f.Detail != "Running 6.8.0-90-generic, newest installed 6.8.0-91-generic" {
		t.Errorf("got %q, %v, %q", f.Key, f.Severity, f.Detail)
	}
	for name, k := range map[string]collect.Kernel{
		"running newest":  {Running: "6.8.0-91-generic", Newest: "6.8.0-91-generic"},
		"no newest":       {Running: "6.8.0-91-generic"}, // e.g. a container
		"running unknown": {Newest: "6.8.0-91-generic"},
	} {
		if _, ok := systemFindings(collect.System{Kernel: k}, DefaultPolicy())[KindKernel]; ok {
			t.Errorf("%s: kernel finding", name)
		}
	}
}

func TestEvaluateEOL(t *testing.T) {
	tests := []struct {
		name   string
		end    time.Time
		pretty string
		want   Severity
		title  string // empty for no finding
	}{
		{"past", now.AddDate(0, 0, -1), "Ubuntu 20.04.6 LTS", High, "Ubuntu 20.04.6 LTS is past end of security support (2026-04-30)"},
		{"today", now, "", High, "focal is past end of security support (2026-05-01)"},
		{"soon", now.Add(30 * day), "Ubuntu 20.04.6 LTS", Medium, "Ubuntu 20.04.6 LTS reaches end of security support on 2026-05-31 (30 days)"},
		{"at the warning", now.Add(90 * day), "Ubuntu 20.04.6 LTS", Medium, "Ubuntu 20.04.6 LTS reaches end of security support on 2026-07-30 (90 days)"},
		{"far off", now.Add(91 * day), "Ubuntu 20.04.6 LTS", Info, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sys := collect.System{
				OS:  collect.OSRelease{Codename: "focal", PrettyName: tc.pretty},
				EOL: &collect.EOL{SecurityEnd: tc.end, Note: "ESM (Ubuntu Pro) until 2030-04-02"},
			}
			f, ok := systemFindings(sys, DefaultPolicy())[KindOSEOL]
			if tc.title == "" {
				if ok {
					t.Errorf("unexpected finding %q", f.Title)
				}
				return
			}
			if !ok {
				t.Fatal("no end-of-life finding")
			}
			if f.Key != "os-eol:focal" || f.Severity != tc.want || f.Title != tc.title || f.Detail != "ESM (Ubuntu Pro) until 2030-04-02" {
				t.Errorf("got %q, %v, %q, %q", f.Key, f.Severity, f.Title, f.Detail)
			}
		})
	}
	if _, ok := systemFindings(collect.System{OS: collect.OSRelease{Codename: "sid"}}, DefaultPolicy())[KindOSEOL]; ok {
		t.Error("end-of-life finding with no EOL date")
	}
}

func TestEvaluateStaleLists(t *testing.T) {
	tests := []struct {
		name    string
		updated time.Time
		policy  time.Duration
		title   string // empty for no finding
	}{
		{"stale", now.Add(-3 * day), 48 * time.Hour, "apt package lists last updated 3d ago"},
		{"fresh", now.Add(-47 * time.Hour), 48 * time.Hour, ""},
		{"at the limit", now.Add(-48 * time.Hour), 48 * time.Hour, ""},
		{"check off", now.AddDate(-1, 0, 0), 0, ""},
		{"unknown", time.Time{}, 48 * time.Hour, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultPolicy()
			p.StaleListsAfter = tc.policy
			f, ok := systemFindings(collect.System{ListsUpdated: tc.updated}, p)[KindStaleLists]
			if ok != (tc.title != "") {
				t.Fatalf("finding %v (%q), want %v", ok, f.Title, tc.title != "")
			}
			if ok && (f.Severity != Medium || f.Title != tc.title || !f.Since.Equal(tc.updated)) {
				t.Errorf("got %v, %q, since %v", f.Severity, f.Title, f.Since)
			}
		})
	}
}

func TestEscalate(t *testing.T) {
	old := now.Add(-7 * day)
	tests := []struct {
		name      string
		kind      string
		sev       Severity
		firstSeen time.Time
		policy    time.Duration
		want      Severity
	}{
		{"security update", KindSecurityUpdate, Medium, old, 7 * day, High},
		{"fix available", KindCVEFixAvailable, High, old, 7 * day, Critical},
		{"fix unreachable", KindCVEFixUnreachable, Low, old, 7 * day, Medium},
		{"capped", KindCVEFixAvailable, Critical, old, 7 * day, Critical},
		{"too recent", KindSecurityUpdate, Medium, old.Add(time.Second), 7 * day, Medium},
		{"never seen", KindSecurityUpdate, Medium, time.Time{}, 7 * day, Medium},
		{"escalation off", KindSecurityUpdate, Medium, now.AddDate(-1, 0, 0), 0, Medium},
		{"plain update", KindUpdate, Info, old, 7 * day, Info},
		{"unfixed CVE", KindCVEUnfixed, Low, old, 7 * day, Low},
		{"reboot", KindReboot, Medium, old, 7 * day, Medium}, // has its own escalation in Evaluate
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultPolicy()
			p.EscalateAfter = tc.policy
			fs := []Finding{{Key: "k", Kind: tc.kind, Severity: tc.sev, FirstSeen: tc.firstSeen}}
			Escalate(fs, p, now)
			if fs[0].Severity != tc.want {
				t.Errorf("severity %v, want %v", fs[0].Severity, tc.want)
			}
		})
	}
}

func TestEscalateSorts(t *testing.T) {
	fs := []Finding{
		{Key: "a", Kind: KindUpdate, Severity: Medium},
		{Key: "b", Kind: KindSecurityUpdate, Severity: Medium, FirstSeen: now.Add(-30 * day)},
	}
	Escalate(fs, DefaultPolicy(), now)
	if fs[0].Key != "b" || fs[0].Severity != High {
		t.Errorf("first finding %q at %v, want the escalated b at high", fs[0].Key, fs[0].Severity)
	}
}

func TestSeverity(t *testing.T) {
	for _, s := range []string{"info", "LOW", "Medium", "high", "critical"} {
		var v Severity
		if err := v.UnmarshalText([]byte(s)); err != nil {
			t.Errorf("%q: %v", s, err)
		}
		if b, _ := v.MarshalText(); !strings.EqualFold(string(b), s) {
			t.Errorf("%q round-trips to %q", s, b)
		}
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("no error for an unknown severity")
	}
	if High.Label() != "HIGH" || Severity(9).String() != "severity(9)" {
		t.Errorf("Label %q, out of range %q", High.Label(), Severity(9).String())
	}
	if Low.Bump(2) != High || High.Bump(5) != Critical {
		t.Errorf("Bump: %v, %v", Low.Bump(2), High.Bump(5))
	}
}

func TestAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		45 * time.Minute: "45m", 6 * time.Hour: "6h", 47 * time.Hour: "47h", 48 * time.Hour: "2d", 10 * day: "10d",
	} {
		if got := Age(d); got != want {
			t.Errorf("Age(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestHighestAndAtLeast(t *testing.T) {
	if _, ok := Highest(nil); ok {
		t.Error("Highest(nil) reports a severity")
	}
	fs := []Finding{{Severity: Low}, {Severity: High}, {Severity: Info}}
	if h, ok := Highest(fs); !ok || h != High {
		t.Errorf("Highest = %v, %v", h, ok)
	}
	if n := len(AtLeast(fs, Low)); n != 2 {
		t.Errorf("AtLeast(low) found %d, want 2", n)
	}
}
