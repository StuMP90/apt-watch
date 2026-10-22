package risk

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
)

// Kinds is every finding kind, for validating ignore rules.
var Kinds = []string{
	KindSecurityUpdate, KindUpdate, KindReboot, KindKernel, KindOSEOL, KindStaleLists,
	KindThirdParty, KindCVEFixAvailable, KindCVEFixUnreachable, KindCVEUnfixed,
	KindCVEUnfixedSummary, KindCVEFixedThirdParty, KindCVEThirdPartyGap,
}

// Date is a calendar day, written 2006-01-02.
type Date struct{ time.Time }

func (d *Date) UnmarshalText(b []byte) error {
	t, err := time.Parse(time.DateOnly, strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("invalid date %q (use YYYY-MM-DD)", b)
	}
	d.Time = t
	return nil
}

func (d Date) MarshalText() ([]byte, error) { return []byte(d.Format(time.DateOnly)), nil }

// MarshalJSON and UnmarshalJSON override the time.Time methods Date would
// otherwise promote, which take precedence over the text ones.
func (d Date) MarshalJSON() ([]byte, error) { return json.Marshal(d.Format(time.DateOnly)) }

func (d *Date) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return d.UnmarshalText([]byte(s))
}

// IgnoreRule suppresses the findings it matches (SPEC §7.3): those that
// name the CVE, and whose source package or any package matches the glob,
// and whose kind is in Kinds. Unset fields match anything, but a rule needs
// a CVE or a package.
type IgnoreRule struct {
	CVE     string   `yaml:"cve" json:"cve,omitempty"`
	Package string   `yaml:"package" json:"package,omitempty"`
	Kinds   []string `yaml:"kinds" json:"kinds,omitempty"`
	Reason  string   `yaml:"reason" json:"reason"`
	Until   Date     `yaml:"until" json:"until,omitzero"` // last day it applies
}

// Suppression records the ignore rule that matched a finding.
type Suppression struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
	Until  Date   `json:"until,omitzero"`
}

// String describes the rule, e.g. "CVE-2025-1234 (security-update-pending)".
func (r IgnoreRule) String() string {
	var s []string
	if r.CVE != "" {
		s = append(s, r.CVE)
	}
	if r.Package != "" {
		s = append(s, "package "+r.Package)
	}
	d := strings.Join(s, " in ")
	if len(r.Kinds) > 0 {
		d += " (" + strings.Join(r.Kinds, ", ") + ")"
	}
	return d
}

// Check validates the rule and normalises its CVE ID.
func (r *IgnoreRule) Check() error {
	if r.CVE == "" && r.Package == "" {
		return errors.New("needs a cve or a package")
	}
	if strings.TrimSpace(r.Reason) == "" {
		return errors.New("needs a reason")
	}
	if r.CVE != "" {
		id, err := NormCVE(r.CVE)
		if err != nil {
			return err
		}
		r.CVE = id
	}
	if _, err := path.Match(r.Package, ""); err != nil {
		return fmt.Errorf("invalid package glob %q", r.Package)
	}
	for _, k := range r.Kinds {
		if !slices.Contains(Kinds, k) {
			return fmt.Errorf("unknown kind %q (one of %s)", k, strings.Join(Kinds, ", "))
		}
	}
	return nil
}

// Expired reports whether the rule's last day is before now's.
func (r IgnoreRule) Expired(now time.Time) bool {
	if r.Until.IsZero() {
		return false
	}
	y, m, d := now.Date()
	return r.Until.Before(time.Date(y, m, d, 0, 0, 0, 0, time.UTC))
}

func (r IgnoreRule) matches(f Finding) bool {
	if len(r.Kinds) > 0 && !slices.Contains(r.Kinds, f.Kind) {
		return false
	}
	if r.CVE != "" && !slices.ContainsFunc(f.CVEs, func(c CVERef) bool { return c.ID == r.CVE }) {
		return false
	}
	if r.Package != "" {
		glob := func(name string) bool { ok, _ := path.Match(r.Package, name); return ok }
		if !glob(f.Source) && !slices.ContainsFunc(f.Packages, func(p PkgRef) bool { return glob(p.Name) }) {
			return false
		}
	}
	return true
}

// ApplyIgnores marks the findings the rules suppress. A finding with
// several CVEs is suppressed by CVE rules only if they cover all of them.
// Expired rules don't apply; they are returned for the report to mention.
func ApplyIgnores(fs []Finding, rules []IgnoreRule, now time.Time) (expired []IgnoreRule) {
	var active []IgnoreRule
	for _, r := range rules {
		if r.Expired(now) {
			expired = append(expired, r)
		} else {
			active = append(active, r)
		}
	}
	for i := range fs {
		f := &fs[i]
		var by []IgnoreRule
		covered := map[string]bool{}
		for _, r := range active {
			if !r.matches(*f) {
				continue
			}
			if r.CVE == "" {
				by = []IgnoreRule{r}
				break
			}
			if !covered[r.CVE] {
				covered[r.CVE] = true
				by = append(by, r)
			}
		}
		if len(by) == 0 || by[0].CVE != "" && len(covered) < len(cveIDs(f.CVEs)) {
			continue
		}
		s := &Suppression{}
		var rs, why []string
		for _, r := range by {
			rs = append(rs, r.String())
			why = append(why, r.Reason)
			if !r.Until.IsZero() && (s.Until.IsZero() || r.Until.Before(s.Until.Time)) {
				s.Until = r.Until
			}
		}
		s.Rule, s.Reason = strings.Join(rs, "; "), strings.Join(slices.Compact(why), "; ")
		f.Suppressed = s
	}
	return expired
}

func cveIDs(cs []CVERef) map[string]bool {
	m := map[string]bool{}
	for _, c := range cs {
		m[c.ID] = true
	}
	return m
}

// Active returns the findings no ignore rule suppresses.
func Active(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Suppressed == nil {
			out = append(out, f)
		}
	}
	return out
}

// Suppressed returns the findings an ignore rule suppresses.
func Suppressed(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Suppressed != nil {
			out = append(out, f)
		}
	}
	return out
}
