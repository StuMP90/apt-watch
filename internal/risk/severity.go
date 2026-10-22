// Package risk turns a collected inventory into findings with severities.
package risk

import (
	"fmt"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// Label is the upper-case form used in reports.
func (s Severity) Label() string { return strings.ToUpper(s.String()) }

func ParseSeverity(s string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(s, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", s)
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	*s = v
	return err
}

// Bump raises s by n levels, capped at Critical.
func (s Severity) Bump(n int) Severity { return min(s+Severity(n), Critical) }
