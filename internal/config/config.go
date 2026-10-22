// Package config loads and validates /etc/aptwatch/config.yaml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"aptwatch/internal/risk"
	"aptwatch/internal/state"
	"aptwatch/internal/vulndb"
)

const DefaultPath = "/etc/aptwatch/config.yaml"

// Duration is a time.Duration that also accepts days, e.g. "7d" or "1d12h".
type Duration time.Duration

var dayRe = regexp.MustCompile(`^(\d+)d(.*)$`)

func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	var days time.Duration
	if m := dayRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		days = time.Duration(n) * 24 * time.Hour
		if s = m[2]; s == "" {
			return days, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use e.g. 30s, 10m, 6h, 7d)", s)
	}
	return days + d, nil
}

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := ParseDuration(string(b))
	*d = Duration(v)
	return err
}

func (d Duration) D() time.Duration { return time.Duration(d) }

// Size is a byte count that accepts units, e.g. "500MB" or "1GiB".
type Size int64

var sizeRe = regexp.MustCompile(`^(\d+)\s*([KMGT]i?B|B)?$`)

func ParseSize(s string) (int64, error) {
	m := sizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("invalid size %q (use e.g. 500MB, 1GiB)", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	mult := map[string]int64{"": 1, "B": 1,
		"KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
		"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}[m[2]]
	return n * mult, nil
}

func (z *Size) UnmarshalText(b []byte) error {
	v, err := ParseSize(string(b))
	*z = Size(v)
	return err
}

type Config struct {
	HostLabel string            `yaml:"host_label"`
	LockFile  string            `yaml:"lock_file"`
	Apt       Apt               `yaml:"apt"`
	Policy    Policy            `yaml:"policy"`
	State     State             `yaml:"state"`
	Report    Report            `yaml:"report"`
	Notify    yaml.Node         `yaml:"notify"` // removed; warned about
	Vulndb    Vulndb            `yaml:"vulndb"`
	Ignore    []risk.IgnoreRule `yaml:"ignore"`

	Path string `yaml:"-"`
}

type Apt struct {
	RefreshLists       bool     `yaml:"refresh_lists"`
	RefreshIfOlderThan Duration `yaml:"refresh_if_older_than"`
	LockTimeout        Duration `yaml:"lock_timeout"`
	StaleAfter         Duration `yaml:"stale_after"`
}

type Policy struct {
	ExitThreshold       risk.Severity `yaml:"exit_threshold"`
	EscalateAfter       Duration      `yaml:"escalate_after"`
	RebootEscalateAfter Duration      `yaml:"reboot_escalate_after"`
	EOLWarnBefore       Duration      `yaml:"eol_warn_before"`
	EPSSBump            float64       `yaml:"epss_bump"`
	ReportUnfixedCVEs   string        `yaml:"report_unfixed_cves"`
	RecentCVEs          Duration      `yaml:"recent_cves"`
	ThirdPartyGaps      bool          `yaml:"report_third_party_gaps"`
}

type Vulndb struct {
	Sources    []string `yaml:"sources"`
	KEV        bool     `yaml:"kev"`
	EPSS       bool     `yaml:"epss"`
	MaxAge     Duration `yaml:"max_age"`
	StaleAfter Duration `yaml:"stale_after"`
	CacheDir   string   `yaml:"cache_dir"`
	MaxSize    Size     `yaml:"max_size"`
	Changelogs bool     `yaml:"changelogs"`
}

type State struct {
	File         string   `yaml:"file"`
	KeepResolved Duration `yaml:"keep_resolved"`
}

type Report struct {
	Format string `yaml:"format"`
}

// ValidFormat reports whether f is a report format: text, html or json.
func ValidFormat(f string) bool {
	return f == "text" || f == "html" || f == "json"
}

func Default() *Config {
	return &Config{
		LockFile: "/run/aptwatch.lock",
		Apt: Apt{
			RefreshLists:       true,
			RefreshIfOlderThan: Duration(6 * time.Hour),
			LockTimeout:        Duration(10 * time.Minute),
			StaleAfter:         Duration(48 * time.Hour),
		},
		Policy: Policy{
			ExitThreshold:       risk.High,
			EscalateAfter:       Duration(7 * 24 * time.Hour),
			RebootEscalateAfter: Duration(7 * 24 * time.Hour),
			EOLWarnBefore:       Duration(90 * 24 * time.Hour),
			EPSSBump:            0.5,
			ReportUnfixedCVEs:   risk.UnfixedSummary,
			RecentCVEs:          Duration(90 * 24 * time.Hour),
			ThirdPartyGaps:      true,
		},
		Vulndb: Vulndb{
			Sources:    []string{vulndb.SourceAuto},
			KEV:        true,
			EPSS:       true,
			MaxAge:     Duration(20 * time.Hour),
			StaleAfter: Duration(72 * time.Hour),
			CacheDir:   "/var/cache/aptwatch",
			MaxSize:    1 << 30,
			Changelogs: true,
		},
		Report: Report{Format: "text"},
		State:  State{File: state.DefaultPath, KeepResolved: Duration(30 * 24 * time.Hour)},
	}
}

// Load reads and validates the config. A missing file at the default path
// gives the defaults. Warnings are for things
// that are accepted but not acted on.
func Load(path string, explicit bool) (*Config, []string, error) {
	c := Default()
	c.Path = path
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return c, []string{"no config file at " + path + ": using defaults"}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if err := checkPerms(path); err != nil {
		return nil, nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	warnings, err := c.validate()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, warnings, nil
}

func (c *Config) validate() ([]string, error) {
	var warnings []string
	for i := range c.Ignore {
		if err := c.Ignore[i].Check(); err != nil {
			return warnings, fmt.Errorf("ignore[%d]: %w", i, err)
		}
	}
	if !c.Notify.IsZero() {
		warnings = append(warnings, "notify: aptwatch no longer sends notifications; section ignored (pipe the report to a handler instead)")
	}
	if !ValidFormat(c.Report.Format) {
		return nil, fmt.Errorf("report: format must be text, html or json")
	}
	dir := filepath.Dir(c.Path)
	abs := func(p string) string {
		if p != "" && !filepath.IsAbs(p) {
			return filepath.Join(dir, p)
		}
		return p
	}
	c.State.File = abs(c.State.File)
	c.LockFile = abs(c.LockFile)
	c.Vulndb.CacheDir = abs(c.Vulndb.CacheDir)

	switch c.Policy.ReportUnfixedCVEs {
	case risk.UnfixedSummary, risk.UnfixedNone, risk.UnfixedFull:
	default:
		return nil, fmt.Errorf("policy: report_unfixed_cves must be none, summary or full")
	}
	if c.Policy.EPSSBump < 0 || c.Policy.EPSSBump > 1 {
		return nil, fmt.Errorf("policy: epss_bump must be between 0 and 1 (0 turns it off)")
	}
	if c.Policy.RecentCVEs < 0 {
		return nil, fmt.Errorf("policy: recent_cves must not be negative (0 turns it off)")
	}
	if len(c.Vulndb.Sources) == 0 {
		return nil, fmt.Errorf("vulndb: sources must not be empty (use [auto])")
	}
	for _, s := range c.Vulndb.Sources {
		switch s {
		case vulndb.SourceAuto, vulndb.SourceUbuntu, vulndb.SourceDebian:
		default:
			return nil, fmt.Errorf("vulndb: unknown source %q (auto, %s or %s)", s, vulndb.SourceUbuntu, vulndb.SourceDebian)
		}
	}
	if c.Vulndb.CacheDir == "" {
		return nil, fmt.Errorf("vulndb: cache_dir is required")
	}
	if c.Vulndb.MaxSize <= 0 {
		return nil, fmt.Errorf("vulndb: max_size must be positive")
	}

	return warnings, nil
}

// RiskPolicy converts the policy settings for the risk package.
func (c *Config) RiskPolicy() risk.Policy {
	return risk.Policy{
		EscalateAfter:       c.Policy.EscalateAfter.D(),
		RebootEscalateAfter: c.Policy.RebootEscalateAfter.D(),
		EOLWarnBefore:       c.Policy.EOLWarnBefore.D(),
		StaleListsAfter:     c.Apt.StaleAfter.D(),
		EPSSBump:            c.Policy.EPSSBump,
		ReportUnfixed:       c.Policy.ReportUnfixedCVEs,
		RecentCVEs:          c.Policy.RecentCVEs.D(),
		ThirdPartyGaps:      c.Policy.ThirdPartyGaps,
	}
}

// VulndbOptions converts the vulndb settings; the caller sets Refresh and
// UserAgent.
func (c *Config) VulndbOptions() vulndb.Options {
	v := c.Vulndb
	return vulndb.Options{
		Dir: v.CacheDir, Sources: v.Sources, KEV: v.KEV, EPSS: v.EPSS,
		MaxAge: v.MaxAge.D(), StaleAfter: v.StaleAfter.D(), MaxSize: int64(v.MaxSize),
	}
}

// checkPerms refuses, when running as root, a config that someone other
// than root could have written: it can make root run commands.
func checkPerms(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return CheckPerms(path)
}

// CheckPerms reports whether anyone but root could write the config.
func CheckPerms(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s: must be owned by root", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: must not be writable by group or others (chmod 600)", path)
	}
	return nil
}
