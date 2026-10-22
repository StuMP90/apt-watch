// Command aptwatch checks a Debian or Ubuntu host for pending updates and
// risks, and reports them (SPEC.md).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"aptwatch/internal/collect"
	"aptwatch/internal/config"
	"aptwatch/internal/report"
	"aptwatch/internal/risk"
	"aptwatch/internal/state"
	"aptwatch/internal/vulndb"
)

var version = "0.1.0-dev"

// Exit codes (SPEC §3).
const (
	exitOK       = 0
	exitFindings = 1
	exitWarnings = 2
	exitFatal    = 3
)

type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

var g struct {
	config   string
	quiet    bool
	logLevel string
	nagios   bool // errors are reported as a plugin's UNKNOWN
}

func main() {
	root := &cobra.Command{
		Use:           "aptwatch",
		Short:         "Watch a Debian/Ubuntu host for pending updates and risks",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return setupLogging()
		},
	}
	root.PersistentFlags().StringVarP(&g.config, "config", "c", config.DefaultPath, "config file")
	root.PersistentFlags().BoolVarP(&g.quiet, "quiet", "q", false, "log errors only")
	root.PersistentFlags().StringVar(&g.logLevel, "log-level", "info", "debug, info, warn or error")
	root.AddCommand(runCmd(), scanCmd(), cveCmd(), dbCmd(), configCmd(), stateCmd(), &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run:   func(*cobra.Command, []string) { fmt.Println("aptwatch", version) },
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := root.ExecuteContext(ctx)
	stop()
	var ee exitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		os.Exit(ee.code)
	case g.nagios:
		fmt.Println("UNKNOWN - aptwatch:", err)
		os.Exit(exitFatal)
	default:
		fmt.Fprintln(os.Stderr, "aptwatch:", err)
		os.Exit(exitFatal)
	}
}

func setupLogging() error {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(g.logLevel)); err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	if g.quiet {
		lvl = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
	return nil
}

func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	cfg, warnings, err := config.Load(g.config, cmd.Flags().Changed("config"))
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		slog.Warn(w)
	}
	return cfg, nil
}

// lock takes the run lock, failing at once if another run holds it.
func lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another aptwatch run holds %s", path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() { f.Close() }, nil
}

// check collects the inventory and evaluates it. With st, findings get
// their history and escalation; without (scan), they are as found. With
// refreshVuln, out-of-date vulnerability data is downloaded first.
func check(ctx context.Context, cfg *config.Config, st *state.State, now time.Time, refreshVuln bool) (*report.Report, []risk.Finding, error) {
	h, err := gather(ctx, cfg, now, refreshVuln)
	if err != nil {
		return nil, nil, err
	}
	pol := cfg.RiskPolicy()
	fs := risk.Evaluate(h.inv, pol, now)
	if h.db != nil {
		fs = risk.AddCVEFindings(fs, h.inv, h.db, pol, now)
	}
	if st != nil {
		st.Annotate(fs, now)
		risk.Escalate(fs, pol, now)
	}
	risk.Sort(fs)
	expired := risk.ApplyIgnores(fs, cfg.Ignore, now)
	return &report.Report{
		Schema:    report.SchemaVersion,
		Tool:      "aptwatch " + version,
		Host:      h.host,
		Generated: now,
		System:    h.inv.System,
		Findings:  fs,
		Updates:   h.inv.Simulation.Updates,
		VulnDB:    h.vulnDB(),
		Warnings:  h.warnings,
		Expired:   expired,
	}, fs, nil
}

// host is what is known about the host: its inventory and the
// vulnerability data for its release (db is nil if there is none).
type host struct {
	inv      *collect.Inventory
	db       *vulndb.DB
	host     string
	warnings []string
}

// gather collects the inventory, with the third-party changelogs if
// configured, and opens the vulnerability data.
func gather(ctx context.Context, cfg *config.Config, now time.Time, refreshVuln bool) (*host, error) {
	inv, warnings, err := collect.Collect(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.Vulndb.Changelogs {
		warnings = append(warnings, collect.AddChangelogs(ctx, inv, cfg.Vulndb.CacheDir)...)
	}
	vo := cfg.VulndbOptions()
	vo.Refresh = refreshVuln
	vo.UserAgent = "aptwatch/" + version
	o := inv.System.OS
	db, ws := vulndb.Open(ctx, vo, vulndb.OS{ID: o.ID, VersionID: o.VersionID, Codename: o.Codename}, now)
	h := &host{inv: inv, db: db, host: cfg.HostLabel, warnings: append(warnings, ws...)}
	if h.host == "" {
		h.host, _, _ = strings.Cut(inv.System.Hostname, ".")
	}
	return h, nil
}

func (h *host) vulnDB() *report.VulnDB {
	if h.db == nil {
		return nil
	}
	return &report.VulnDB{Sources: h.db.Sources, Fetched: h.db.Fetched, KEV: len(h.db.KEV), EPSS: len(h.db.EPSS)}
}

func refresh(ctx context.Context, cfg *config.Config) {
	if !cfg.Apt.RefreshLists {
		return
	}
	if os.Geteuid() != 0 {
		slog.Debug("not root: skipping apt-get update")
		return
	}
	if t, err := collect.ListsUpdated(collect.AptListsDir); err == nil && time.Since(t) < cfg.Apt.RefreshIfOlderThan.D() {
		slog.Debug("apt lists are recent: skipping apt-get update", "updated", t)
		return
	}
	slog.Info("running apt-get update")
	if err := collect.RefreshLists(ctx, cfg.Apt.LockTimeout.D()); err != nil {
		// Carry on with the old lists; the stale-lists check reports it.
		slog.Warn("apt-get update failed", "err", err)
	}
}

func printReport(w io.Writer, rep *report.Report, format string) error {
	switch format {
	case "nagios":
		return nil
	case "json":
		return rep.JSON(w)
	case "html":
		return rep.HTML(w)
	}
	return rep.Text(w)
}

// reportFormat is "nagios" with --nagios, else the --format flag if
// given, else the config's report.format.
func reportFormat(cmd *cobra.Command, cfg *config.Config) (string, error) {
	if g.nagios {
		return "nagios", nil
	}
	if !cmd.Flags().Changed("format") {
		return cfg.Report.Format, nil
	}
	f, _ := cmd.Flags().GetString("format")
	if !config.ValidFormat(f) {
		return "", fmt.Errorf("--format must be text, html or json")
	}
	return f, nil
}

func exitFor(w io.Writer, cfg *config.Config, rep *report.Report) error {
	if g.nagios {
		return nagios(w, cfg, rep)
	}
	switch {
	case rep.Highest() >= cfg.Policy.ExitThreshold && len(risk.Active(rep.Findings)) > 0:
		return exitError{exitFindings}
	case len(rep.Warnings) > 0:
		return exitError{exitWarnings}
	}
	return nil
}

// Nagios plugin exit codes.
const (
	nagiosOK       = 0
	nagiosWarning  = 1
	nagiosCritical = 2
)

// nagios prints the report as a monitoring plugin's one line (SPEC §3):
// CRITICAL for findings at or above policy.exit_threshold, WARNING for
// lesser risks or warnings, else OK. Fatal errors are UNKNOWN (main).
func nagios(w io.Writer, cfg *config.Config, rep *report.Report) error {
	active := len(risk.Active(rep.Findings)) > 0
	status, code := "OK", nagiosOK
	switch hi := rep.Highest(); {
	case active && hi >= cfg.Policy.ExitThreshold:
		status, code = "CRITICAL", nagiosCritical
	case active && hi >= risk.Low || len(rep.Warnings) > 0:
		status, code = "WARNING", nagiosWarning
	}
	line := status + " - " + rep.Summary()
	if n := len(rep.Warnings); n > 0 {
		line += fmt.Sprintf(" — %d warning%s: %s", n, plural(n), rep.Warnings[0])
	}
	fmt.Fprintln(w, line)
	if code == nagiosOK {
		return nil
	}
	return exitError{code}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func runCmd() *cobra.Command {
	var noRefresh, dryRun bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Check the host, record the results and print the report (the cron/timer job)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			format, err := reportFormat(cmd, cfg)
			if err != nil {
				return err
			}
			unlock, err := lock(cfg.LockFile)
			if err != nil {
				return err
			}
			defer unlock()
			ctx := cmd.Context()
			if !noRefresh && !dryRun {
				refresh(ctx, cfg)
			}
			st, err := state.Load(cfg.State.File)
			if err != nil {
				return err
			}
			now := time.Now()
			rep, fs, err := check(ctx, cfg, st, now, !noRefresh)
			if err != nil {
				return err
			}
			diff := st.Update(fs, now, cfg.State.KeepResolved.D())
			rep.Diff = &diff
			if err := printReport(cmd.OutOrStdout(), rep, format); err != nil {
				return err
			}
			if !dryRun {
				if err := st.Save(cfg.State.File); err != nil {
					return fmt.Errorf("saving state: %w", err)
				}
			}
			return exitFor(cmd.OutOrStdout(), cfg, rep)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&noRefresh, "no-refresh", false, "don't run apt-get update or download vulnerability data")
	f.BoolVar(&dryRun, "dry-run", false, "print the report but don't save the state")
	f.String("format", "", "report format: text, html or json (default: report.format in the config, else text)")
	f.BoolVar(&g.nagios, "nagios", false, "print one summary line and exit 0/1/2/3 = OK/WARNING/CRITICAL/UNKNOWN")
	// Notifications were removed; accepted so that existing cron lines work.
	f.Bool("no-notify", false, "no effect")
	_ = f.MarkHidden("no-notify")
	return cmd
}

func scanCmd() *cobra.Command {
	var noRefresh bool
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Check the host and print the report (no state)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			format, err := reportFormat(cmd, cfg)
			if err != nil {
				return err
			}
			rep, _, err := check(cmd.Context(), cfg, nil, time.Now(), !noRefresh)
			if err != nil {
				return err
			}
			if err := printReport(cmd.OutOrStdout(), rep, format); err != nil {
				return err
			}
			return exitFor(cmd.OutOrStdout(), cfg, rep)
		},
	}
	cmd.Flags().String("format", "", "report format: text, html or json (default: report.format in the config, else text)")
	cmd.Flags().BoolVar(&noRefresh, "no-refresh", false, "use only cached vulnerability data")
	cmd.Flags().BoolVar(&g.nagios, "nagios", false, "print one summary line and exit 0/1/2/3 = OK/WARNING/CRITICAL/UNKNOWN")
	return cmd
}

func cveCmd() *cobra.Command {
	var noRefresh bool
	cmd := &cobra.Command{
		Use:   "cve CVE-ID...",
		Short: "Report whether the host is affected by the given CVEs, and what fixes them",
		Long: `Report the status of each CVE on the host (SPEC §3.1). Exits 1 if any
needs action (a fix is pending, unreachable, needs Pro or a reboot, or
there is none yet), 2 if any is unknown or there were warnings, else 0.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ids := make([]string, 0, len(args))
			for _, a := range args {
				id, err := risk.NormCVE(a)
				if err != nil {
					return err
				}
				if !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			format, err := reportFormat(cmd, cfg)
			if err != nil {
				return err
			}
			now := time.Now()
			h, err := gather(cmd.Context(), cfg, now, !noRefresh)
			if err != nil {
				return err
			}
			rep := &report.CVEReport{
				Schema:    report.SchemaVersion,
				Tool:      "aptwatch " + version,
				Host:      h.host,
				Generated: now,
				VulnDB:    h.vulnDB(),
				Warnings:  h.warnings,
			}
			for _, id := range ids {
				rep.Checks = append(rep.Checks, risk.CheckCVE(h.inv, h.db, id))
			}
			switch format {
			case "json":
				err = rep.JSON(os.Stdout)
			case "html":
				err = rep.HTML(os.Stdout)
			default:
				err = rep.Text(os.Stdout)
			}
			if err != nil {
				return err
			}
			switch hi := rep.Highest(); {
			case risk.NeedsAction(hi):
				return exitError{exitFindings}
			case hi == risk.StatusUnknown || len(rep.Warnings) > 0:
				return exitError{exitWarnings}
			}
			return nil
		},
	}
	cmd.Flags().String("format", "", "report format: text, html or json (default: report.format in the config, else text)")
	cmd.Flags().BoolVar(&noRefresh, "no-refresh", false, "use only cached vulnerability data")
	return cmd
}

func stateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "state", Short: "Inspect or reset the stored state"}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the state file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			st, err := state.Load(cfg.State.File)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(st)
		},
	}, &cobra.Command{
		Use:   "reset",
		Short: "Forget all findings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			unlock, err := lock(cfg.LockFile)
			if err != nil {
				return err
			}
			defer unlock()
			if err := os.Remove(cfg.State.File); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			slog.Info("state reset", "file", filepath.Clean(cfg.State.File))
			return nil
		},
	})
	return cmd
}
