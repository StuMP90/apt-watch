package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"aptwatch/internal/collect"
	"aptwatch/internal/config"
	"aptwatch/internal/risk"
	"aptwatch/internal/vulndb"
)

func dbCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "db", Short: "Refresh or inspect the cached vulnerability data"}

	var force bool
	update := &cobra.Command{
		Use:   "update",
		Short: "Download out-of-date vulnerability data and rebuild the index",
		Long: `Refresh the vulnerability data that run and scan use, without checking
the host. Feeds checked within vulndb.max_age are left alone unless
--force. Exits 2 if a feed failed (the cached copy stays in use), 3 if
no advisory data could be loaded.`,
		Args: cobra.NoArgs,
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
			sys, err := hostOS()
			if err != nil {
				return err
			}
			vo := cfg.VulndbOptions()
			vo.Refresh = true
			vo.UserAgent = "aptwatch/" + version
			if force {
				vo.MaxAge = 0
			}
			now := time.Now()
			db, warnings := vulndb.Open(cmd.Context(), vo, sys, now)
			for _, w := range warnings {
				slog.Warn(w)
			}
			if db == nil {
				return errors.New("no vulnerability data available")
			}
			fs, err := vulndb.Status(vo, sys)
			if err != nil {
				return err
			}
			if err := printFeeds(os.Stdout, cfg, sys, fs, now); err != nil {
				return err
			}
			if len(warnings) > 0 {
				return exitError{exitWarnings}
			}
			return nil
		},
	}
	update.Flags().BoolVar(&force, "force", false, "check every feed, however recently it was checked")

	var asJSON bool
	status := &cobra.Command{
		Use:   "status",
		Short: "Show each vulnerability data feed: when it was checked, its size and last error",
		Long: `Show the cached vulnerability data, from the cache alone (nothing is
downloaded). Exits 2 if a feed is missing, older than vulndb.stale_after,
or its last refresh failed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			sys, err := hostOS()
			if err != nil {
				return err
			}
			vo := cfg.VulndbOptions()
			fs, err := vulndb.Status(vo, sys)
			if err != nil {
				return err
			}
			now := time.Now()
			if asJSON {
				e := json.NewEncoder(os.Stdout)
				e.SetIndent("", "  ")
				err = e.Encode(fs)
			} else {
				err = printFeeds(os.Stdout, cfg, sys, fs, now)
			}
			if err != nil {
				return err
			}
			for _, f := range fs {
				if feedProblem(f, vo.StaleAfter, now) != "" {
					return exitError{exitWarnings}
				}
			}
			return nil
		},
	}
	status.Flags().BoolVar(&asJSON, "json", false, "print JSON")

	cmd.AddCommand(update, status)
	return cmd
}

func hostOS() (vulndb.OS, error) {
	o, err := collect.ReadOSRelease("/etc/os-release")
	if err != nil {
		return vulndb.OS{}, err
	}
	return vulndb.OS{ID: o.ID, VersionID: o.VersionID, Codename: o.Codename}, nil
}

// feedProblem says what is wrong with a feed, or "" if nothing is.
func feedProblem(f vulndb.FeedStatus, staleAfter time.Duration, now time.Time) string {
	switch {
	case f.Error != "" && !f.Cached:
		return fmt.Sprintf("never downloaded; failed %s: %s", f.ErrorAt.Format("2006-01-02 15:04"), f.Error)
	case !f.Cached:
		return "not downloaded yet (run aptwatch db update)"
	case f.Error != "":
		return fmt.Sprintf("refresh failed %s: %s", f.ErrorAt.Format("2006-01-02 15:04"), f.Error)
	case staleAfter > 0 && now.Sub(f.Checked) > staleAfter:
		return "stale: " + risk.Age(now.Sub(f.Checked)) + " old"
	}
	return ""
}

func printFeeds(w io.Writer, cfg *config.Config, sys vulndb.OS, fs []vulndb.FeedStatus, now time.Time) error {
	fmt.Fprintf(w, "Vulnerability data in %s for %s %s\n\n", cfg.Vulndb.CacheDir, sys.ID, sys.VersionID)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FEED\tCHECKED\tCHANGED\tSIZE\tSTATUS")
	for _, f := range fs {
		checked, changed, size := "-", "-", "-"
		if f.Cached {
			checked = f.Checked.Format("2006-01-02 15:04") + " (" + risk.Age(now.Sub(f.Checked)) + " ago)"
			changed = f.Fetched.Format("2006-01-02")
			size = humanSize(f.Size)
		}
		st := feedProblem(f, cfg.VulndbOptions().StaleAfter, now)
		if st == "" {
			st = "ok"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Name, checked, changed, size, st)
	}
	return tw.Flush()
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Check the configuration"}
	cmd.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Validate the config file and its permissions",
		Long: `Load and validate the config file, whoever runs it: it must be owned by
root and not writable by group or others (SPEC §10). Exits 3 if the config
is invalid, 2 if it loaded with warnings or has expired ignore rules,
else 0.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, warnings, err := config.Load(g.config, true)
			if err != nil {
				return err
			}
			if err := config.CheckPerms(g.config); err != nil {
				return err
			}
			now := time.Now()
			fmt.Printf("%s: OK\n", g.config)
			var expired []string
			for _, r := range cfg.Ignore {
				if r.Expired(now) {
					expired = append(expired, fmt.Sprintf("ignore rule %s expired on %s (%s)", r, r.Until.Format(time.DateOnly), r.Reason))
				}
			}
			if n := len(cfg.Ignore); n > 0 {
				fmt.Printf("  %d ignore rule%s, %d expired\n", n, plural(n), len(expired))
			}
			warnings = append(warnings, expired...)
			for _, w := range warnings {
				fmt.Println("  warning:", w)
			}
			if len(warnings) > 0 {
				return exitError{exitWarnings}
			}
			return nil
		},
	})
	return cmd
}
