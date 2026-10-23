//go:build genman

package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// The man pages are generated at release time, so the shipped binary
// doesn't carry the generator:
//
//	go run -tags genman ./cmd/aptwatch genman DIR
func init() { extraCmds = append(extraCmds, genmanCmd) }

func genmanCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "genman DIR",
		Short:  "Write gzipped section 8 man pages to DIR",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return genMan(cmd.Root(), args[0])
		},
	}
}

// genMan writes one page per command, e.g. aptwatch-db-update.8.gz. The
// date comes from SOURCE_DATE_EPOCH when it is set, and the gzip header
// has no name or time, so a release build gives the same files each time.
func genMan(root *cobra.Command, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	root.DisableAutoGenTag = true
	// cobra adds its completion command when it runs; leave it out.
	if c, _, err := root.Find([]string{"completion"}); err == nil && c != root {
		root.RemoveCommand(c)
	}
	hdr := &doc.GenManHeader{Section: "8", Source: "aptwatch " + version, Manual: "aptwatch"}
	var walk func(*cobra.Command) error
	walk = func(c *cobra.Command) error {
		if !c.IsAvailableCommand() && c != root {
			return nil
		}
		var page bytes.Buffer
		h := *hdr
		if err := doc.GenMan(c, &h, &page); err != nil {
			return err
		}
		var gz bytes.Buffer
		w, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
		w.Write(page.Bytes())
		if err := w.Close(); err != nil {
			return err
		}
		name := strings.ReplaceAll(c.CommandPath(), " ", "-") + ".8.gz"
		if err := os.WriteFile(filepath.Join(dir, name), gz.Bytes(), 0o644); err != nil {
			return err
		}
		for _, sub := range c.Commands() {
			if err := walk(sub); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root)
}
