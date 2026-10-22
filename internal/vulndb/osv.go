package vulndb

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"aptwatch/internal/runx"
)

// Canonical's OSV export, all releases in one tarball (SPEC §6.2).
const ubuntuOSVURL = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"

func ubuntuFeed(os OS) advFeed {
	release := os.VersionID
	return advFeed{
		feed:    feed{Name: "osv-ubuntu.tar.xz", URL: ubuntuOSVURL},
		Release: release,
		parse: func(ctx context.Context, r io.Reader) (map[string][]Advisory, error) {
			return parseOSVTarXZ(ctx, r, release)
		},
	}
}

// parseOSVTarXZ unpacks the tarball through xz(1), streaming: it is about
// 50 MB packed and 11 GB unpacked.
func parseOSVTarXZ(ctx context.Context, r io.Reader, release string) (map[string][]Advisory, error) {
	xz, err := runx.LookPath("xz")
	if err != nil {
		return nil, fmt.Errorf("%w (install xz-utils)", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, xz, "-dc", "-T0")
	cmd.Env = []string{"PATH=" + runx.Path, "LC_ALL=C"}
	cmd.Stdin = r
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	adv, perr := parseOSVTar(out, release)
	if perr != nil {
		cancel()
	}
	werr := cmd.Wait()
	if perr != nil {
		// A parse error from truncated output hides xz's own complaint,
		// such as a download that isn't xz at all.
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("xz: %s", msg)
		}
		return nil, perr
	}
	if werr != nil {
		return nil, fmt.Errorf("xz: %v: %s", werr, strings.TrimSpace(stderr.String()))
	}
	return adv, nil
}

// parseOSVTar reads the CVE records (osv/cve/...) from the tar stream and
// returns the advisories for one Ubuntu release, by source package.
func parseOSVTar(r io.Reader, release string) (map[string][]Advisory, error) {
	std := []byte(`"Ubuntu:` + release)
	pro := []byte(`"Ubuntu:Pro:` + release)
	out := map[string][]Advisory{}
	tr := tar.NewReader(r)
	records := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("osv tarball: %w", err)
		}
		if h.Typeflag != tar.TypeReg || !strings.Contains("/"+h.Name, "/cve/") || !strings.HasSuffix(h.Name, ".json") {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			return nil, fmt.Errorf("osv tarball: %s: %w", h.Name, err)
		}
		records++
		// Most records don't mention this release: skip them unparsed.
		if !bytes.Contains(b, std) && !bytes.Contains(b, pro) {
			continue
		}
		if err := addOSVRecord(out, b, release); err != nil {
			return nil, fmt.Errorf("osv tarball: %s: %w", h.Name, err)
		}
	}
	if records == 0 {
		return nil, errors.New("osv tarball: no CVE records")
	}
	for src, as := range out {
		out[src] = mergeAdvisories(as)
	}
	return out, nil
}

type osvRecord struct {
	ID        string   `json:"id"`
	Upstream  []string `json:"upstream"`
	Withdrawn string   `json:"withdrawn"`
	Published string   `json:"published"`
	Details   string   `json:"details"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Availability string `json:"availability"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

func addOSVRecord(out map[string][]Advisory, b []byte, release string) error {
	var rec osvRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return err
	}
	if rec.Withdrawn != "" {
		return nil
	}
	cve := ""
	for _, u := range rec.Upstream {
		if strings.HasPrefix(u, "CVE-") {
			cve = u
			break
		}
	}
	if cve == "" {
		cve = strings.TrimPrefix(rec.ID, "UBUNTU-")
	}
	if !strings.HasPrefix(cve, "CVE-") {
		return nil
	}
	prio := "unknown"
	for _, s := range rec.Severity {
		if s.Type == "Ubuntu" {
			prio = NormPriority(s.Score)
		}
	}
	desc := shorten(rec.Details, 200)
	pub, _ := time.Parse(time.RFC3339, rec.Published)
	for _, a := range rec.Affected {
		// Standard and Pro (ESM) only: FIPS, Realtime and other
		// variants are separate products with their own packages.
		var isPro bool
		switch a.Package.Ecosystem {
		case "Ubuntu:" + release, "Ubuntu:" + release + ":LTS":
		case "Ubuntu:Pro:" + release + ":LTS":
			isPro = true
		default:
			continue
		}
		fixed := ""
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if v := ev["fixed"]; v != "" && fixed == "" {
					fixed = v
				}
			}
		}
		if strings.Contains(a.EcosystemSpecific.Availability, "Ubuntu Pro") {
			isPro = true
		}
		out[a.Package.Name] = append(out[a.Package.Name], Advisory{
			CVE: cve, Fixed: fixed, Priority: prio, Pro: isPro && fixed != "", Desc: desc, Published: pub,
		})
	}
	return nil
}
