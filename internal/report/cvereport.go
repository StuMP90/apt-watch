package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"aptwatch/internal/risk"
)

// CVEReport is the result of aptwatch cve: the status of the given CVEs
// on the host (SPEC §3.1).
type CVEReport struct {
	Schema    int             `json:"schema"`
	Tool      string          `json:"tool"`
	Host      string          `json:"host"`
	Generated time.Time       `json:"generated"`
	Checks    []risk.CVECheck `json:"checks"`
	VulnDB    *VulnDB         `json:"vulndb,omitempty"`
	Warnings  []string        `json:"warnings,omitempty"`
}

var statusLabels = map[string]string{
	risk.StatusUnreachable:   "UNREACHABLE",
	risk.StatusPro:           "NEEDS PRO",
	risk.StatusPending:       "FIX PENDING",
	risk.StatusRebootPending: "REBOOT PENDING",
	risk.StatusNoFix:         "NO FIX YET",
	risk.StatusUnconfirmed:   "UNCONFIRMED",
	risk.StatusUnknown:       "UNKNOWN",
	risk.StatusFixed:         "FIXED",
	risk.StatusNotAffected:   "NOT AFFECTED",
}

func statusLabel(s string) string { return statusLabels[s] }

// statusClass is the colour a status is shown in, by the severity classes.
func statusClass(s string) string {
	switch {
	case s == risk.StatusNoFix || s == risk.StatusUnconfirmed:
		return "medium"
	case risk.NeedsAction(s):
		return "high"
	case s == risk.StatusUnknown:
		return "info"
	}
	return "ok"
}

// Summary is the one-line overview, e.g. "web01: CVE-2026-1234 FIX PENDING"
// or "web01: 3 CVEs checked — 1 FIX PENDING, 2 FIXED".
func (r *CVEReport) Summary() string {
	if len(r.Checks) == 1 {
		c := r.Checks[0]
		return fmt.Sprintf("%s: %s %s", r.Host, c.ID, statusLabel(c.Status))
	}
	counts := map[string]int{}
	var order []string
	for _, c := range r.Checks {
		if counts[c.Status] == 0 {
			order = append(order, c.Status)
		}
		counts[c.Status]++
	}
	slices.SortFunc(order, risk.CompareStatus)
	var parts []string
	for _, s := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[s], statusLabel(s)))
	}
	return fmt.Sprintf("%s: %d CVEs checked — %s", r.Host, len(r.Checks), strings.Join(parts, ", "))
}

// Highest is the status most in need of action.
func (r *CVEReport) Highest() string {
	h := risk.StatusNotAffected
	for _, c := range r.Checks {
		if risk.CompareStatus(c.Status, h) < 0 {
			h = c.Status
		}
	}
	return h
}

func (r *CVEReport) JSON(w io.Writer) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}

// cveMeta is the line of dates and scores under a CVE's heading.
func cveMeta(c risk.CVECheck) []string {
	var m []string
	if c.Priority != "" && c.Priority != "unknown" {
		m = append(m, "priority "+c.Priority)
	}
	if !c.Published.IsZero() {
		m = append(m, "published "+c.Published.Format(time.DateOnly))
	}
	if c.KEV {
		s := "★ known exploited (CISA KEV)"
		if !c.KEVAdded.IsZero() {
			s += " since " + c.KEVAdded.Format(time.DateOnly)
		}
		m = append(m, s)
	}
	if c.EPSS >= 0.01 {
		m = append(m, fmt.Sprintf("EPSS %.0f%%", c.EPSS*100))
	}
	return m
}

// cveVersions is how a package's versions read, e.g. "1.0-1 → 1.0-2".
func cveVersions(p risk.CVEPackage) string {
	if p.Candidate != "" && p.Candidate != p.Installed {
		return p.Installed + " → " + p.Candidate
	}
	return p.Installed
}

// cveVerdict explains a CVE's overall status in a sentence.
func cveVerdict(c risk.CVECheck) string {
	switch c.Status {
	case risk.StatusNotAffected:
		if len(c.NotInstalled) > 0 {
			return "None of the affected packages is installed."
		}
		return "The vulnerability data doesn't list it for this release."
	case risk.StatusUnknown:
		if !c.Known && len(c.Packages) == 0 {
			return "Not in the vulnerability data for this release, nor in any third-party changelog read: " +
				"check the ID, or it may be too new, rejected, or not affect this distribution."
		}
		return "Can't tell for some of the affected packages."
	case risk.StatusFixed:
		return "Fixed in every affected installed package."
	}
	return ""
}

func (r *CVEReport) Text(w io.Writer) error {
	b := &strings.Builder{}
	p := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }

	p("%s\n", r.Summary())
	p("%s\n", strings.Repeat("=", min(len([]rune(r.Summary())), 78)))

	for _, c := range r.Checks {
		p("\n%s  %s\n", c.ID, statusLabel(c.Status))
		if m := cveMeta(c); len(m) > 0 {
			p("  %s\n", strings.Join(m, " · "))
		}
		if c.Desc != "" {
			p("  %s\n", c.Desc)
		}
		if c.URL != "" {
			p("  %s\n", c.URL)
		}
		if v := cveVerdict(c); v != "" {
			p("  %s\n", v)
		}
		if len(c.Packages) > 0 {
			p("\n")
			tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "  Source\tInstalled\tFixed in\tStatus\tRepository\n")
			for _, pk := range c.Packages {
				fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", pk.Source, cveVersions(pk), dash(pk.Fixed), statusLabel(pk.Status), dash(pk.Repo))
			}
			tw.Flush()
			for _, pk := range c.Packages {
				if pk.Note == "" && pk.Command == "" {
					continue
				}
				p("  %s:", pk.Source)
				if pk.Note != "" {
					p(" %s", pk.Note)
				}
				p("\n")
				if pk.Command != "" {
					p("    %s\n", pk.Command)
				}
			}
		}
		if len(c.NotInstalled) > 0 {
			p("  Also affects, not installed: %s\n", strings.Join(c.NotInstalled, ", "))
		}
	}

	p("\nVulnerability data: %s\n", vulnLine(r.VulnDB, r.Generated))
	if len(r.Warnings) > 0 {
		p("\nWarnings\n")
		for _, wn := range r.Warnings {
			p("  ! %s\n", wn)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// HTML writes the report as a self-contained page, like Report.HTML.
func (r *CVEReport) HTML(w io.Writer) error {
	return cveTmpl.Execute(w, r)
}

var cveTmpl = template.Must(template.New("cve").Funcs(template.FuncMap{
	"label":    statusLabel,
	"class":    statusClass,
	"meta":     func(c risk.CVECheck) string { return strings.Join(cveMeta(c), " · ") },
	"verdict":  cveVerdict,
	"versions": cveVersions,
	"vulnLine": func(r *CVEReport) string { return vulnLine(r.VulnDB, r.Generated) },
	"join":     strings.Join,
}).Parse(cveSrc))

const cveSrc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{{.Tool}}">
<title>{{.Summary}}</title>
<style>
` + htmlCSS + `</style>
</head>
<body>
<main>
<div class="top {{class .Highest}}">
<h1>{{.Summary}}</h1>
<div class="muted">{{.Generated.Local.Format "Monday 2 January 2006, 15:04 MST"}}</div>
</div>
{{- range .Checks}}

<h2><span class="mono">{{if .URL}}<a href="{{.URL}}">{{.ID}}</a>{{else}}{{.ID}}{{end}}</span>
<span class="badge {{class .Status}}">{{label .Status}}</span></h2>
{{- with meta .}}
<div class="muted">{{.}}</div>
{{- end}}
{{- if .Desc}}
<p class="detail">{{.Desc}}</p>
{{- end}}
{{- with verdict .}}
<p class="detail">{{.}}</p>
{{- end}}
{{- if .Packages}}
<div class="scroll"><table>
<tr><th>Source</th><th>Installed</th><th>Fixed in</th><th>Status</th><th>Repository</th></tr>
{{- range .Packages}}
<tr><td class="mono">{{.Source}}</td><td class="mono">{{versions .}}</td><td class="mono">{{.Fixed}}</td>
<td><span class="badge {{class .Status}}">{{label .Status}}</span></td><td>{{.Repo}}</td></tr>
{{- if or .Note .Command}}
<tr><td></td><td colspan="4">
{{- if .Note}}<div class="detail">{{.Note}}</div>{{end}}
{{- if .Binaries}}<div class="detail muted">Packages: <span class="mono">{{join .Binaries ", "}}</span></div>{{end}}
{{- if .Command}}<pre>{{.Command}}</pre>{{end}}
</td></tr>
{{- end}}
{{- end}}
</table></div>
{{- end}}
{{- if .NotInstalled}}
<p class="detail muted">Also affects, not installed: <span class="mono">{{join .NotInstalled ", "}}</span></p>
{{- end}}
{{- end}}

<h2>Vulnerability data</h2>
<p>{{vulnLine .}}</p>

{{- if .Warnings}}

<h2>Warnings</h2>
<ul class="warnings">
{{- range .Warnings}}
<li>{{.}}</li>
{{- end}}
</ul>
{{- end}}

<footer class="muted">{{.Tool}} on {{.Host}}</footer>
</main>
</body>
</html>
`
