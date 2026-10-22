package report

import (
	"html/template"
	"io"
	"strings"

	"aptwatch/internal/risk"
)

// HTML writes the full report as a self-contained page: inline CSS, no
// scripts and nothing fetched, so it can be saved, served or mailed as is.
func (r *Report) HTML(w io.Writer) error {
	return htmlTmpl.Execute(w, htmlData{
		R:        r,
		Summary:  r.Summary(),
		Highest:  r.Highest(),
		System:   r.systemRows(),
		Changes:  r.changes(),
		Findings: risk.AtLeast(risk.Active(r.Findings), risk.Low),
		Ignored:  risk.Suppressed(r.Findings),
		Fixed:    r.thirdPartyFixed(),
		Groups:   r.updateGroups(),
		Commands: r.suggestions(),
	})
}

type htmlData struct {
	R        *Report
	Summary  string
	Highest  risk.Severity
	System   []row
	Changes  []change
	Findings []risk.Finding
	Ignored  []risk.Finding
	Fixed    []risk.Finding
	Groups   []updateGroup
	Commands []string
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sev":       func(s risk.Severity) string { return s.String() },
	"when":      func(r *Report, f risk.Finding) string { return r.when(f) },
	"packages":  func(f risk.Finding) string { return strings.Join(packageNames(f.Packages, 8), ", ") },
	"cveTags":   func(c risk.CVERef) string { return strings.Join(cveTags(c), ", ") },
	"installed": installedOrNew,
	"suite":     suite,
	"flags":     updateFlags,
	"lower":     strings.ToLower,
	"ignored":   suppressedLine,
	"expired":   expiredLine,
}).Parse(htmlSrc))

// htmlCSS is the style sheet shared by the HTML pages.
const htmlCSS = `:root {
  --bg: #ffffff; --fg: #1f2328; --muted: #656d76; --line: #d0d7de; --panel: #f6f8fa;
  --link: #0969da;
  --critical: #a40e26; --high: #cf222e; --medium: #9a6700; --low: #0969da; --info: #656d76;
  --ok: #1a7f37;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --fg: #e6edf3; --muted: #8d96a0; --line: #30363d; --panel: #161b22;
    --link: #4493f8;
    --critical: #ff7b72; --high: #f85149; --medium: #d29922; --low: #4493f8; --info: #8d96a0;
    --ok: #3fb950;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 1.35em; margin: 0 0 4px; overflow-wrap: anywhere; }
h2 { font-size: 1.1em; margin: 32px 0 8px; padding-bottom: 4px; border-bottom: 1px solid var(--line); }
h3 { font-size: 1em; margin: 16px 0 6px; }
a { color: var(--link); }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.9em; }
.muted { color: var(--muted); }
.top { border-left: 6px solid var(--info); padding: 4px 0 4px 14px; }
.top.critical { border-color: var(--critical); } .top.high { border-color: var(--high); }
.top.medium { border-color: var(--medium); } .top.low { border-color: var(--low); }
.top.info, .top.ok { border-color: var(--ok); }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; vertical-align: top; padding: 4px 12px 4px 0; border-bottom: 1px solid var(--line); }
th { font-weight: 600; white-space: nowrap; }
table.kv th { width: 7em; color: var(--muted); font-weight: normal; }
.badge { display: inline-block; min-width: 5.5em; padding: 1px 6px; border-radius: 4px; text-align: center;
  font-size: 0.75em; font-weight: 700; letter-spacing: 0.04em; color: #fff; background: var(--info); }
.badge.critical { background: var(--critical); } .badge.high { background: var(--high); }
.badge.medium { background: var(--medium); } .badge.low { background: var(--low); }
.badge.ok { background: var(--ok); }
.tag { font-size: 0.75em; font-weight: 700; letter-spacing: 0.04em; }
.tag.resolved { color: var(--ok); }
ul.findings { list-style: none; margin: 0; padding: 0; }
ul.findings > li { padding: 10px 0; border-bottom: 1px solid var(--line); }
.title { font-weight: 600; overflow-wrap: anywhere; }
.detail { margin: 4px 0 0; overflow-wrap: anywhere; }
ul.cves { margin: 4px 0 0; padding-left: 20px; }
.kev { color: var(--critical); font-weight: 600; }
pre { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px;
  overflow-x: auto; margin: 0; }
ul.warnings { padding-left: 20px; }
footer { margin-top: 40px; font-size: 0.85em; }
`

const htmlSrc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{{.R.Tool}}">
<title>{{.Summary}}</title>
<style>
` + htmlCSS + `</style>
</head>
<body>
<main>
<div class="top {{sev .Highest}}">
<h1>{{.Summary}}</h1>
<div class="muted">{{.R.Generated.Local.Format "Monday 2 January 2006, 15:04 MST"}}</div>
</div>

<h2>System</h2>
<div class="scroll"><table class="kv">
{{- range .System}}
<tr><th>{{.Key}}</th><td>{{range $i, $l := .Lines}}{{if $i}}<br><span class="muted">{{$l}}</span>{{else}}{{$l}}{{end}}{{end}}</td></tr>
{{- end}}
</table></div>

{{- if .Changes}}

<h2>Changes since last run</h2>
<div class="scroll"><table>
{{- range .Changes}}
<tr><td class="tag {{lower .Label}}">{{.Label}}</td><td><span class="badge {{sev .Severity}}">{{.Severity.Label}}</span></td><td>{{.Title}}</td></tr>
{{- end}}
</table></div>
{{- end}}

<h2>Findings ({{len .Findings}})</h2>
{{- if not .Findings}}
<p class="muted">None.</p>
{{- else}}
<ul class="findings">
{{- range .Findings}}
<li>
<span class="badge {{sev .Severity}}">{{.Severity.Label}}</span>
<span class="title">{{.Title}}</span>
{{- with when $.R .}} <span class="muted">— {{.}}</span>{{end}}
{{- if .Detail}}
<p class="detail">{{.Detail}}</p>
{{- end}}
{{- if .Packages}}
<div class="detail muted">Packages: <span class="mono">{{packages .}}</span></div>
{{- end}}
{{- template "cves" .CVEs}}
</li>
{{- end}}
</ul>
{{- end}}

{{- if or .Ignored .R.Expired}}

<h2>Suppressed findings ({{len .Ignored}})</h2>
<ul class="findings">
{{- range .Ignored}}
<li>
<span class="badge {{sev .Severity}}">{{.Severity.Label}}</span>
<span class="title">{{.Title}}</span>
<p class="detail muted">{{ignored .Suppressed}}</p>
</li>
{{- end}}
</ul>
{{- if .R.Expired}}
<ul class="warnings">
{{- range .R.Expired}}
<li>{{expired .}}</li>
{{- end}}
</ul>
{{- end}}
{{- end}}

{{- if .Fixed}}

<h2>Recent CVEs fixed in installed third-party packages</h2>
<ul class="findings">
{{- range .Fixed}}
<li>
<span class="title">{{.Title}}</span>
{{- template "cves" .CVEs}}
</li>
{{- end}}
</ul>
{{- end}}

<h2>Pending updates ({{len .R.Updates}})</h2>
{{- if not .R.Updates}}
<p class="muted">None: up to date.</p>
{{- end}}
{{- range .Groups}}
<h3>{{.Label}} ({{len .Updates}})</h3>
<div class="scroll"><table>
<tr><th>Package</th><th>Installed</th><th>Candidate</th><th>Suite</th><th></th></tr>
{{- range .Updates}}
<tr><td class="mono">{{.Package}}</td><td class="mono">{{installed .}}</td><td class="mono">{{.Candidate}}</td><td>{{suite .}}</td><td>{{range flags .}}<span class="tag">{{.}}</span> {{end}}</td></tr>
{{- end}}
</table></div>
{{- end}}

{{- if .Commands}}

<h2>Suggested commands</h2>
<pre>{{range .Commands}}{{.}}
{{end}}</pre>
{{- end}}

{{- if .R.Warnings}}

<h2>Warnings</h2>
<ul class="warnings">
{{- range .R.Warnings}}
<li>{{.}}</li>
{{- end}}
</ul>
{{- end}}

<footer class="muted">{{.R.Tool}} on {{.R.Host}}</footer>
</main>
</body>
</html>
{{define "cves"}}
{{- if .}}
<ul class="cves">
{{- range $c := .}}
<li><span class="mono">{{if $c.URL}}<a href="{{$c.URL}}">{{$c.ID}}</a>{{else}}{{$c.ID}}{{end}}</span>
{{- with cveTags $c}} <span{{if $c.KEV}} class="kev"{{end}}>({{.}})</span>{{end}}</li>
{{- end}}
</ul>
{{- end}}
{{- end}}
`
