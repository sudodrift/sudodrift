// Package report renders text and self-contained HTML drift reports.
package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/sudodrift/sudodrift/internal/diff"
	"github.com/sudodrift/sudodrift/internal/snapshot"
)

// Input is everything a report needs.
type Input struct {
	Base, Current *snapshot.Snapshot
	Changes       []diff.Change
	Ignored       int
	ToolVersion   string
	// Generated is the time shown in the HTML report. Zero means now.
	Generated time.Time
}

// WriteText prints a plain-text drift summary.
func WriteText(w io.Writer, in Input) {
	s := diff.Summarize(in.Changes)
	fmt.Fprintf(w, "base:    %s\n", describe(in.Base))
	fmt.Fprintf(w, "current: %s\n", describe(in.Current))
	if in.Base.Hostname != in.Current.Hostname {
		fmt.Fprintf(w, "warning: hostnames differ (%s vs %s)\n", Sanitize(in.Base.Hostname), Sanitize(in.Current.Hostname))
	}
	for _, p := range []struct {
		name string
		s    *snapshot.Snapshot
	}{{"base", in.Base}, {"current", in.Current}} {
		if len(p.s.Warnings) > 0 {
			fmt.Fprintf(w, "note:    %s snapshot is partial (%d warning(s), e.g. unreadable paths); run snapshot as root for full coverage\n", p.name, len(p.s.Warnings))
		}
	}
	if in.Ignored > 0 {
		fmt.Fprintf(w, "ignored: %d change(s) matched the ignore file\n", in.Ignored)
	}
	if s.Total == 0 {
		fmt.Fprintln(w, "\nNo drift detected.")
		return
	}
	fmt.Fprintf(w, "\nDRIFT DETECTED: %d change(s): High %d, Medium %d, Low %d | added %d, removed %d, changed %d\n\n",
		s.Total, s.High, s.Medium, s.Low, s.Added, s.Removed, s.Changed)
	for _, c := range in.Changes {
		fmt.Fprintf(w, "[%-6s] %-7s %-14s %s\n", strings.ToUpper(c.Severity.String()), c.Type, c.Category, Sanitize(c.Message))
	}
}

// Sanitize makes untrusted text (file names, key comments, hostnames) safe to
// print on a terminal by escaping control characters such as ESC.
func Sanitize(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			fmt.Fprintf(&b, "\\x%02x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func describe(s *snapshot.Snapshot) string {
	return fmt.Sprintf("host=%s time=%s hash=%s", Sanitize(s.Hostname), s.Timestamp, shortHash(s.ContentHash))
}

func shortHash(h string) string {
	if len(h) > 19 {
		return h[:19] + "…"
	}
	return h
}

type catCount struct {
	Name  string
	Count int
}

type view struct {
	Generated   string
	ToolVersion string
	Base, Cur   *snapshot.Snapshot
	Sum         diff.Summary
	Cats        []catCount
	Changes     []diff.Change
	Ignored     int
	HostWarn    bool
}

// WriteHTML renders a single self-contained HTML file: inline CSS, no
// scripts, no external assets.
func WriteHTML(w io.Writer, in Input) error {
	gen := in.Generated
	if gen.IsZero() {
		gen = time.Now()
	}
	v := view{
		Generated:   gen.UTC().Format(time.RFC3339),
		ToolVersion: in.ToolVersion,
		Base:        in.Base, Cur: in.Current,
		Sum:      diff.Summarize(in.Changes),
		Changes:  in.Changes,
		Ignored:  in.Ignored,
		HostWarn: in.Base.Hostname != in.Current.Hostname,
	}
	for k, n := range v.Sum.ByCategory {
		v.Cats = append(v.Cats, catCount{k, n})
	}
	sort.Slice(v.Cats, func(i, j int) bool {
		if v.Cats[i].Count != v.Cats[j].Count {
			return v.Cats[i].Count > v.Cats[j].Count
		}
		return v.Cats[i].Name < v.Cats[j].Name
	})
	return tmpl.Execute(w, v)
}

var tmpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"lower": strings.ToLower,
	"sev":   func(s diff.Severity) string { return strings.ToLower(s.String()) },
}).Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>sudodrift report: {{.Cur.Hostname}}</title>
<style>
:root{--bg:#f6f7f9;--fg:#1d2430;--mut:#667085;--card:#fff;--bd:#e2e5ea;
--add:#1a7f37;--addbg:#e9f7ee;--rem:#c62828;--rembg:#fdecec;--chg:#9a6700;--chgbg:#fff6df;
--hi:#c62828;--med:#d97706;--low:#2563eb}
@media(prefers-color-scheme:dark){:root{--bg:#0f141b;--fg:#e6e9ef;--mut:#98a2b3;--card:#171e28;--bd:#2a3342;
--addbg:#12301f;--rembg:#3a1818;--chgbg:#3a2f10;--add:#4ade80;--rem:#f87171;--chg:#fbbf24}}
*{box-sizing:border-box}body{margin:0;padding:24px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto}h1{margin:0 0 4px;font-size:24px}h2{font-size:16px;margin:28px 0 10px}
.sub{color:var(--mut);margin-bottom:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px 14px}
.card .n{font-size:28px;font-weight:700;line-height:1.1}.card .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card.high .n{color:var(--hi)}.card.med .n{color:var(--med)}.card.low .n{color:var(--low)}
.card.add .n{color:var(--add)}.card.rem .n{color:var(--rem)}.card.chg .n{color:var(--chg)}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:700px){.meta{grid-template-columns:1fr}}
.meta .card{font-size:13px}.meta b{display:block;margin-bottom:4px}code{font:12px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:top}
th{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
tr.t-added td:first-child{border-left:4px solid var(--add)}tr.t-added{background:var(--addbg)}
tr.t-removed td:first-child{border-left:4px solid var(--rem)}tr.t-removed{background:var(--rembg)}
tr.t-changed td:first-child{border-left:4px solid var(--chg)}tr.t-changed{background:var(--chgbg)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
.badge.high{background:var(--hi)}.badge.medium{background:var(--med)}.badge.low{background:var(--low)}
.type{font-weight:600}.type.added{color:var(--add)}.type.removed{color:var(--rem)}.type.changed{color:var(--chg)}
.ok{background:var(--addbg);border:1px solid var(--add);color:var(--add);padding:14px;border-radius:8px;font-weight:600}
.warn{background:var(--chgbg);border:1px solid var(--chg);padding:10px 14px;border-radius:8px;margin-bottom:12px}
.cats span{display:inline-block;margin:0 8px 6px 0;padding:2px 10px;border:1px solid var(--bd);border-radius:999px;background:var(--card)}
footer{color:var(--mut);font-size:12px;margin-top:28px}
</style></head><body><div class="wrap">
<h1>sudodrift report</h1>
<div class="sub">Linux permission drift on <b>{{.Cur.Hostname}}</b> · generated {{.Generated}}</div>
{{if .HostWarn}}<div class="warn">Warning: the two snapshots come from different hosts ({{.Base.Hostname}} vs {{.Cur.Hostname}}).</div>{{end}}

<h2>Summary</h2>
<div class="cards">
<div class="card"><div class="n">{{.Sum.Total}}</div><div class="l">Total changes</div></div>
<div class="card high"><div class="n">{{.Sum.High}}</div><div class="l">High</div></div>
<div class="card med"><div class="n">{{.Sum.Medium}}</div><div class="l">Medium</div></div>
<div class="card low"><div class="n">{{.Sum.Low}}</div><div class="l">Low</div></div>
<div class="card add"><div class="n">{{.Sum.Added}}</div><div class="l">Added</div></div>
<div class="card rem"><div class="n">{{.Sum.Removed}}</div><div class="l">Removed</div></div>
<div class="card chg"><div class="n">{{.Sum.Changed}}</div><div class="l">Changed</div></div>
</div>
{{if .Cats}}<div class="cats" style="margin-top:12px">{{range .Cats}}<span>{{.Name}}: <b>{{.Count}}</b></span>{{end}}</div>{{end}}
{{if .Ignored}}<div class="sub">{{.Ignored}} change(s) suppressed by the ignore file.</div>{{end}}

<h2>Snapshots</h2>
<div class="meta">
<div class="card"><b>Base</b>host {{.Base.Hostname}}<br>taken {{.Base.Timestamp}}<br>root <code>{{.Base.Root}}</code><br>hash <code>{{.Base.ContentHash}}</code></div>
<div class="card"><b>Current</b>host {{.Cur.Hostname}}<br>taken {{.Cur.Timestamp}}<br>root <code>{{.Cur.Root}}</code><br>hash <code>{{.Cur.ContentHash}}</code></div>
</div>

<h2>Changes</h2>
{{if .Changes}}
<table><thead><tr><th>Severity</th><th>Change</th><th>Category</th><th>Details</th></tr></thead><tbody>
{{range .Changes}}<tr class="t-{{.Type}}"><td><span class="badge {{sev .Severity}}">{{.Severity}}</span></td>
<td><span class="type {{.Type}}">{{.Type}}</span></td><td>{{.Category}}</td><td>{{.Message}}</td></tr>
{{end}}</tbody></table>
{{else}}<div class="ok">No drift detected between the two snapshots.</div>{{end}}
<footer>Generated by sudodrift {{.ToolVersion}}. Severity is a heuristic, not a verdict: review each change in context.</footer>
</div></body></html>
`))
