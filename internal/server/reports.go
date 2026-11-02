package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// Reports: a page for a person, not a stream for a machine.
//
// Everything in mustra is already exportable, which is a different thing.
// Connect answers "send these rows to my SIEM"; this answers "the person
// who signs off on patching wants one page a week and does not have a
// console login". Same data, same sources — the difference is that a
// report has sections, rolls counts up, and carries the date it was true.
//
// Two decisions worth naming. Renderings are stored rather than
// regenerated: the point of a monthly report is to be able to say what the
// fleet looked like on the first, and re-running today's query against
// today's data answers a different question. And a webhook gets the text
// digest rather than the document, because a Discord channel is not a place
// to paste eight hundred lines of HTML.

const (
	// defaultSectionLimit caps rows in a table section. A report is meant
	// to be read; four hundred rows is an export wearing a report's hat.
	defaultSectionLimit = 25
	maxSectionLimit     = 500
	// maxRenderedReport caps the stored document, because a section over a
	// large fleet can produce more HTML than anybody will ever scroll.
	maxRenderedReport = 512 * 1024
)

// reportSection is one block of a report.
type reportSection struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Note            string `json:"note,omitempty"`
	Source          string `json:"source"`
	SavedQuestionID string `json:"saved_question_id,omitempty"`

	// GroupBy turns a list into a count: "12 Windows, 24 Debian" instead of
	// thirty-six rows. This is most of what makes a report a report.
	GroupBy string `json:"group_by,omitempty"`

	// Columns picks what a table section shows. Empty means the first few
	// the data happens to have, which is right for a quick section and
	// wrong for one somebody reads every week.
	Columns []string `json:"columns,omitempty"`
	Limit   int      `json:"limit,omitempty"`

	// A deliberately small filter: one column, one substring, optionally
	// negated with a leading "!". Anything more expressive belongs in a
	// saved question, which is a real query language and already exists.
	FilterColumn string `json:"filter_column,omitempty"`
	FilterValue  string `json:"filter_value,omitempty"`
}

type renderedSection struct {
	Title   string
	Rows    int
	Shown   int
	Summary []aggregateRow
	HTML    string
	Err     string
}

type aggregateRow struct {
	Label string
	Count int
	Share float64
}

// --- data -------------------------------------------------------------

// sectionRows fetches one section's data. It reuses Connect's sources
// wholesale, with the cursor deliberately blank: an export sends what is
// new since last time, and a report that did that would describe the week
// as empty because nothing changed since Tuesday.
func (s *Server) sectionRows(ctx context.Context, sec reportSection) ([]map[string]any, error) {
	rows, err := exportRowsMemo(ctx, sec.Source, sec.SavedQuestionID, func() ([]map[string]any, error) {
		rows, _, err := s.runExport(ctx, store.ExportConfig{
			Source: sec.Source, SavedQuestionID: sec.SavedQuestionID,
		})
		return rows, err
	})
	if err != nil {
		return nil, err
	}
	return filterRows(rows, sec.FilterColumn, sec.FilterValue), nil
}

// exportMemo lets the panels of one dashboard (or the sections of one
// report) that read the same source share one read of it. The built-in
// Fleet overview is six panels over "endpoints" and Security posture three
// over "patches"; each read decodes every endpoint's cached snapshot, so a
// dashboard view cost six fleet-wide decodes where one gives the same
// answer. Scoped to a single render, so nothing is ever served stale:
// rows are only read after this point (filterRows builds a new slice).
type exportMemo struct {
	mu   sync.Mutex
	rows map[[2]string][]map[string]any
}

type exportMemoKey struct{}

// withExportMemo returns ctx carrying a fresh memo for one render.
func withExportMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, exportMemoKey{}, &exportMemo{rows: map[[2]string][]map[string]any{}})
}

// exportRowsMemo returns the memoized rows of (source, question) when ctx
// carries a memo, computing them once; without one it just computes.
func exportRowsMemo(ctx context.Context, source, question string, compute func() ([]map[string]any, error)) ([]map[string]any, error) {
	m, _ := ctx.Value(exportMemoKey{}).(*exportMemo)
	if m == nil {
		return compute()
	}
	key := [2]string{source, question}
	m.mu.Lock()
	defer m.mu.Unlock()
	if rows, ok := m.rows[key]; ok {
		return rows, nil
	}
	rows, err := compute()
	if err != nil {
		return nil, err // not memoized: the next section tries again
	}
	m.rows[key] = rows
	return rows, nil
}

// filterRows keeps the rows whose column contains the value, or — with a
// leading "!" — those that do not. Case-insensitive, because "Fail" and
// "fail" being different answers is nobody's intent.
func filterRows(rows []map[string]any, column, value string) []map[string]any {
	column = strings.TrimSpace(column)
	value = strings.TrimSpace(value)
	if column == "" || value == "" {
		return rows
	}
	negate := strings.HasPrefix(value, "!")
	needle := strings.ToLower(strings.TrimPrefix(value, "!"))
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		hit := strings.Contains(strings.ToLower(stringify(r[column])), needle)
		if hit != negate {
			out = append(out, r)
		}
	}
	return out
}

// aggregate counts rows by one column, biggest first. A blank value is
// reported as "(not set)" rather than silently folded into another bucket
// or dropped — "how many endpoints have no site" is a real question and
// usually an unwelcome answer.
func aggregate(rows []map[string]any, column string) []aggregateRow {
	counts := map[string]int{}
	for _, r := range rows {
		label := strings.TrimSpace(stringify(r[column]))
		if label == "" {
			label = "(not set)"
		}
		counts[label]++
	}
	out := make([]aggregateRow, 0, len(counts))
	for label, n := range counts {
		share := 0.0
		if len(rows) > 0 {
			share = float64(n) * 100 / float64(len(rows))
		}
		out = append(out, aggregateRow{Label: label, Count: n, Share: share})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func sectionLimit(sec reportSection) int {
	if sec.Limit <= 0 {
		return defaultSectionLimit
	}
	if sec.Limit > maxSectionLimit {
		return maxSectionLimit
	}
	return sec.Limit
}

// --- rendering --------------------------------------------------------

func esc(s string) string { return html.EscapeString(s) }

func (s *Server) renderSection(ctx context.Context, sec reportSection) renderedSection {
	title := strings.TrimSpace(sec.Title)
	if title == "" {
		title = sec.Source
	}
	out := renderedSection{Title: title}

	rows, err := s.sectionRows(ctx, sec)
	if err != nil {
		// A section that cannot be built says so in the document. Dropping
		// it would produce a report that looks complete and is not, which
		// is the one thing a report must never do.
		out.Err = err.Error()
		out.HTML = fmt.Sprintf(`<section class="rpt-section"><h2>%s</h2>`+
			`<p class="rpt-error">This section could not be built: %s</p></section>`,
			esc(title), esc(err.Error()))
		return out
	}
	out.Rows = len(rows)

	var body strings.Builder
	fmt.Fprintf(&body, `<section class="rpt-section"><h2>%s</h2>`, esc(title))
	if strings.TrimSpace(sec.Note) != "" {
		fmt.Fprintf(&body, `<p class="rpt-note">%s</p>`, esc(sec.Note))
	}
	meta := fmt.Sprintf("%d row%s from %s", len(rows), plural(len(rows)), sec.Source)
	if sec.FilterColumn != "" && sec.FilterValue != "" {
		meta += fmt.Sprintf(", where %s %s %q", sec.FilterColumn,
			map[bool]string{true: "does not contain", false: "contains"}[strings.HasPrefix(sec.FilterValue, "!")],
			strings.TrimPrefix(sec.FilterValue, "!"))
	}
	fmt.Fprintf(&body, `<p class="rpt-meta">%s</p>`, esc(meta))

	switch {
	case len(rows) == 0:
		body.WriteString(`<p class="rpt-empty">Nothing matched.</p>`)
	case sec.GroupBy != "":
		out.Summary = aggregate(rows, sec.GroupBy)
		shown := out.Summary
		if limit := sectionLimit(sec); len(shown) > limit {
			shown = shown[:limit]
		}
		out.Shown = len(shown)
		body.WriteString(`<table><thead><tr><th>` + esc(sec.GroupBy) +
			`</th><th class="num">Count</th><th class="num">Share</th></tr></thead><tbody>`)
		for _, a := range shown {
			fmt.Fprintf(&body, `<tr><td>%s</td><td class="num">%d</td><td class="num">%.0f%%</td></tr>`,
				esc(a.Label), a.Count, a.Share)
		}
		body.WriteString(`</tbody></table>`)
		if len(out.Summary) > len(shown) {
			fmt.Fprintf(&body, `<p class="rpt-more">… and %d more.</p>`, len(out.Summary)-len(shown))
		}
	default:
		cols := sec.Columns
		if len(cols) == 0 {
			cols = columnsOf(rows)
			if len(cols) > 6 {
				cols = cols[:6]
			}
		}
		limit := sectionLimit(sec)
		shown := rows
		if len(shown) > limit {
			shown = shown[:limit]
		}
		out.Shown = len(shown)
		body.WriteString(`<table><thead><tr>`)
		for _, c := range cols {
			body.WriteString(`<th>` + esc(c) + `</th>`)
		}
		body.WriteString(`</tr></thead><tbody>`)
		for _, r := range shown {
			body.WriteString(`<tr>`)
			for _, c := range cols {
				body.WriteString(`<td>` + esc(stringify(r[c])) + `</td>`)
			}
			body.WriteString(`</tr>`)
		}
		body.WriteString(`</tbody></table>`)
		if len(rows) > len(shown) {
			fmt.Fprintf(&body, `<p class="rpt-more">… and %d more.</p>`, len(rows)-len(shown))
		}
	}
	body.WriteString(`</section>`)
	out.HTML = body.String()
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

type renderedReport struct {
	// Generated is the moment the document's stamp names, to the
	// microsecond Postgres keeps, so the stored run says the same.
	Generated time.Time
	HTML      string
	Summary   string
	Rows      int
	Sections  int
	Failed    int
}

func (s *Server) renderReport(ctx context.Context, rep store.Report, sections []reportSection) renderedReport {
	ctx = withExportMemo(ctx)
	generated := time.Now().UTC().Truncate(time.Microsecond)
	var body strings.Builder
	fmt.Fprintf(&body, `<div class="rpt"><header class="rpt-head"><h1>%s</h1>`, esc(rep.Name))
	if strings.TrimSpace(rep.Description) != "" {
		fmt.Fprintf(&body, `<p class="rpt-desc">%s</p>`, esc(rep.Description))
	}
	fmt.Fprintf(&body, `<p class="rpt-stamp">Generated %s from mustra's cached fleet data.</p></header>`,
		esc(generated.Format("2 January 2006, 15:04 MST")))

	var summary strings.Builder
	fmt.Fprintf(&summary, "%s — %s\n", rep.Name, generated.Format("2 Jan 2006 15:04 MST"))

	out := renderedReport{Generated: generated, Sections: len(sections)}
	for _, sec := range sections {
		r := s.renderSection(ctx, sec)
		body.WriteString(r.HTML)
		out.Rows += r.Rows
		if r.Err != "" {
			out.Failed++
			fmt.Fprintf(&summary, "\n%s: could not be built (%s)", r.Title, r.Err)
			continue
		}
		fmt.Fprintf(&summary, "\n%s: %d row%s", r.Title, r.Rows, plural(r.Rows))
		// The digest carries the top of an aggregate, because "24 Debian,
		// 12 Windows" is the whole answer for most grouped sections and
		// sending only a row count would waste the message.
		for i, a := range r.Summary {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&summary, "\n  %s: %d (%.0f%%)", a.Label, a.Count, a.Share)
		}
	}
	body.WriteString(`</div>`)

	out.HTML = body.String()
	if len(out.HTML) > maxRenderedReport {
		// Cut at a section boundary rather than a byte offset: slicing
		// mid-tag left an unclosed table that the download served as a
		// standalone document, and slicing mid-rune produced invalid UTF-8.
		cut := out.HTML[:maxRenderedReport]
		if i := strings.LastIndex(cut, "</section>"); i > 0 {
			cut = cut[:i+len("</section>")]
		} else {
			for len(cut) > 0 && !utf8.ValidString(cut) {
				cut = cut[:len(cut)-1]
			}
		}
		out.HTML = cut +
			`<p class="rpt-more">… this rendering was truncated; narrow a section's rows or columns.</p></div>`
	}
	out.Summary = summary.String()
	return out
}

// reportDocument wraps a rendering in a standalone HTML file — the thing
// written to disk or downloaded. Styles are inlined because this leaves
// mustra: a file that needs the console's stylesheet to be readable is a
// file that stops being readable the moment it is emailed on.
func reportDocument(name, fragment string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<title>` + esc(name) + `</title><style>
body { font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       color: #1c2024; background: #fff; margin: 0; padding: 32px 24px; }
.rpt { max-width: 900px; margin: 0 auto; }
.rpt-head h1 { font-size: 24px; margin: 0 0 6px; }
.rpt-desc { margin: 0 0 6px; color: #444; }
.rpt-stamp { margin: 0 0 26px; color: #777; font-size: 12.5px; }
.rpt-section { margin-bottom: 30px; }
.rpt-section h2 { font-size: 16px; margin: 0 0 6px; border-bottom: 2px solid #e6e8eb; padding-bottom: 6px; }
.rpt-note { margin: 6px 0; color: #444; font-size: 13.5px; }
.rpt-meta { margin: 4px 0 10px; color: #777; font-size: 12px; }
.rpt-empty, .rpt-more { color: #777; font-size: 12.5px; }
.rpt-error { color: #b3261e; font-size: 13px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eceef0; vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #666; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
tr:last-child td { border-bottom: none; }
</style></head><body>` + fragment + `</body></html>`
}

// --- running ----------------------------------------------------------

func (s *Server) runReport(ctx context.Context, rep store.Report, who string, preview bool) (*store.ReportRun, error) {
	var sections []reportSection
	if err := json.Unmarshal(rep.Sections, &sections); err != nil || len(sections) == 0 {
		return nil, fmt.Errorf("this report has no usable sections")
	}
	rendered := s.renderReport(ctx, rep, sections)

	run := store.ReportRun{
		ID: idgen.New("rpt-"), ReportID: rep.ID, Name: rep.Name, GeneratedAt: rendered.Generated, GeneratedBy: who,
		SectionCount: rendered.Sections, RowCount: rendered.Rows,
		HTML: rendered.HTML, Summary: rendered.Summary, Preview: preview,
	}
	if rendered.Failed > 0 {
		run.Error = fmt.Sprintf("%d of %d sections could not be built",
			rendered.Failed, rendered.Sections)
	}

	if rep.Destination != "" {
		if err := s.deliverReport(ctx, rep, rendered); err != nil {
			s.logger.Warn("report delivery failed", "report", rep.Name, "error", err)
			run.Error = strings.TrimSpace(run.Error + " · delivery failed: " + err.Error())
		} else {
			run.Delivered = true
		}
	}
	if err := s.store.SaveReportRun(ctx, run); err != nil {
		return nil, err
	}
	s.logger.Info("report generated", "report", rep.Name, "sections", rendered.Sections,
		"rows", rendered.Rows, "delivered", run.Delivered, "by", who)
	return &run, nil
}

// deliverReport sends the document where it was asked to go. A webhook
// receives the text digest: a Discord channel is not a place to paste
// eight hundred lines of HTML, and the digest is what somebody reads on a
// phone anyway.
func (s *Server) deliverReport(ctx context.Context, rep store.Report, rendered renderedReport) error {
	cfg := store.ExportConfig{
		Source: "report", Destination: rep.Destination,
		Target: rep.Target, WebhookStyle: rep.WebhookStyle,
	}
	switch rep.Destination {
	case "file":
		return deliverFileAs(cfg, []byte(reportDocument(rep.Name, rendered.HTML)), "html")
	case "webhook", "syslog":
		return s.deliver(ctx, cfg, []byte(rendered.Summary), "text/plain; charset=utf-8")
	default:
		return fmt.Errorf("unknown destination %q", rep.Destination)
	}
}

func (s *Server) reportSchedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDueReports(ctx)
		}
	}
}

func (s *Server) runDueReports(ctx context.Context) {
	due, err := s.store.DueReports(ctx, time.Now().UTC())
	if err != nil {
		s.logger.Warn("reports: could not check for due runs", "error", err)
		return
	}
	for _, rep := range due {
		// The next slot is booked before the work, so a report that fails
		// does not stay due and run again every minute.
		next, err := computeNextRun(rep.ScheduleKind, rep.TimeOfDay, rep.Weekday, time.Now().UTC())
		if err != nil {
			s.logger.Warn("reports: bad schedule", "report", rep.Name, "error", err)
			next = nil
		}
		// Booked before the work, matching runDuePlaybooks. Marking
		// afterwards meant a restart mid-render left next_run_at in the
		// past, so the report re-ran and re-delivered on startup.
		if err := s.store.MarkReportRun(ctx, rep.ID, time.Now().UTC(), next, ""); err != nil {
			s.logger.Warn("reports: could not update the schedule", "report", rep.Name, "error", err)
		}
		run, runErr := s.runReport(ctx, rep, "scheduler", false)
		errText := ""
		if runErr != nil {
			errText = runErr.Error()
		} else if run != nil {
			errText = run.Error
		}
		if errText != "" {
			if err := s.store.MarkReportRun(ctx, rep.ID, time.Now().UTC(), next, errText); err != nil {
				s.logger.Warn("reports: could not record the failure", "report", rep.Name, "error", err)
			}
		}
	}
}
