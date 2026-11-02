package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// Dashboards: user-authored panels over the same sources Reports and
// Connect read — a saved question, or a module's export — drawn as a
// number, a donut, bars, a stacked bar, an area over time, or a table.
//
// A panel is a report section plus a chart. That is deliberate: the
// filtering, grouping and limits a report section already has are exactly
// what a panel needs, and one evaluation path means a number on Home and
// the same number in Monday's report cannot disagree.
//
// History is sampled, not recomputed: every quarter hour each panel's
// count (and its series) is written to panel_samples, which is what an
// area panel and a "last 30 days" view are drawn from. Alerts are
// thresholds on a panel's count or on one slice's share, evaluated with
// the Guide and surfaced there while they hold.

const (
	dashboardSampleEvery = 15 * time.Minute
	dashboardSampleKeep  = 100 * 24 * time.Hour
	maxDashboardPanels   = 24
)

// dashboardPanel is one panel. It embeds a report section for the data
// half; the rest says how to draw it.
type dashboardPanel struct {
	reportSection
	// Chart is number | donut | bar | stacked | area | table | text.
	Chart string `json:"chart"`
	// SeriesBy is the second grouping of a stacked bar: bars by GroupBy,
	// segments by SeriesBy.
	SeriesBy string `json:"series_by,omitempty"`
	// GroupIDs restricts the panel to endpoints in these computer groups
	// (rows without an agent id pass through untouched).
	GroupIDs []string `json:"group_ids,omitempty"`
	// Text is a text panel's body; a line that is just a URL path
	// ("/interact", "/playbooks#pb-1") is rendered as a link.
	Text string `json:"text,omitempty"`
	// Highlight marks the panel when its count crosses a threshold:
	// conditional formatting, the thing Home's "highlights only" filter
	// keys on.
	Highlight *panelThreshold `json:"highlight,omitempty"`
	// Width is 1 (a third), 2 (two thirds) or 3 (full).
	Width int `json:"width,omitempty"`
}

// panelThreshold is a comparison against a panel's count, or against one
// slice's share when Label is set (Percent then compares 0-100).
type panelThreshold struct {
	Op      string  `json:"op"` // gt | gte | lt | lte | eq | zero | nonzero
	Value   float64 `json:"value"`
	Label   string  `json:"label,omitempty"`
	Percent bool    `json:"percent,omitempty"`
}

// panelData is what a panel evaluates to.
type panelData struct {
	ID        string          `json:"id"`
	Chart     string          `json:"chart"`
	Title     string          `json:"title"`
	Count     int             `json:"count"`
	Total     int             `json:"total"`
	Series    []seriesPoint   `json:"series,omitempty"`
	Stacked   []stackedBar    `json:"stacked,omitempty"`
	Columns   []string        `json:"columns,omitempty"`
	Rows      [][]string      `json:"rows,omitempty"`
	History   []historyPoint  `json:"history,omitempty"`
	Text      string          `json:"text,omitempty"`
	Highlight bool            `json:"highlight"`
	Error     string          `json:"error,omitempty"`
	Width     int             `json:"width"`
	Source    json.RawMessage `json:"-"`

	// The three below travel with the evaluated panel so the console can
	// link a mark to the rows behind it — a slice labelled "linux" becomes
	// a query for the endpoints that make it up. Without them the panel is
	// a picture with nothing to click, which is what shipped first: the
	// console had the drill-down and the data never carried what it needed.
	DrillSource   string `json:"source,omitempty"`
	DrillGroupBy  string `json:"group_by,omitempty"`
	DrillSeriesBy string `json:"series_by,omitempty"`
	// The panel's own filter, so an ungrouped number links to the endpoints
	// it counted rather than to all of them: "Online now" is 40 of 41.
	DrillFilterColumn string `json:"filter_column,omitempty"`
	DrillFilterValue  string `json:"filter_value,omitempty"`
}

type seriesPoint struct {
	// Label is for a person; Key is the value the row actually held. A
	// drill-down link is built from Key, because "Windows Server 2025
	// Standard" matches no endpoint and the string it was made from does.
	// Key is omitted when it equals Label, which is most columns.
	Label string  `json:"label"`
	Key   string  `json:"key,omitempty"`
	Value int     `json:"value"`
	Share float64 `json:"share"`
}

type stackedBar struct {
	Label string        `json:"label"`
	Key   string        `json:"key,omitempty"`
	Total int           `json:"total"`
	Parts []seriesPoint `json:"parts"`
}

type historyPoint struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

func decodePanels(raw json.RawMessage) ([]dashboardPanel, error) {
	var panels []dashboardPanel
	if len(raw) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(raw, &panels); err != nil {
		return nil, fmt.Errorf("panels: %w", err)
	}
	return panels, nil
}

// validatePanels fills ids and defaults and rejects what cannot be drawn.
func (s *Server) validatePanels(ctx context.Context, panels []dashboardPanel) ([]dashboardPanel, error) {
	if len(panels) > maxDashboardPanels {
		return nil, fmt.Errorf("a dashboard holds at most %d panels", maxDashboardPanels)
	}
	known := map[string]bool{}
	for _, src := range reportSourceCatalog {
		known[src["id"]] = true
	}
	out := make([]dashboardPanel, 0, len(panels))
	for i, p := range panels {
		if p.ID == "" {
			p.ID = idgen.New("pn-")
		}
		p.Title = strings.TrimSpace(p.Title)
		if p.Title == "" {
			p.Title = fmt.Sprintf("Panel %d", i+1)
		}
		switch p.Chart {
		case "number", "donut", "bar", "stacked", "area", "table", "text":
		case "":
			p.Chart = "number"
		default:
			return nil, fmt.Errorf("panel %q: unknown chart %q", p.Title, p.Chart)
		}
		if p.Width < 1 || p.Width > 3 {
			p.Width = 1
			if p.Chart == "table" || p.Chart == "stacked" || p.Chart == "area" {
				p.Width = 2
			}
		}
		if p.Chart != "text" {
			if !known[p.Source] {
				return nil, fmt.Errorf("panel %q: unknown source %q", p.Title, p.Source)
			}
			if p.Source == "question" {
				if p.SavedQuestionID == "" {
					return nil, fmt.Errorf("panel %q: pick a saved question", p.Title)
				}
				q, err := s.store.GetSavedQuestion(ctx, p.SavedQuestionID)
				if err != nil {
					return nil, err
				}
				if q == nil {
					return nil, fmt.Errorf("panel %q: that saved question no longer exists", p.Title)
				}
			}
			if (p.Chart == "donut" || p.Chart == "bar" || p.Chart == "stacked") && strings.TrimSpace(p.GroupBy) == "" {
				return nil, fmt.Errorf("panel %q: a %s needs a group-by column", p.Title, p.Chart)
			}
			if p.Chart == "stacked" && strings.TrimSpace(p.SeriesBy) == "" {
				return nil, fmt.Errorf("panel %q: a stacked bar needs a series-by column", p.Title)
			}
		}
		if p.Highlight != nil && !validThresholdOp(p.Highlight.Op) {
			return nil, fmt.Errorf("panel %q: unknown highlight condition %q", p.Title, p.Highlight.Op)
		}
		out = append(out, p)
	}
	return out, nil
}

func validThresholdOp(op string) bool {
	switch op {
	case "gt", "gte", "lt", "lte", "eq", "zero", "nonzero":
		return true
	}
	return false
}

// evaluatePanel produces the data for one panel. groupIDs (from the
// viewer's Home filter) narrows on top of the panel's own groups.
func (s *Server) evaluatePanel(ctx context.Context, dashboardID string, p dashboardPanel, groupIDs []string, window time.Duration) panelData {
	d := panelData{
		ID: p.ID, Chart: p.Chart, Title: p.Title, Width: p.Width,
		DrillSource: p.Source, DrillGroupBy: p.GroupBy, DrillSeriesBy: p.SeriesBy,
		DrillFilterColumn: p.FilterColumn, DrillFilterValue: p.FilterValue,
	}
	if d.Width == 0 {
		d.Width = 1
	}
	if p.Chart == "text" {
		d.Text = p.Text
		return d
	}
	rows, err := s.sectionRows(ctx, p.reportSection)
	if err != nil {
		d.Error = err.Error()
		return d
	}
	if len(p.GroupIDs) > 0 || len(groupIDs) > 0 {
		rows, err = s.rowsInGroups(ctx, rows, append(append([]string{}, p.GroupIDs...), groupIDs...))
		if err != nil {
			d.Error = err.Error()
			return d
		}
	}
	d.Count = len(rows)
	d.Total = len(rows)
	switch p.Chart {
	case "donut", "bar":
		for _, a := range aggregate(rows, p.GroupBy) {
			d.Series = append(d.Series, newSeriesPoint(p.GroupBy, a.Label, a.Count, a.Share))
		}
		d.Series = foldSeries(d.Series, 8, d.Total)
	case "stacked":
		d.Stacked = stack(rows, p.GroupBy, p.SeriesBy)
	case "table":
		cols := p.Columns
		if len(cols) == 0 {
			cols = firstColumns(rows, 5)
		}
		d.Columns = cols
		limit := sectionLimit(p.reportSection)
		for i, r := range rows {
			if i >= limit {
				break
			}
			vals := make([]string, len(cols))
			for j, c := range cols {
				vals[j] = stringify(r[c])
			}
			d.Rows = append(d.Rows, vals)
		}
	case "area":
		if window <= 0 {
			window = 30 * 24 * time.Hour
		}
		samples, err := s.store.ListPanelSamples(ctx, dashboardID, p.ID, time.Now().Add(-window))
		if err != nil {
			d.Error = err.Error()
		}
		for _, sm := range samples {
			d.History = append(d.History, historyPoint{At: sm.At, Value: sm.Value})
		}
		// The live value is the newest point, so a fresh panel is not empty.
		d.History = append(d.History, historyPoint{At: time.Now(), Value: float64(d.Count)})
	}
	if p.Highlight != nil {
		d.Highlight = thresholdHolds(*p.Highlight, d)
	}
	return d
}

// foldSeries keeps the first max-1 slices and folds the rest into
// "Other": a categorical palette has eight slots, and a ninth hue is never
// generated.
func foldSeries(in []seriesPoint, max int, total int) []seriesPoint {
	if len(in) <= max {
		return in
	}
	out := append([]seriesPoint{}, in[:max-1]...)
	other := seriesPoint{Label: "Other"}
	for _, p := range in[max-1:] {
		other.Value += p.Value
	}
	if total > 0 {
		other.Share = float64(other.Value) * 100 / float64(total)
	}
	return append(out, other)
}

func stack(rows []map[string]any, by, seriesBy string) []stackedBar {
	bars := map[string]*stackedBar{}
	var order []string
	seriesOrder := map[string]int{}
	for _, r := range rows {
		bl := strings.TrimSpace(stringify(r[by]))
		if bl == "" {
			bl = notSetLabel
		}
		sl := strings.TrimSpace(stringify(r[seriesBy]))
		if sl == "" {
			sl = notSetLabel
		}
		b := bars[bl]
		if b == nil {
			b = &stackedBar{Label: displayLabel(by, bl), Key: rawKey(by, bl)}
			bars[bl] = b
			order = append(order, bl)
		}
		b.Total++
		found := false
		for i := range b.Parts {
			if seriesKey(b.Parts[i]) == sl {
				b.Parts[i].Value++
				found = true
				break
			}
		}
		if !found {
			b.Parts = append(b.Parts, newSeriesPoint(seriesBy, sl, 1, 0))
		}
		if _, ok := seriesOrder[sl]; !ok {
			seriesOrder[sl] = len(seriesOrder)
		}
	}
	out := make([]stackedBar, 0, len(order))
	for _, l := range order {
		b := bars[l]
		// Segments in one fixed order across every bar, so a colour means
		// the same thing in each.
		sort.Slice(b.Parts, func(i, j int) bool { return seriesOrder[seriesKey(b.Parts[i])] < seriesOrder[seriesKey(b.Parts[j])] })
		for i := range b.Parts {
			b.Parts[i].Share = float64(b.Parts[i].Value) * 100 / float64(b.Total)
		}
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Label < out[j].Label
	})
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func firstColumns(rows []map[string]any, n int) []string {
	if len(rows) == 0 {
		return nil
	}
	keys := make([]string, 0, len(rows[0]))
	for k := range rows[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// hostname first when there is one: a table of endpoints without the
	// endpoint is a puzzle.
	for i, k := range keys {
		if k == "hostname" {
			keys = append([]string{k}, append(keys[:i:i], keys[i+1:]...)...)
			break
		}
	}
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

// rowsInGroups keeps rows whose agent_id is in any of the groups. Rows
// with no agent id (a deployment, a question-history line) pass through.
func (s *Server) rowsInGroups(ctx context.Context, rows []map[string]any, groupIDs []string) ([]map[string]any, error) {
	members, err := s.agentsInGroups(ctx, groupIDs)
	if err != nil {
		return nil, err
	}
	out := rows[:0:0]
	for _, r := range rows {
		id := stringify(r["agent_id"])
		if id == "" || members[id] {
			out = append(out, r)
		}
	}
	return out, nil
}

// thresholdHolds evaluates a threshold against evaluated panel data.
func thresholdHolds(t panelThreshold, d panelData) bool {
	v := float64(d.Count)
	if t.Label != "" {
		v = 0
		for _, sp := range d.Series {
			if strings.EqualFold(sp.Label, t.Label) {
				if t.Percent {
					v = sp.Share
				} else {
					v = float64(sp.Value)
				}
			}
		}
		for _, b := range d.Stacked {
			for _, sp := range b.Parts {
				if strings.EqualFold(sp.Label, t.Label) {
					v += float64(sp.Value)
				}
			}
		}
	}
	switch t.Op {
	case "gt":
		return v > t.Value
	case "gte":
		return v >= t.Value
	case "lt":
		return v < t.Value
	case "lte":
		return v <= t.Value
	case "eq":
		return math.Abs(v-t.Value) < 1e-9
	case "zero":
		return v == 0
	case "nonzero":
		return v != 0
	}
	return false
}

func thresholdValue(t panelThreshold, d panelData) float64 {
	if t.Label == "" {
		return float64(d.Count)
	}
	for _, sp := range d.Series {
		if strings.EqualFold(sp.Label, t.Label) {
			if t.Percent {
				return sp.Share
			}
			return float64(sp.Value)
		}
	}
	v := 0.0
	for _, b := range d.Stacked {
		for _, sp := range b.Parts {
			if strings.EqualFold(sp.Label, t.Label) {
				v += float64(sp.Value)
			}
		}
	}
	return v
}

func describeThreshold(t panelThreshold) string {
	what := "count"
	if t.Label != "" {
		what = fmt.Sprintf("%q", t.Label)
		if t.Percent {
			what += " share"
		}
	}
	ops := map[string]string{"gt": ">", "gte": "≥", "lt": "<", "lte": "≤", "eq": "="}
	switch t.Op {
	case "zero":
		return what + " is zero"
	case "nonzero":
		return what + " is not zero"
	}
	if t.Percent {
		return fmt.Sprintf("%s %s %.0f%%", what, ops[t.Op], t.Value)
	}
	return fmt.Sprintf("%s %s %.0f", what, ops[t.Op], t.Value)
}

// --- sampling -------------------------------------------------------------

func (s *Server) dashboardSampleLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(45 * time.Second):
	}
	s.seedDashboards(ctx)
	ticker := time.NewTicker(dashboardSampleEvery)
	defer ticker.Stop()
	for {
		s.sampleDashboards(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) sampleDashboards(ctx context.Context) {
	dashboards, err := s.store.ListDashboards(ctx)
	if err != nil {
		s.logger.Warn("dashboard sampling: list failed", "error", err)
		return
	}
	at := time.Now().Truncate(time.Minute)
	// One sampling pass reads each source once, across every dashboard.
	mctx := withExportMemo(ctx)
	for _, db := range dashboards {
		panels, err := decodePanels(db.Panels)
		if err != nil {
			continue
		}
		for _, p := range panels {
			if p.Chart == "text" {
				continue
			}
			d := s.evaluatePanel(mctx, db.ID, p, nil, 0)
			if d.Error != "" {
				continue
			}
			series, _ := json.Marshal(d.Series)
			if err := s.store.RecordPanelSample(ctx, db.ID, p.ID, at, float64(d.Count), series); err != nil {
				s.logger.Warn("dashboard sampling: record failed", "dashboard", db.Name, "panel", p.Title, "error", err)
			}
		}
	}
	if _, err := s.store.PrunePanelSamples(ctx, dashboardSampleKeep); err != nil {
		s.logger.Warn("dashboard sampling: prune failed", "error", err)
	}
}

// seedDashboards creates two starter dashboards on a fresh install so
// Home has something to show before anyone authors one. They are
// ordinary dashboards afterwards: edit or delete them.
func (s *Server) seedDashboards(ctx context.Context) {
	n, err := s.store.CountDashboards(ctx)
	if err != nil || n > 0 {
		return
	}
	seeds := []struct {
		name, desc string
		panels     []dashboardPanel
	}{
		{"Fleet overview", "Who is out there and what they run.", []dashboardPanel{
			{reportSection: reportSection{Title: "Managed endpoints", Source: "endpoints"}, Chart: "number", Width: 1},
			{reportSection: reportSection{Title: "Online now", Source: "endpoints", FilterColumn: "online", FilterValue: "true"}, Chart: "number", Width: 1,
				Highlight: &panelThreshold{Op: "zero"}},
			{reportSection: reportSection{Title: "Endpoints over time", Source: "endpoints"}, Chart: "area", Width: 1},
			{reportSection: reportSection{Title: "By operating system", Source: "endpoints", GroupBy: "os"}, Chart: "donut", Width: 1},
			{reportSection: reportSection{Title: "By agent version", Source: "endpoints", GroupBy: "agent_version"}, Chart: "bar", Width: 2},
			{reportSection: reportSection{Title: "Platform by site", Source: "endpoints", GroupBy: "site"}, Chart: "stacked", SeriesBy: "platform", Width: 3},
		}},
		{"Security posture", "Patches, vulnerabilities and compliance at a glance.", []dashboardPanel{
			{reportSection: reportSection{Title: "Missing patches", Source: "patches"}, Chart: "number", Width: 1, Highlight: &panelThreshold{Op: "gt", Value: 0}},
			{reportSection: reportSection{Title: "Vulnerability findings", Source: "findings"}, Chart: "number", Width: 1},
			{reportSection: reportSection{Title: "Findings over time", Source: "findings"}, Chart: "area", Width: 1},
			{reportSection: reportSection{Title: "Patches by severity", Source: "patches", GroupBy: "severity"}, Chart: "donut", Width: 1},
			{reportSection: reportSection{Title: "Compliance by result", Source: "compliance", GroupBy: "state"}, Chart: "donut", Width: 1},
			{reportSection: reportSection{Title: "Enforce standing", Source: "enforce", GroupBy: "state"}, Chart: "bar", Width: 1},
			{reportSection: reportSection{Title: "Most-missed patches", Source: "patches", Columns: []string{"hostname", "patch", "severity"}, Limit: 15}, Chart: "table", Width: 3},
		}},
	}
	for _, sd := range seeds {
		panels, err := s.validatePanels(ctx, sd.panels)
		if err != nil {
			s.logger.Warn("seed dashboard skipped", "name", sd.name, "error", err)
			continue
		}
		raw, _ := json.Marshal(panels)
		if err := s.store.UpsertDashboard(ctx, store.Dashboard{ID: idgen.New("db-"), Name: sd.name, Description: sd.desc, Panels: raw, Shared: true, CreatedBy: "mustra"}); err != nil {
			s.logger.Warn("seed dashboard failed", "name", sd.name, "error", err)
		}
	}
	s.logger.Info("seeded starter dashboards", "count", len(seeds))
}

// --- alerts ---------------------------------------------------------------

// guideAlerts is the Guide evaluator for custom alerts: one item per
// alert whose condition holds. An alert that stops holding is resolved
// like any other Guide item, so the tray only ever shows what is true now.
func (s *Server) guideAlerts(ctx context.Context) ([]guideItem, error) {
	alerts, err := s.store.ListDashboardAlerts(ctx)
	if err != nil {
		return nil, err
	}
	if len(alerts) == 0 {
		return nil, nil
	}
	dashboards := map[string]*store.Dashboard{}
	var items []guideItem
	for _, a := range alerts {
		if !a.Enabled {
			continue
		}
		db, ok := dashboards[a.DashboardID]
		if !ok {
			db, _ = s.store.GetDashboard(ctx, a.DashboardID)
			dashboards[a.DashboardID] = db
		}
		if db == nil {
			_ = s.store.SetAlertState(ctx, a.ID, nil, "error", "its dashboard no longer exists")
			continue
		}
		panels, _ := decodePanels(db.Panels)
		var panel *dashboardPanel
		for i := range panels {
			if panels[i].ID == a.PanelID {
				panel = &panels[i]
			}
		}
		if panel == nil {
			_ = s.store.SetAlertState(ctx, a.ID, nil, "error", "its panel no longer exists")
			continue
		}
		var cond panelThreshold
		if err := json.Unmarshal(a.Condition, &cond); err != nil || !validThresholdOp(cond.Op) {
			_ = s.store.SetAlertState(ctx, a.ID, nil, "error", "condition is not valid")
			continue
		}
		d := s.evaluatePanel(ctx, db.ID, *panel, nil, 0)
		if d.Error != "" {
			_ = s.store.SetAlertState(ctx, a.ID, nil, "error", d.Error)
			continue
		}
		v := thresholdValue(cond, d)
		holds := thresholdHolds(cond, d)
		unit := ""
		if cond.Percent {
			unit = "%"
		}
		detail := fmt.Sprintf("%s on %q is %.0f%s; alert when %s.", panel.Title, db.Name, v, unit, describeThreshold(cond))
		state := "ok"
		if holds {
			state = "triggered"
			items = append(items, guideItem{key: a.ID, kind: "observation", severity: a.Severity, title: a.Name, detail: detail,
				link: "/dashboards#view/" + db.ID, count: 1})
		}
		_ = s.store.SetAlertState(ctx, a.ID, &v, state, detail)
	}
	return items, nil
}
