package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Connect: get mustra's data out, into whatever already runs alongside it.
//
// The design decision worth stating is that this exports *answers*, not
// tables. A destination receives the result of a question, a deployment
// history, or a findings list — the same thing the console shows — rather
// than a dump of rows that a consumer would then have to re-derive meaning
// from. That keeps one definition of "what is true" and makes an export
// reproducible: you can always ask the same question in the UI and get
// what the SIEM got.
//
// History sources carry an incremental cursor, so a run exports what is
// new rather than resending everything and making the consumer dedupe.

type exportSource string

const (
	sourceQuestion    exportSource = "question"
	sourceDeployments exportSource = "deployments"
	sourceFindings    exportSource = "findings"
	sourceHistory     exportSource = "question_history"
	sourceEndpoints   exportSource = "endpoints"
	sourceDiscover    exportSource = "discover"
	// Added for Reports, and available to Connect for the same reason
	// every other source is: a report and an export are the same question
	// asked with a different delivery.
	sourceCompliance exportSource = "compliance"
	sourceEnforce    exportSource = "enforce"
	sourcePatches    exportSource = "patches"
	sourcePlaybooks  exportSource = "playbooks"
)

// What an export may be saved with: exactly what runExport, formatRows and
// deliver handle, so a saved export cannot fail every run by construction.
var (
	exportSources = map[exportSource]bool{sourceQuestion: true, sourceDeployments: true, sourceFindings: true,
		sourceHistory: true, sourceEndpoints: true, sourceCompliance: true, sourceEnforce: true,
		sourcePatches: true, sourcePlaybooks: true}
	exportFormats      = map[string]bool{"json": true, "ndjson": true, "csv": true, "cef": true, "syslog": true}
	exportDestinations = map[string]bool{"webhook": true, "file": true, "syslog": true}
)

// findingRows is the findings source, the worst first: a report shows its
// first rows, and they have to be the ones somebody should read. A finding the
// distribution says needs no action stays out, as on the Risk page: a report's
// count has to agree with the page it is about.
func findingRows(vulns []store.AgentVulnRow, intel map[string]store.ExploitIntel) []map[string]any {
	rows := make([]map[string]any, 0, len(vulns))
	for _, v := range vulns {
		if v.Suppressed {
			continue
		}
		x, _ := vulnIntel(v, intel)
		rows = append(rows, map[string]any{
			"agent_id": v.AgentID, "hostname": v.Hostname, "vuln_id": v.VulnID,
			"package": v.PackageName, "version": v.PackageVersion,
			"severity": firstNonEmpty(v.Severity, "unknown"), "summary": v.Summary, "fixed_version": v.FixedVersion,
			"kev": x.KEV, "ransomware": x.Ransomware, "epss": x.EPSS,
		})
	}
	sevRank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a["kev"] != b["kev"] {
			return a["kev"].(bool)
		}
		if ra, rb := sevRank[a["severity"].(string)], sevRank[b["severity"].(string)]; ra != rb {
			return ra > rb
		}
		return a["epss"].(float64) > b["epss"].(float64)
	})
	return rows
}

// runExport produces the rows for one source. Every source answers as
// []map[string]any so formatting is source-agnostic.
func (s *Server) runExport(ctx context.Context, cfg store.ExportConfig) ([]map[string]any, string, error) {
	switch exportSource(cfg.Source) {
	case sourceQuestion:
		if cfg.SavedQuestionID == "" {
			return nil, "", fmt.Errorf("this export needs a saved query to run")
		}
		saved, err := s.store.GetSavedQuestion(ctx, cfg.SavedQuestionID)
		if err != nil || saved == nil {
			return nil, "", fmt.Errorf("saved query not found")
		}
		devices, _, err := s.devicesForMatching(ctx)
		if err != nil {
			return nil, "", err
		}
		var where []groups.Rule
		_ = json.Unmarshal(saved.Where, &where)
		result := answerQuestion(devices, questionRequest{
			Get: saved.Get, Where: where, MatchAll: saved.MatchAll, Text: saved.Name, RecordSensor: saved.RecordSensor,
		})
		rows := make([]map[string]any, 0, len(result.Rows))
		for _, r := range result.Rows {
			row := map[string]any{"count": r.Count}
			if r.Hostname != "" {
				row["hostname"] = r.Hostname
			}
			for i, field := range result.Get {
				if i < len(r.Values) {
					row[field] = r.Values[i]
				}
			}
			rows = append(rows, row)
		}
		return rows, "", nil

	case sourceDeployments:
		runs, err := s.store.ListPatchJobRuns(ctx, 500)
		if err != nil {
			return nil, "", err
		}
		ids := make([]string, 0, len(runs))
		for _, r := range runs {
			ids = append(ids, r.ID)
		}
		counts, _ := s.store.RunOutcomeCounts(ctx, ids)
		rows := []map[string]any{}
		cursor := newExportCursor(cfg.Cursor)
		for _, run := range runs {
			if !cursor.take(run.StartedAt) {
				continue
			}
			rows = append(rows, map[string]any{
				"id": run.ID, "what": run.ScheduleName, "target": run.TargetDesc,
				"devices": run.AgentCount, "by": run.TriggeredBy,
				"started_at": run.StartedAt.UTC().Format(time.RFC3339Nano),
				"status":     deploymentStatus(run, counts[run.ID]),
				"outcomes":   counts[run.ID],
			})
		}
		return rows, cursor.String(), nil

	case sourceHistory:
		history, err := s.store.ListQuestionHistory(ctx, 1000)
		if err != nil {
			return nil, "", err
		}
		rows := []map[string]any{}
		cursor := newExportCursor(cfg.Cursor)
		for _, h := range history {
			if !cursor.take(h.AskedAt) {
				continue
			}
			rows = append(rows, map[string]any{
				"id": h.ID, "question": h.Text, "asked_by": h.AskedBy,
				"asked_at": h.AskedAt.UTC().Format(time.RFC3339Nano), "matched": h.Matched, "total": h.Total,
			})
		}
		return rows, cursor.String(), nil

	case sourceEndpoints:
		agents, err := s.store.ListAgents(ctx, s.staleAfter())
		if err != nil {
			return nil, "", err
		}
		// Operator-maintained attributes ride along as columns, which is
		// what makes a summary report grouped by "owner" or "cost centre"
		// possible without a second source.
		attrs, err := s.store.AttributeValuesByAgent(ctx)
		if err != nil {
			return nil, "", err
		}
		rows := make([]map[string]any, 0, len(agents))
		for _, a := range agents {
			row := map[string]any{
				"agent_id": a.AgentID, "hostname": a.Hostname, "os": a.OS, "arch": a.Arch,
				"platform": a.Platform, "platform_version": a.PlatformVersion,
				"agent_version": a.AgentVersion, "site": a.Site, "online": a.Online,
				"ips": strings.Join(a.IPs, " "),
				// Retention, so a report can separate the fleet from what is
				// merely remembered, and group by either.
				"managed": a.Managed, "last_seen": lastSeen(a), "retired_at": retiredAt(a),
			}
			for name, value := range attrs[a.AgentID] {
				row["attr_"+name] = value
			}
			rows = append(rows, row)
		}
		return rows, "", nil

	case sourceFindings:
		vulns, err := s.store.ListAllAgentVulnerabilities(ctx)
		if err != nil {
			return nil, "", err
		}
		return findingRows(vulns, s.intelForRows(ctx, vulns)), "", nil

	case sourceCompliance:
		results, err := s.store.ListComplianceResults(ctx)
		if err != nil {
			return nil, "", err
		}
		s.loadExceptions(ctx).apply(results)
		rows := make([]map[string]any, 0, len(results))
		for _, c := range results {
			rows = append(rows, map[string]any{
				"agent_id": c.AgentID, "hostname": c.Hostname, "policy_id": c.PolicyID,
				"check_id": c.CheckID, "title": c.Title, "severity": c.Severity,
				"state": c.State, "detail": c.Detail,
				"checked_at": c.CheckedAt.UTC().Format(time.RFC3339),
			})
		}
		return rows, "", nil

	case sourceEnforce:
		results, err := s.store.ListEnforceResults(ctx, "")
		if err != nil {
			return nil, "", err
		}
		rows := make([]map[string]any, 0, len(results))
		for _, e := range results {
			rows = append(rows, map[string]any{
				"agent_id": e.AgentID, "hostname": e.Hostname, "policy_id": e.PolicyID,
				"setting": e.Name, "severity": e.Severity, "state": e.State,
				"detail": e.Detail, "consecutive_failures": e.ConsecutiveFailures,
				"remediation_count": e.RemediationCount,
				"checked_at":        e.CheckedAt.UTC().Format(time.RFC3339),
			})
		}
		return rows, "", nil

	case sourcePatches:
		// From the cached patches sensor rather than a live sweep: a report
		// must not wake thirty-nine machines every morning to build itself.
		snapshots, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorPatches))
		if err != nil {
			return nil, "", err
		}
		rows := []map[string]any{}
		for _, snap := range snapshots {
			var patches []proto.PatchInfo
			if json.Unmarshal(snap.Data, &patches) != nil {
				continue
			}
			for _, p := range patches {
				rows = append(rows, map[string]any{
					"agent_id": snap.AgentID, "hostname": snap.Hostname,
					"patch": p.Name, "installed": p.CurrentVersion,
					"available": p.NewVersion, "severity": p.Severity,
					"collected_at": snap.CollectedAt.UTC().Format(time.RFC3339),
				})
			}
		}
		return rows, "", nil

	case sourcePlaybooks:
		runs, err := s.store.ListPlaybookRuns(ctx, 200)
		if err != nil {
			return nil, "", err
		}
		rows := make([]map[string]any, 0, len(runs))
		cursor := newExportCursor(cfg.Cursor)
		for _, run := range runs {
			if !cursor.take(run.StartedAt) {
				continue
			}
			rows = append(rows, map[string]any{
				"id": run.ID, "playbook": run.Name, "target": run.TargetDesc,
				"endpoints": run.AgentCount, "status": run.Status,
				"by": run.TriggeredBy, "started_at": run.StartedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		return rows, cursor.String(), nil

	default:
		return nil, "", fmt.Errorf("unknown export source %q", cfg.Source)
	}
}

// exportCursor is a history source's incremental cursor: the start of
// the newest row an export has sent, stored as RFC 3339 with nanoseconds.
// It is compared as a time, never as a string: RFC3339Nano drops trailing
// zeros, so "…14.5Z" sorts before "…14Z" and a row started later in the
// cursor's second would never be sent.
type exportCursor struct {
	since  time.Time // zero when the export has never run
	newest time.Time
}

// newExportCursor reads a stored cursor. One that does not parse (only a
// hand-edited row could hold one) counts as none: resending rows is
// better than never sending them.
func newExportCursor(stored string) *exportCursor {
	since, _ := time.Parse(time.RFC3339Nano, stored)
	return &exportCursor{since: since, newest: since}
}

// take reports whether a row started at t is new since the stored cursor,
// and advances the cursor to the newest such row.
func (c *exportCursor) take(t time.Time) bool {
	if !c.since.IsZero() && !t.After(c.since) {
		return false
	}
	if t.After(c.newest) {
		c.newest = t
	}
	return true
}

// String is the cursor to store after the run, "" (keep what is stored)
// when there is none.
func (c *exportCursor) String() string {
	if c.newest.IsZero() {
		return ""
	}
	return c.newest.UTC().Format(time.RFC3339Nano)
}

// ---- formats ----

func formatRows(format string, rows []map[string]any, cfg store.ExportConfig) ([]byte, string, error) {
	switch format {
	case "json":
		body, err := json.MarshalIndent(rows, "", "  ")
		return body, "application/json", err

	case "ndjson":
		// One object per line: what Loki, Vector and most log shippers
		// actually want, and streamable rather than requiring the whole
		// array to be parsed at once.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, row := range rows {
			if err := enc.Encode(row); err != nil {
				return nil, "", err
			}
		}
		return buf.Bytes(), "application/x-ndjson", nil

	case "csv":
		var buf bytes.Buffer
		wr := newSafeCSVWriter(&buf)
		cols := columnsOf(rows)
		if err := wr.Write(cols); err != nil {
			return nil, "", err
		}
		for _, row := range rows {
			rec := make([]string, len(cols))
			for i, c := range cols {
				rec[i] = stringify(row[c])
			}
			if err := wr.Write(rec); err != nil {
				return nil, "", err
			}
		}
		wr.Flush()
		return buf.Bytes(), "text/csv", wr.Error()

	case "cef":
		var buf bytes.Buffer
		for _, row := range rows {
			buf.WriteString(cefLine(cfg.Source, row))
			buf.WriteString("\n")
		}
		return buf.Bytes(), "text/plain", nil

	case "syslog":
		var buf bytes.Buffer
		host, _ := os.Hostname()
		for _, row := range rows {
			payload, _ := json.Marshal(row)
			// RFC 5424: <priority>version timestamp host app procid msgid sd msg
			fmt.Fprintf(&buf, "<134>1 %s %s mustra - %s - %s\n",
				time.Now().UTC().Format(time.RFC3339), host, cfg.Source, payload)
		}
		return buf.Bytes(), "text/plain", nil

	default:
		return nil, "", fmt.Errorf("unknown format %q", format)
	}
}

// columnsOf derives a stable column set across heterogeneous rows. Sorted
// rather than map-order so a CSV's columns don't move between runs, which
// would break every downstream consumer that assumes position.
func columnsOf(rows []map[string]any) []string {
	seen := map[string]bool{}
	var cols []string
	for _, row := range rows {
		for k := range row {
			if !seen[k] {
				seen[k] = true
				cols = append(cols, k)
			}
		}
	}
	sort.Strings(cols)
	return cols
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return strings.Trim(string(b), `"`)
	}
}

// cefLine renders one row as ArcSight CEF, which is what most SIEMs ingest
// without a custom parser.
func cefLine(source string, row map[string]any) string {
	esc := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, "|", `\|`)
		s = strings.ReplaceAll(s, "=", `\=`)
		return s
	}
	var ext strings.Builder
	for _, k := range columnsOf([]map[string]any{row}) {
		fmt.Fprintf(&ext, "%s=%s ", esc(k), esc(stringify(row[k])))
	}
	return fmt.Sprintf("CEF:0|mustra|mustra|1.0|%s|%s|3|%s",
		esc(source), esc(source), strings.TrimSpace(ext.String()))
}

// ---- destinations ----

func (s *Server) deliver(ctx context.Context, cfg store.ExportConfig, body []byte, contentType string) error {
	switch cfg.Destination {
	case "webhook":
		return s.deliverWebhook(ctx, cfg, body, contentType)
	case "file":
		return deliverFile(cfg, body)
	case "syslog":
		return deliverSyslog(ctx, cfg, body, s.webhookAllowedHosts(ctx))
	default:
		return fmt.Errorf("unknown destination %q", cfg.Destination)
	}
}

func (s *Server) deliverWebhook(ctx context.Context, cfg store.ExportConfig, body []byte, contentType string) error {
	payload := body
	ct := contentType
	// Discord (and Slack) want a JSON object with a message field, not a
	// bare array — so a plain webhook URL pointed at either works without
	// the operator having to build a shim.
	if cfg.WebhookStyle == "discord" || cfg.WebhookStyle == "slack" {
		// Rune-safe: invalid UTF-8 here does not error, it gets silently
		// replaced with U+FFFD on the way into the JSON envelope, so the
		// export arrives subtly corrupted rather than obviously broken.
		text := safeTruncate(string(body), 1800)
		field := "content"
		if cfg.WebhookStyle == "slack" {
			field = "text"
		}
		wrapped, err := json.Marshal(map[string]string{field: "```\n" + text + "\n```"})
		if err != nil {
			return err
		}
		payload = wrapped
		ct = "application/json"
	}

	client, allowed := s.webhookClient(ctx)
	if err := checkWebhookURL(cfg.Target, allowed); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ct)
	// Discord rejects the default Go user agent outright.
	req.Header.Set("User-Agent", "mustra-connect/1.0")
	headers, err := s.exportHeaders(cfg)
	if err != nil {
		return fmt.Errorf("the export's headers could not be opened: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %s", cfg.Target, resp.Status)
	}
	return nil
}

func deliverFile(cfg store.ExportConfig, body []byte) error {
	return deliverFileAs(cfg, body, "out")
}

// deliverFileAs writes to a directory or an exact path. The extension only
// applies to the generated name: a report is an HTML document and calling
// it .out would make it something nobody double-clicks.
//
// Files land only under the export directory (MUSTRA_EXPORT_DIR, default
// /var/lib/mustra/output): the server runs as root in its container, and
// "write a file wherever settings.manage says" was a way to overwrite
// anything — the CA, the agent builds, a cron entry. The write goes
// through os.Root, so a symlink inside the directory cannot lead out of it
// either. A path that names the directory itself (absolute) is accepted
// for compatibility with existing exports.
func deliverFileAs(cfg store.ExportConfig, body []byte, ext string) error {
	path := strings.TrimSpace(cfg.Target)
	if path == "" {
		return fmt.Errorf("a file destination needs a path")
	}
	base := exportDir()
	rel := path
	if filepath.IsAbs(path) {
		r, err := filepath.Rel(base, filepath.Clean(path))
		if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return fmt.Errorf("file exports are written under %s; %s is outside it", base, path)
		}
		rel = r
		if strings.HasSuffix(path, "/") {
			rel += "/"
		}
	}
	// A timestamped name unless the operator asked for a fixed one, so
	// successive runs don't silently overwrite each other's output.
	if rel == "." || strings.HasSuffix(rel, "/") || filepath.Ext(rel) == "" {
		rel = filepath.Join(rel, fmt.Sprintf("mustra-%s-%s.%s",
			cfg.Source, time.Now().UTC().Format("20060102T150405Z"), ext))
	}
	rel = filepath.Clean(rel)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("file exports are written under %s", base)
	}
	if err := os.MkdirAll(base, 0o750); err != nil {
		return err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return err
	}
	defer root.Close()
	if dir := filepath.Dir(rel); dir != "." {
		if err := root.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	return root.WriteFile(rel, body, 0o640)
}

func exportDir() string {
	if d := os.Getenv("MUSTRA_EXPORT_DIR"); d != "" {
		return filepath.Clean(d)
	}
	return "/var/lib/mustra/output"
}

// deliverSyslog sends an export to a syslog collector, through the same
// address checks as a webhook.
func deliverSyslog(ctx context.Context, cfg store.ExportConfig, body []byte, allowed map[string]bool) error {
	network := "udp"
	if strings.HasPrefix(cfg.Target, "tcp://") {
		network = "tcp"
	}
	addr := strings.TrimPrefix(strings.TrimPrefix(cfg.Target, "udp://"), "tcp://")
	conn, err := guardedDial(ctx, network, addr, allowed, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	_, err = conn.Write(body)
	return err
}

// ---- HTTP ----

// listExportsResponse is what GET /api/connect/exports answers.
type listExportsResponse struct {
	Exports []exportView `json:"exports"`
}

// Export headers (an Authorization token for the webhook, typically) are
// a credential, and are kept as every other stored credential is: sealed
// in the vault, written but never read back through the API. The
// response says whether any are set and their names, so an operator can
// tell an export with a token from one without, and nothing more; a
// script running in a settings.manage session cannot collect them.

// exportHeadersAAD is the vault association for one export's headers.
func exportHeadersAAD(id string) string { return "export:" + id + ":headers" }

// exportHeaders opens the headers an export sends.
func (s *Server) exportHeaders(cfg store.ExportConfig) (map[string]string, error) {
	if cfg.HeadersSealed == "" {
		return cfg.Headers, nil
	}
	plain, err := s.openSetting(exportHeadersAAD(cfg.ID), cfg.HeadersSealed)
	if err != nil {
		return nil, err
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(plain), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// sealExportHeaders puts headers on cfg in their stored form.
func (s *Server) sealExportHeaders(cfg *store.ExportConfig, headers map[string]string) error {
	cfg.Headers, cfg.HeadersSealed = nil, ""
	if len(headers) == 0 {
		return nil
	}
	raw, err := json.Marshal(headers)
	if err != nil {
		return err
	}
	sealed, err := s.sealSetting(exportHeadersAAD(cfg.ID), string(raw))
	if err != nil {
		return err
	}
	cfg.HeadersSealed = sealed
	return nil
}

// exportView is an export as the API answers it: its configuration
// without the headers' values.
type exportView struct {
	store.ExportConfig
	// Headers is never answered; see HeadersSet.
	Headers map[string]string `json:"headers,omitempty"`
	// HeadersSet says whether the export sends any headers.
	HeadersSet bool `json:"headers_set"`
	// HeaderNames are the headers it sends, by name.
	HeaderNames []string `json:"header_names,omitempty"`
}

func (s *Server) exportViewOf(cfg store.ExportConfig) exportView {
	v := exportView{ExportConfig: cfg}
	names := map[string]bool{}
	for k := range cfg.Headers {
		names[k] = true
	}
	if cfg.HeadersSealed != "" {
		// Names only; a sealed value that cannot be opened still counts
		// as set, which is what the operator needs to know to fix it.
		if h, err := s.exportHeaders(cfg); err == nil {
			for k := range h {
				names[k] = true
			}
		}
		v.HeadersSet = true
	}
	v.ExportConfig.Headers = nil
	for k := range names {
		v.HeaderNames = append(v.HeaderNames, k)
	}
	sort.Strings(v.HeaderNames)
	v.HeadersSet = v.HeadersSet || len(v.HeaderNames) > 0
	return v
}

func (s *Server) handleListExports(w http.ResponseWriter, r *http.Request) {
	cfgs, err := s.store.ListExportConfigs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]exportView, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, s.exportViewOf(c))
	}
	writeJSONResponse(w, listExportsResponse{Exports: out})
}

// exportBody is the body of POST /api/connect/exports and PUT
// /api/connect/exports/{id}.
type exportBody struct {
	store.ExportConfig
	// Headers are sent with every webhook post; put a token here rather
	// than in the URL. Write-only: they are stored sealed and never
	// answered. Omit the field to keep the stored headers; send {} to
	// remove them.
	Headers *map[string]string `json:"headers" api:"writeonly"`
}

func (s *Server) handleUpsertExport(w http.ResponseWriter, r *http.Request) {
	var in exportBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body := in.ExportConfig
	body.Headers, body.HeadersSealed = nil, ""
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || body.Source == "" || body.Destination == "" {
		http.Error(w, "name, source and destination are required", http.StatusBadRequest)
		return
	}
	if !exportSources[exportSource(body.Source)] {
		http.Error(w, "unknown source", http.StatusBadRequest)
		return
	}
	if !exportDestinations[body.Destination] {
		http.Error(w, "destination must be webhook, file or syslog", http.StatusBadRequest)
		return
	}
	if body.Format == "" {
		body.Format = "json" // what the form preselects; an empty one failed every run
	}
	if !exportFormats[body.Format] {
		http.Error(w, "format must be json, ndjson, csv, cef or syslog", http.StatusBadRequest)
		return
	}
	// The id is the server's to mint: a PUT edits an export that exists,
	// and a POST cannot choose one (it used to accept any string, slashes
	// and control characters included, and keep it as the row id).
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetExportConfig(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such export", http.StatusNotFound)
			return
		}
		body.ID = id
		if in.Headers == nil {
			// Headers omitted: keep what is stored. A row written before
			// headers were sealed is sealed on its way back.
			body.HeadersSealed = existing.HeadersSealed
			if body.HeadersSealed == "" && len(existing.Headers) > 0 {
				if err := s.sealExportHeaders(&body, existing.Headers); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
	} else {
		body.ID = idgen.New("exp-")
		body.CreatedBy = auth.CurrentUser(r.Context()).Username
	}
	if in.Headers != nil {
		for k := range *in.Headers {
			if strings.TrimSpace(k) == "" || strings.ContainsAny(k, " \t\r\n:") {
				http.Error(w, "a header name cannot be empty or contain spaces, colons or line breaks", http.StatusBadRequest)
				return
			}
		}
		if err := s.sealExportHeaders(&body, *in.Headers); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	cfg, err := s.store.UpsertExportConfig(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, s.exportViewOf(*cfg))
}

func (s *Server) handleDeleteExport(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteExportConfig(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// runExportResponse is what POST /api/connect/exports/{id}/run answers.
type runExportResponse struct {
	Cursor string `json:"cursor"`
	Rows   int    `json:"rows"`
}

// handleRunExport runs one export now. Used by the "Run now" button and by
// the scheduler, so a scheduled export and a manual one take exactly the
// same path — there is no second code path to drift.
func (s *Server) handleRunExport(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetExportConfig(r.Context(), r.PathValue("id"))
	if err != nil || cfg == nil {
		http.Error(w, "no such export", http.StatusNotFound)
		return
	}
	rows, newCursor, err := s.executeExport(r.Context(), *cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, runExportResponse{Rows: rows, Cursor: newCursor})
}

// executeExport is the shared body: gather, format, deliver, record.
func (s *Server) executeExport(ctx context.Context, cfg store.ExportConfig) (int, string, error) {
	rows, newCursor, err := s.runExport(ctx, cfg)
	if err != nil {
		_ = s.store.RecordExportRun(ctx, cfg.ID, 0, err.Error())
		return 0, "", err
	}
	if len(rows) == 0 {
		// Nothing new is a successful run, not a failure — and sending an
		// empty payload to a chat webhook every interval is how people
		// come to hate a tool.
		_ = s.store.RecordExportRun(ctx, cfg.ID, 0, "")
		if newCursor != "" {
			_ = s.store.SetExportCursor(ctx, cfg.ID, newCursor)
		}
		return 0, newCursor, nil
	}

	body, contentType, err := formatRows(cfg.Format, rows, cfg)
	if err != nil {
		_ = s.store.RecordExportRun(ctx, cfg.ID, 0, err.Error())
		return 0, "", err
	}
	if err := s.deliver(ctx, cfg, body, contentType); err != nil {
		_ = s.store.RecordExportRun(ctx, cfg.ID, 0, err.Error())
		return 0, "", err
	}
	_ = s.store.RecordExportRun(ctx, cfg.ID, len(rows), "")
	if newCursor != "" {
		_ = s.store.SetExportCursor(ctx, cfg.ID, newCursor)
	}
	s.logger.Info("export delivered", "export", cfg.Name, "source", cfg.Source,
		"destination", cfg.Destination, "rows", len(rows))
	return len(rows), newCursor, nil
}

// exportSchedulerLoop runs due exports. Deliberately the same one-minute
// tick as the patch scheduler rather than a second cadence to reason
// about; an interval is in minutes, so a minute is the finest resolution
// that means anything.
func (s *Server) exportSchedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			due, err := s.store.DueExports(ctx)
			if err != nil {
				s.logger.Warn("listing due exports failed", "error", err)
				continue
			}
			for _, cfg := range due {
				// Sequential on purpose: exports are I/O to someone else's
				// endpoint, and a fleet-wide burst of webhook posts is a
				// good way to get rate-limited by the thing you're
				// reporting to.
				if _, _, err := s.executeExport(ctx, cfg); err != nil {
					s.logger.Warn("scheduled export failed", "export", cfg.Name, "error", err)
				}
			}
		}
	}
}

// lastSeen and retiredAt render an endpoint's timestamps for export. Last
// Seen is the whole point of keeping a retired row: it says when what the
// record describes was last true.
func lastSeen(a store.AgentRecord) string {
	if a.LastHeartbeat == nil {
		return a.FirstSeen.UTC().Format(time.RFC3339)
	}
	return a.LastHeartbeat.UTC().Format(time.RFC3339)
}

func retiredAt(a store.AgentRecord) string {
	if a.RetiredAt == nil {
		return ""
	}
	return a.RetiredAt.UTC().Format(time.RFC3339)
}
