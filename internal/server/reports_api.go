package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// HTTP surface for Reports. Reading a report is reading data the console
// already shows, so any signed-in user may; authoring one takes
// settings.manage, the same permission Connect asks for — both decide
// where mustra's data goes when it leaves.

// listReportsResponse is what GET /api/reports answers.
type listReportsResponse struct {
	Reports []store.Report      `json:"reports"`
	Runs    []store.ReportRun   `json:"runs"`
	Sources []map[string]string `json:"sources"`
}

func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	reports, err := s.store.ListReports(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runs, err := s.store.ListReportRuns(r.Context(), "", 30)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listReportsResponse{
		Reports: reports, Runs: runs, Sources: reportSourceCatalog,
	})
}

// reportSourceCatalog is what the editor offers, with a line each on what
// the source actually answers — the difference between picking a source
// and guessing at one.
var reportSourceCatalog = []map[string]string{
	{"id": "endpoints", "label": "Endpoints", "desc": "Every managed device with its OS, platform, agent version, site and addresses."},
	{"id": "patches", "label": "Missing patches", "desc": "Per endpoint, per patch, from the cached patches sensor — no fleet sweep to build a report."},
	{"id": "compliance", "label": "Compliance results", "desc": "Every benchmark check result: pass, fail, or unknown, with its severity."},
	{"id": "enforce", "label": "Enforce standing", "desc": "Every desired-state setting per endpoint, and what mustra did about it."},
	{"id": "findings", "label": "Vulnerabilities", "desc": "CVE matches per endpoint and package, filtered through the distribution's own verdict."},
	{"id": "deployments", "label": "Deployments", "desc": "Every patch, software and playbook run, with its outcome counts."},
	{"id": "playbooks", "label": "Playbook runs", "desc": "Each playbook run, its targets and how it ended."},
	{"id": "question", "label": "A saved query", "desc": "Any query you have saved in Interact, answered fresh at report time."},
	{"id": "question_history", "label": "Query history", "desc": "What has been run against the fleet, by whom."},
}

// getReportResponse is what GET /api/reports/{id} answers.
type getReportResponse struct {
	Report *store.Report     `json:"report"`
	Runs   []store.ReportRun `json:"runs"`
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.GetReport(r.Context(), r.PathValue("id"))
	if err != nil || rep == nil {
		http.Error(w, "no such report", http.StatusNotFound)
		return
	}
	runs, err := s.store.ListReportRuns(r.Context(), rep.ID, 30)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, getReportResponse{Report: rep, Runs: runs})
}

// reportRunResponse is what GET /api/reports/runs/{id} and
// POST /api/reports/{id}/run answer.
type reportRunResponse struct {
	Run *store.ReportRun `json:"run"`
}

func (s *Server) handleGetReportRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetReportRun(r.Context(), r.PathValue("id"))
	if err != nil || run == nil {
		http.Error(w, "no such rendering", http.StatusNotFound)
		return
	}
	// ?download=1 hands back the standalone document rather than the
	// fragment the console embeds.
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", safeFilename(run.Name, run.GeneratedAt)))
		_, _ = w.Write([]byte(reportDocument(run.Name, run.HTML)))
		return
	}
	writeJSONResponse(w, reportRunResponse{Run: run})
}

func safeFilename(name string, at time.Time) string {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		case r == ' ':
			return '-'
		default:
			return -1
		}
	}, name)
	if clean == "" {
		clean = "report"
	}
	return fmt.Sprintf("%s-%s.html", clean, at.UTC().Format("20060102"))
}

// listReportRunsResponse is what GET /api/reports/runs answers.
type listReportRunsResponse struct {
	Runs []store.ReportRun `json:"runs"`
}

func (s *Server) handleListReportRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := s.store.ListReportRuns(r.Context(), r.URL.Query().Get("report"), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listReportRunsResponse{Runs: runs})
}

type reportRequest struct {
	ID           string          `json:"id"`
	Name         string          `json:"name" api:"required"`
	Description  string          `json:"description"`
	Sections     []reportSection `json:"sections" api:"required"`
	Enabled      *bool           `json:"enabled"`
	ScheduleKind string          `json:"schedule_kind"`
	TimeOfDay    string          `json:"time_of_day"`
	Weekday      *int            `json:"weekday"`
	Destination  string          `json:"destination"`
	Target       string          `json:"target"`
	WebhookStyle string          `json:"webhook_style"`
	// EmailTemplate overrides the email this report goes out as.
	EmailTemplate store.EmailTemplate `json:"email_template"`
}

var reportDestinations = map[string]bool{"": true, "webhook": true, "file": true, "syslog": true, "email": true}

// saveReportResponse is what POST /api/reports and PUT /api/reports/{id}
// answer.
type saveReportResponse struct {
	Report *store.Report `json:"report"`
}

func (s *Server) handleSaveReport(w http.ResponseWriter, r *http.Request) {
	var req reportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// The path wins when there is one. PUT /…/{id} with an id-less body used
	// to mint a fresh object rather than update the one addressed, and with
	// a mismatched body id it updated a different one.
	if id := r.PathValue("id"); id != "" {
		req.ID = id
	}
	if err := checkClientID("report", req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "a report needs a name", http.StatusBadRequest)
		return
	}
	sections, err := s.validateReportSections(r, req.Sections)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !reportDestinations[req.Destination] {
		http.Error(w, "destination must be blank, webhook, file, syslog or email", http.StatusBadRequest)
		return
	}
	if req.Destination != "" && strings.TrimSpace(req.Target) == "" {
		http.Error(w, "a delivery destination needs a target", http.StatusBadRequest)
		return
	}
	if req.Destination == "" {
		req.Target, req.WebhookStyle = "", ""
	}
	if req.Destination == "email" {
		to, err := parseMailRecipients(req.Target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Target, req.WebhookStyle = strings.Join(to, ", "), ""
		if err := s.validateEmailTemplate(r.Context(), "report", req.EmailTemplate, s.loadEmailShared(r.Context()).Macros); err != nil {
			http.Error(w, "this report's email template: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	var next *time.Time
	if req.ScheduleKind != "" && req.ScheduleKind != "none" {
		next, err = computeNextRun(req.ScheduleKind, req.TimeOfDay, req.Weekday, time.Now().UTC())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		req.ScheduleKind, req.TimeOfDay, req.Weekday = "", "", nil
	}

	encoded, err := json.Marshal(sections)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.ID == "" {
		req.ID = idgen.New("rep-")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	who := auth.CurrentUser(r.Context()).Username
	existing, _ := s.store.GetReport(r.Context(), req.ID)

	if err := s.store.UpsertReport(r.Context(), store.Report{
		ID: req.ID, Name: req.Name, Description: strings.TrimSpace(req.Description),
		Sections: encoded, Enabled: enabled, ScheduleKind: req.ScheduleKind,
		TimeOfDay: req.TimeOfDay, Weekday: req.Weekday, Destination: req.Destination,
		Target: strings.TrimSpace(req.Target), WebhookStyle: req.WebhookStyle, EmailTemplate: req.EmailTemplate, UpdatedBy: who,
	}, next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "report.update"
	if existing == nil {
		action = "report.create"
	}
	// Where it is delivered is the part worth auditing: a report is fleet
	// data leaving mustra, on a timer, to an address somebody chose.
	s.audit(r.Context(), auditEvent{
		Action: action, Actor: who, Target: req.Name,
		Detail: map[string]any{"sections": len(sections), "schedule": req.ScheduleKind,
			"destination": req.Destination, "target": req.Target, "enabled": enabled},
	})
	saved, _ := s.store.GetReport(r.Context(), req.ID)
	writeJSONResponse(w, saveReportResponse{Report: saved})
}

func (s *Server) validateReportSections(r *http.Request, sections []reportSection) ([]reportSection, error) {
	if len(sections) == 0 {
		return nil, fmt.Errorf("a report needs at least one section")
	}
	known := map[string]bool{}
	for _, src := range reportSourceCatalog {
		known[src["id"]] = true
	}
	for i := range sections {
		sec := &sections[i]
		sec.Title = strings.TrimSpace(sec.Title)
		if sec.ID == "" {
			sec.ID = idgen.New("sec-")
		}
		if err := checkClientID(fmt.Sprintf("section %d", i+1), sec.ID); err != nil {
			return nil, err
		}
		if !known[sec.Source] {
			return nil, fmt.Errorf("section %d: unknown source %q", i+1, sec.Source)
		}
		if sec.Source == "question" {
			saved, err := s.store.GetSavedQuestion(r.Context(), sec.SavedQuestionID)
			if err != nil || saved == nil {
				return nil, fmt.Errorf("section %d: pick a saved query", i+1)
			}
		}
		if sec.Limit < 0 {
			return nil, fmt.Errorf("section %d: a row limit cannot be negative", i+1)
		}
		var cols []string
		for _, c := range sec.Columns {
			if c = strings.TrimSpace(c); c != "" {
				cols = append(cols, c)
			}
		}
		sec.Columns = cols
	}
	return sections, nil
}

// deleteReportResponse is what DELETE /api/reports/{id} answers.
type deleteReportResponse struct {
	Deleted string `json:"deleted"`
}

func (s *Server) handleDeleteReport(w http.ResponseWriter, r *http.Request) {
	rep, _ := s.store.GetReport(r.Context(), r.PathValue("id"))
	if rep == nil {
		http.Error(w, "no such report", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteReport(r.Context(), rep.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "report.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: rep.Name, Severity: "notice",
	})
	writeJSONResponse(w, deleteReportResponse{Deleted: rep.Name})
}

// handleRunReport renders now. deliver=false previews without sending —
// the difference between checking a section and posting a half-built
// report to a channel of people.
func (s *Server) handleRunReport(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.GetReport(r.Context(), r.PathValue("id"))
	if err != nil || rep == nil {
		http.Error(w, "no such report", http.StatusNotFound)
		return
	}
	// Parsed, not merely present: ?deliver=false used to post the report to
	// the configured webhook, which is the opposite of what a client
	// following the documented contract asked for.
	deliver, _ := strconv.ParseBool(r.URL.Query().Get("deliver"))
	if !deliver {
		rep.Destination = ""
	}
	who := auth.CurrentUser(r.Context()).Username
	run, err := s.runReport(r.Context(), *rep, who, !deliver)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if deliver {
		s.audit(r.Context(), auditEvent{
			Action: "report.deliver", Actor: who, Target: rep.Name, Severity: "notice",
			Detail: map[string]any{"destination": rep.Destination, "target": rep.Target,
				"delivered": run.Delivered, "rows": run.RowCount},
		})
	}
	writeJSONResponse(w, reportRunResponse{Run: run})
}
