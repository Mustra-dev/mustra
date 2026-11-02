package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Dashboards are authored by anyone signed in and shared by default; a
// dashboard is edited by its author or by anyone with settings.manage.
// Alerts are administration: they write into the Guide tray everyone
// sees, so they take settings.manage.

func (s *Server) canEditDashboard(r *http.Request, d *store.Dashboard) bool {
	u := auth.CurrentUser(r.Context())
	return d.CreatedBy == u.Username || s.isAdmin(r)
}

// canViewDashboard is the list view's rule applied to a fetch by id: a
// private dashboard is its author's (and an administrator's), and knowing
// its id is not a reason to read it.
func (s *Server) canViewDashboard(r *http.Request, d *store.Dashboard) bool {
	return d.Shared || s.canEditDashboard(r, d)
}

// isAdmin says whether the caller holds settings.manage.
func (s *Server) isAdmin(r *http.Request) bool {
	ok, _ := s.auth.HasPermission(r.Context(), auth.CurrentUser(r.Context()), auth.PermSettingsManage)
	return ok
}

// listDashboardsResponse is what GET /api/dashboards answers.
type listDashboardsResponse struct {
	CanManageAlerts bool                  `json:"can_manage_alerts"`
	Dashboards      []map[string]any      `json:"dashboards"`
	Questions       []store.SavedQuestion `json:"questions"`
	Sources         []map[string]string   `json:"sources"`
}

// GET /api/dashboards
func (s *Server) handleListDashboards(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListDashboards(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u := auth.CurrentUser(r.Context())
	admin := s.isAdmin(r)
	// Content sets: a role holding one sees only the dashboards (and,
	// below, the saved questions) it names.
	dashAllowed, err := s.contentFilter(r.Context(), "dashboards")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	questionAllowed, err := s.contentFilter(r.Context(), "questions")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, d := range list {
		if !d.Shared && d.CreatedBy != u.Username && !admin {
			continue
		}
		if !dashAllowed(d.ID) {
			continue
		}
		out = append(out, map[string]any{"id": d.ID, "name": d.Name, "description": d.Description, "panel_count": d.PanelCount, "shared": d.Shared,
			"created_by": d.CreatedBy, "updated_at": d.UpdatedAt, "editable": d.CreatedBy == u.Username || admin})
	}
	all, _ := s.store.ListSavedQuestions(r.Context())
	questions := make([]store.SavedQuestion, 0, len(all))
	for _, q := range all {
		if questionAllowed(q.ID) {
			questions = append(questions, q)
		}
	}
	writeJSONResponse(w, listDashboardsResponse{Dashboards: out, Sources: reportSourceCatalog, Questions: questions,
		CanManageAlerts: admin})
}

// getDashboardResponse is what GET /api/dashboards/{id} answers.
type getDashboardResponse struct {
	Dashboard *store.Dashboard `json:"dashboard"`
	Editable  bool             `json:"editable"`
}

// GET /api/dashboards/{id}
func (s *Server) handleGetDashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDashboard(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if d == nil || !s.canViewDashboard(r, d) {
		http.Error(w, "no such dashboard", http.StatusNotFound)
		return
	}
	if !s.requireContent(w, r, "dashboards", d.ID, d.Name) {
		return
	}
	writeJSONResponse(w, getDashboardResponse{Dashboard: d, Editable: s.canEditDashboard(r, d)})
}

type dashboardBody struct {
	Name        string           `json:"name" api:"required"`
	Description string           `json:"description"`
	Shared      *bool            `json:"shared"`
	Panels      []dashboardPanel `json:"panels"`
}

// POST /api/dashboards, PUT /api/dashboards/{id}
func (s *Server) handleSaveDashboard(w http.ResponseWriter, r *http.Request) {
	var body dashboardBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	panels, err := s.validatePanels(r.Context(), body.Panels)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(panels)
	if raw == nil || string(raw) == "null" {
		raw = []byte("[]")
	}
	u := auth.CurrentUser(r.Context())
	d := store.Dashboard{Name: body.Name, Description: strings.TrimSpace(body.Description), Panels: raw, Shared: true, CreatedBy: u.Username}
	if body.Shared != nil {
		d.Shared = *body.Shared
	}
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetDashboard(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such dashboard", http.StatusNotFound)
			return
		}
		if !s.canEditDashboard(r, existing) {
			http.Error(w, "only the author or an administrator can edit this dashboard", http.StatusForbidden)
			return
		}
		d.ID, d.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		d.ID = idgen.New("db-")
	}
	if err := s.store.UpsertDashboard(r.Context(), d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "dashboard.save", Actor: u.Username, Target: d.Name, Severity: "info", Detail: map[string]any{"id": d.ID, "panels": len(panels)}})
	out, _ := s.store.GetDashboard(r.Context(), d.ID)
	writeJSONResponse(w, out)
}

// POST /api/dashboards/{id}/clone
func (s *Server) handleCloneDashboard(w http.ResponseWriter, r *http.Request) {
	src, err := s.store.GetDashboard(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if src == nil || !s.canViewDashboard(r, src) {
		http.Error(w, "no such dashboard", http.StatusNotFound)
		return
	}
	if !s.requireContent(w, r, "dashboards", src.ID, src.Name) {
		return
	}
	panels, _ := decodePanels(src.Panels)
	for i := range panels {
		panels[i].ID = idgen.New("pn-") // fresh ids: samples and alerts belong to the original
	}
	raw, _ := json.Marshal(panels)
	u := auth.CurrentUser(r.Context())
	d := store.Dashboard{ID: idgen.New("db-"), Name: src.Name + " (copy)", Description: src.Description, Panels: raw, Shared: false, CreatedBy: u.Username}
	if err := s.store.UpsertDashboard(r.Context(), d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out, _ := s.store.GetDashboard(r.Context(), d.ID)
	writeJSONResponse(w, out)
}

// DELETE /api/dashboards/{id}
func (s *Server) handleDeleteDashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDashboard(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if d == nil {
		http.Error(w, "no such dashboard", http.StatusNotFound)
		return
	}
	if !s.canEditDashboard(r, d) {
		http.Error(w, "only the author or an administrator can delete this dashboard", http.StatusForbidden)
		return
	}
	if err := s.store.DeleteDashboard(r.Context(), d.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "dashboard.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: d.Name, Severity: "info"})
	w.WriteHeader(http.StatusNoContent)
}

func windowParam(r *http.Request) time.Duration {
	switch r.URL.Query().Get("range") {
	case "24h":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "90d":
		return 90 * 24 * time.Hour
	}
	return 30 * 24 * time.Hour
}

func groupsParam(r *http.Request) []string {
	var out []string
	for _, g := range strings.Split(r.URL.Query().Get("groups"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

// dashboardDataResponse is what GET /api/dashboards/{id}/data answers.
type dashboardDataResponse struct {
	Description string      `json:"description"`
	Editable    bool        `json:"editable"`
	GeneratedAt time.Time   `json:"generated_at"`
	Highlighted int         `json:"highlighted"`
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Panels      []panelData `json:"panels"`
}

// GET /api/dashboards/{id}/data?groups=a,b&range=30d&highlights=1
func (s *Server) handleDashboardData(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDashboard(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if d == nil || !s.canViewDashboard(r, d) {
		http.Error(w, "no such dashboard", http.StatusNotFound)
		return
	}
	if !s.requireContent(w, r, "dashboards", d.ID, d.Name) {
		return
	}
	panels, err := decodePanels(d.Panels)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups := groupsParam(r)
	window := windowParam(r)
	onlyHighlights := r.URL.Query().Get("highlights") == "1"
	out := make([]panelData, 0, len(panels))
	highlighted := 0
	ctx := withExportMemo(r.Context()) // panels over the same source share one read
	for _, p := range panels {
		pd := s.evaluatePanel(ctx, d.ID, p, groups, window)
		if pd.Highlight {
			highlighted++
		}
		if onlyHighlights && !pd.Highlight {
			continue
		}
		out = append(out, pd)
	}
	writeJSONResponse(w, dashboardDataResponse{ID: d.ID, Name: d.Name, Description: d.Description, Panels: out,
		Highlighted: highlighted, GeneratedAt: time.Now().UTC(), Editable: s.canEditDashboard(r, d)})
}

// POST /api/dashboards/preview — evaluate one panel before it is saved.
func (s *Server) handlePanelPreview(w http.ResponseWriter, r *http.Request) {
	var p dashboardPanel
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	panels, err := s.validatePanels(r.Context(), []dashboardPanel{p})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONResponse(w, s.evaluatePanel(r.Context(), "", panels[0], nil, 0))
}

// dashboardColumnsResponse is what GET /api/dashboards/columns answers.
type dashboardColumnsResponse struct {
	Columns []string `json:"columns"`
	Rows    int      `json:"rows"`
}

// GET /api/dashboards/columns?source=&question= — the columns a source
// yields right now, for the group-by pickers.
func (s *Server) handleDashboardColumns(w http.ResponseWriter, r *http.Request) {
	sec := reportSection{Source: r.URL.Query().Get("source"), SavedQuestionID: r.URL.Query().Get("question")}
	rows, err := s.sectionRows(r.Context(), sec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	seen := map[string]bool{}
	var cols []string
	for i, row := range rows {
		if i > 200 {
			break
		}
		for k := range row {
			if !seen[k] {
				seen[k] = true
				cols = append(cols, k)
			}
		}
	}
	if cols == nil {
		cols = []string{}
	}
	sortStrings(cols)
	writeJSONResponse(w, dashboardColumnsResponse{Columns: cols, Rows: len(rows)})
}

// --- alerts ---------------------------------------------------------------

// dashboardAlertsResponse is what GET /api/dashboard-alerts and
// POST /api/dashboard-alerts/evaluate answer.
type dashboardAlertsResponse struct {
	Alerts []store.DashboardAlert `json:"alerts"`
}

func (s *Server) handleListDashboardAlerts(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListDashboardAlerts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, dashboardAlertsResponse{Alerts: list})
}

// saveDashboardAlertRequest is the body of POST /api/dashboard-alerts and
// PUT /api/dashboard-alerts/{id}. A PUT replaces the whole alert: a field
// it leaves out takes its empty value, and enabled left out switches the
// alert off. Send every field, as read from GET /api/dashboard-alerts.
type saveDashboardAlertRequest struct {
	store.DashboardAlert
	// Enabled is true when a create leaves it out. On a PUT, left out is
	// false.
	Enabled *bool `json:"enabled"`
}

func (s *Server) handleSaveDashboardAlert(w http.ResponseWriter, r *http.Request) {
	var req saveDashboardAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in := req.DashboardAlert
	in.Enabled = req.Enabled != nil && *req.Enabled
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	var cond panelThreshold
	if err := json.Unmarshal(in.Condition, &cond); err != nil || !validThresholdOp(cond.Op) {
		http.Error(w, "condition needs an op of gt, gte, lt, lte, eq, zero or nonzero", http.StatusBadRequest)
		return
	}
	switch in.Severity {
	case "critical", "high", "medium", "low":
	default:
		in.Severity = "medium"
	}
	d, err := s.store.GetDashboard(r.Context(), in.DashboardID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if d == nil {
		http.Error(w, "no such dashboard", http.StatusBadRequest)
		return
	}
	panels, _ := decodePanels(d.Panels)
	found := false
	for _, p := range panels {
		if p.ID == in.PanelID && p.Chart != "text" {
			found = true
		}
	}
	if !found {
		http.Error(w, "that panel is not on the dashboard (or is a text panel)", http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetDashboardAlert(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such alert", http.StatusNotFound)
			return
		}
		in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		in.ID, in.CreatedBy = idgen.New("al-"), u.Username
		if req.Enabled == nil {
			in.Enabled = true
		}
	}
	if err := s.store.UpsertDashboardAlert(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "alert.save", Actor: u.Username, Target: in.Name, Severity: "info", Detail: map[string]any{"id": in.ID, "dashboard": d.Name, "severity": in.Severity, "enabled": in.Enabled}})
	// Evaluate straight away so the tray reflects it without waiting for
	// the next Guide pass.
	go s.evaluateGuide(context.WithoutCancel(r.Context()))
	out, err := s.store.GetDashboardAlert(r.Context(), in.ID)
	if err == nil && out == nil {
		err = fmt.Errorf("it was deleted meanwhile")
	}
	if err != nil {
		http.Error(w, "saved, but could not read it back: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteDashboardAlert(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetDashboardAlert(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such alert", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteDashboardAlert(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "alert.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "info"})
	go s.evaluateGuide(context.WithoutCancel(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/dashboard-alerts/evaluate — run the Guide pass over every
// alert now.
func (s *Server) handleEvaluateAlerts(w http.ResponseWriter, r *http.Request) {
	s.evaluateGuide(r.Context())
	list, err := s.store.ListDashboardAlerts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, dashboardAlertsResponse{Alerts: list})
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
