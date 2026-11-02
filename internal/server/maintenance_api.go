package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/maintenance"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Maintenance windows say when an endpoint may be touched. The rule the
// dispatchers apply:
//
//   - a window restricts only the endpoints in its groups (no groups =
//     every endpoint), and only while it is in effect: a recurring window
//     from its start date on, a one-time window from when it is saved
//     until it closes; an endpoint no enabled window in effect covers is
//     unrestricted;
//   - an endpoint covered by several windows may be touched while any one
//     of them is open;
//   - a deployment marked override_windows ignores all of this, and only a
//     user holding deploy.override_windows may mark one.
//
// windowGate resolves group membership once per evaluation and caches it
// briefly, because the Deploy dispatcher asks every five seconds for every
// queued job and group rules can be expensive to evaluate.

type windowGate struct {
	mu       sync.Mutex
	at       time.Time
	windows  []store.MaintenanceWindow
	members  map[string]map[string]bool // window id -> agent ids (nil = every endpoint)
	agents   map[string]store.AgentZone // agent id -> OS and reported time zone
	lastErr  error
	cacheTTL time.Duration
}

type windowVerdict struct {
	Allowed bool
	// Reason is set when not allowed: which window(s) apply and when the
	// nearest one next opens.
	Reason string
	// NextOpen is the earliest next opening among the windows that cover
	// the endpoint; zero when unknown.
	NextOpen time.Time
}

func (s *Server) refreshWindowGate(ctx context.Context) error {
	g := &s.windows
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cacheTTL == 0 {
		g.cacheTTL = 30 * time.Second
	}
	if time.Since(g.at) < g.cacheTTL {
		return g.lastErr
	}
	windows, err := s.store.ListMaintenanceWindows(ctx)
	if err != nil {
		g.lastErr = err
		g.at = time.Now()
		return err
	}
	agents, err := s.store.AgentZones(ctx)
	if err != nil {
		g.lastErr = err
		g.at = time.Now()
		return err
	}
	members := map[string]map[string]bool{}
	for _, w := range windows {
		if !w.Enabled {
			continue
		}
		set, err := s.agentsInGroups(ctx, w.GroupIDs)
		if err != nil {
			g.lastErr = err
			g.at = time.Now()
			return err
		}
		members[w.ID] = set
	}
	g.windows, g.members, g.agents, g.lastErr, g.at = windows, members, agents, nil, time.Now()
	return nil
}

// windowCheck decides whether an endpoint may receive work of the given
// kind ("deploy" or "patch") right now. A store failure fails open with a
// logged warning: a broken window table must not silently freeze every
// deployment in the fleet, and the failure is loud in the log.
func (s *Server) windowCheck(ctx context.Context, agentID, kind string, now time.Time) windowVerdict {
	if err := s.refreshWindowGate(ctx); err != nil {
		s.logger.Warn("maintenance windows unavailable; allowing dispatch", "error", err)
		return windowVerdict{Allowed: true}
	}
	g := &s.windows
	g.mu.Lock()
	windows, members, agents := g.windows, g.members, g.agents
	g.mu.Unlock()
	zone := agents[agentID]

	// pending are the windows that cover the endpoint but are not in
	// effect yet; one of them may still open before any covering one.
	var covering, pending []store.MaintenanceWindow
	for _, w := range windows {
		if !w.Enabled || !slices.Contains(w.AppliesTo, kind) {
			continue
		}
		set, ok := members[w.ID]
		if !ok {
			continue
		}
		if set != nil && !set[agentID] {
			continue
		}
		// A platform window covers only that platform's endpoints.
		if w.Platform != "" && zone.OS != "" && w.Platform != zone.OS {
			continue
		}
		// Before a recurring window's effective date, or once a one-time
		// window is over, a window restricts nothing: it would otherwise hold the endpoint
		// closed with no opening to wait for, until its jobs expired.
		if !engineWindow(w).InEffectIn(now, windowLocation(w, zone)) {
			pending = append(pending, w)
			continue
		}
		covering = append(covering, w)
	}
	if len(covering) == 0 {
		return windowVerdict{Allowed: true}
	}
	var next time.Time
	names := []string{}
	for _, w := range covering {
		mw, loc := engineWindow(w), windowLocation(w, zone)
		if mw.OpenIn(now, loc) {
			return windowVerdict{Allowed: true}
		}
		names = append(names, w.Name)
		if t, ok := mw.NextOpenIn(now, loc); ok && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	// Named only when it opens first, so the reason names what it waits for.
	soonest := ""
	for _, w := range pending {
		if t, ok := engineWindow(w).NextOpenIn(now, windowLocation(w, zone)); ok && (next.IsZero() || t.Before(next)) {
			next, soonest = t, w.Name
		}
	}
	if soonest != "" {
		names = append(names, soonest)
	}
	reason := "Waiting for maintenance window " + strings.Join(names, " or ")
	if !next.IsZero() {
		reason += "; next opens " + next.UTC().Format("Mon 2006-01-02 15:04 UTC")
	}
	return windowVerdict{Allowed: false, Reason: reason, NextOpen: next}
}

// engineWindow is a stored window as internal/maintenance evaluates it.
func engineWindow(w store.MaintenanceWindow) maintenance.Window {
	return maintenance.Window{Recurrence: w.Recurrence, Interval: w.Interval, Weekdays: w.Weekdays, Start: w.StartTime,
		StartDate: w.StartDate, DurationMinutes: w.DurationMinutes, MonthDay: w.MonthDay, MonthWeek: w.MonthWeek,
		MonthWeekday: w.MonthWeekday, Timezone: w.Timezone, NoDST: !w.ObserveDST}
}

// windowLocation is the zone a window is read in for one endpoint: the
// window's own, or for an endpoint-local window the endpoint's reported
// zone (by name, else its reported offset), falling back to the window's
// zone for an endpoint that has not reported one.
func windowLocation(w store.MaintenanceWindow, zone store.AgentZone) *time.Location {
	fallback := time.UTC
	if loc, err := time.LoadLocation(w.Timezone); err == nil && w.Timezone != "" {
		fallback = loc
	}
	pin := func(loc *time.Location) *time.Location {
		if !w.ObserveDST {
			return maintenance.StandardTime(loc)
		}
		return loc
	}
	if w.TimeBase != "endpoint" {
		return pin(fallback)
	}
	if zone.Timezone != "" {
		if loc, err := time.LoadLocation(zone.Timezone); err == nil {
			return pin(loc)
		}
	}
	if zone.UTCOffsetSeconds != nil {
		return time.FixedZone("endpoint", *zone.UTCOffsetSeconds)
	}
	return pin(fallback)
}

// invalidateWindowGate drops the cache after an edit so the change is felt
// on the next dispatcher tick rather than half a minute later.
func (s *Server) invalidateWindowGate() {
	s.windows.mu.Lock()
	s.windows.at = time.Time{}
	s.windows.mu.Unlock()
}

// canOverrideWindows is whether the request's user may mark a deployment
// as ignoring maintenance windows.
func (s *Server) canOverrideWindows(r *http.Request) bool {
	u := auth.CurrentUser(r.Context())
	if u == nil {
		return false
	}
	ok, err := s.auth.HasPermission(r.Context(), u, auth.PermDeployOverride)
	return err == nil && ok
}

// --- Windows API -----------------------------------------------------

// maintenanceWindowView is an entry of what GET /api/maintenance-windows
// answers.
type maintenanceWindowView struct {
	store.MaintenanceWindow
	OpenNow  bool       `json:"open_now"`
	NextOpen *time.Time `json:"next_open,omitempty"`
	Members  int        `json:"members"`
}

// listMaintenanceWindowsResponse is what GET /api/maintenance-windows
// answers.
type listMaintenanceWindowsResponse struct {
	CanOverride bool                    `json:"can_override"`
	Windows     []maintenanceWindowView `json:"windows"`
}

func (s *Server) handleListMaintenanceWindows(w http.ResponseWriter, r *http.Request) {
	windows, err := s.store.ListMaintenanceWindows(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	now := time.Now()
	out := make([]maintenanceWindowView, 0, len(windows))
	for _, mwin := range windows {
		// An endpoint-local window is shown in its fallback zone here; each
		// endpoint reads it in its own when deciding.
		mw := engineWindow(mwin)
		v := maintenanceWindowView{MaintenanceWindow: mwin, OpenNow: mw.Open(now)}
		if t, ok := mw.NextOpen(now); ok {
			v.NextOpen = &t
		}
		if set, err := s.agentsInGroups(r.Context(), mwin.GroupIDs); err == nil {
			if set == nil {
				v.Members = -1 // every endpoint
			} else {
				v.Members = len(set)
			}
		}
		out = append(out, v)
	}
	writeJSONResponse(w, listMaintenanceWindowsResponse{Windows: out, CanOverride: s.canOverrideWindows(r)})
}

// saveMaintenanceWindowResponse is what POST /api/maintenance-windows and
// PUT /api/maintenance-windows/{id} answer.
type saveMaintenanceWindowResponse struct {
	ID string `json:"id"`
}

func (s *Server) handleSaveMaintenanceWindow(w http.ResponseWriter, r *http.Request) {
	var in store.MaintenanceWindow
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || json.Unmarshal(raw, &in) != nil {
		http.Error(w, "invalid window", 400)
		return
	}
	// A POST creates under an ID minted here, whatever the body says; a
	// PUT updates the window it names, which must exist.
	var old *store.MaintenanceWindow
	if id := r.PathValue("id"); id != "" {
		if old, err = s.store.GetMaintenanceWindow(r.Context(), id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if old == nil {
			http.Error(w, "no such window", 404)
			return
		}
		in.ID = old.ID
	} else {
		in.ID = idgen.New("mw-")
		in.Enabled = true
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", 400)
		return
	}
	if strings.TrimSpace(in.Timezone) == "" {
		in.Timezone = "UTC"
	}
	if in.Interval < 1 {
		in.Interval = 1
	}
	// observe_dst left out keeps what is stored (true for a new window):
	// its JSON zero value would otherwise switch DST off for a client that
	// predates the field.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if _, given := fields["observe_dst"]; !given {
		in.ObserveDST = old == nil || old.ObserveDST
	}
	switch in.Platform {
	case "", "windows", "darwin", "linux":
	default:
		http.Error(w, "platform must be windows, darwin or linux", 400)
		return
	}
	switch in.TimeBase {
	case "":
		in.TimeBase = "zone"
	case "zone", "endpoint":
	default:
		http.Error(w, "time_base must be zone or endpoint", 400)
		return
	}
	mw := engineWindow(in)
	if err := mw.Validate(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if len(in.AppliesTo) == 0 {
		in.AppliesTo = []string{"deploy", "patch"}
	}
	for _, k := range in.AppliesTo {
		if k != "deploy" && k != "patch" {
			http.Error(w, "applies_to entries must be deploy or patch", 400)
			return
		}
	}
	if in.GroupIDs == nil {
		in.GroupIDs = []string{}
	}
	if !s.requireKnownGroups(w, r, in.GroupIDs) {
		return
	}
	if in.Weekdays == nil {
		in.Weekdays = []int{}
	}
	in.CreatedBy = auth.CurrentUser(r.Context()).Username
	if err := s.store.UpsertMaintenanceWindow(r.Context(), in); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.invalidateWindowGate()
	s.audit(r.Context(), auditEvent{Action: "maintenance_window.save", Actor: in.CreatedBy, Target: in.Name, Severity: "notice", Detail: map[string]any{"id": in.ID, "enabled": in.Enabled, "groups": len(in.GroupIDs)}})
	writeJSONResponse(w, saveMaintenanceWindowResponse{ID: in.ID})
}

func (s *Server) handleDeleteMaintenanceWindow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.store.GetMaintenanceWindow(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if existing == nil {
		http.NotFound(w, r)
		return
	}
	if err := s.store.DeleteMaintenanceWindow(r.Context(), id); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.invalidateWindowGate()
	s.audit(r.Context(), auditEvent{Action: "maintenance_window.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "notice"})
	w.WriteHeader(204)
}

// maintenanceWindowCheckRequest is the body of POST /api/maintenance-windows/check.
type maintenanceWindowCheckRequest struct {
	AgentIDs []string `json:"agent_ids"`
	Kind     string   `json:"kind"`
}

// maintenanceWindowCheckResponse is what POST
// /api/maintenance-windows/check answers.
type maintenanceWindowCheckResponse struct {
	CanOverride bool              `json:"can_override"`
	Checked     int               `json:"checked"`
	Waiting     map[string]string `json:"waiting"`
}

// handleMaintenanceWindowCheck answers "may these endpoints be touched
// now?" so the deployment form can warn before the operator commits.
func (s *Server) handleMaintenanceWindowCheck(w http.ResponseWriter, r *http.Request) {
	var req maintenanceWindowCheckRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if req.Kind == "" {
		req.Kind = "deploy"
	}
	s.invalidateWindowGate()
	now := time.Now()
	waiting := map[string]string{}
	for _, id := range req.AgentIDs {
		if v := s.windowCheck(r.Context(), id, req.Kind, now); !v.Allowed {
			waiting[id] = v.Reason
		}
	}
	writeJSONResponse(w, maintenanceWindowCheckResponse{Checked: len(req.AgentIDs), Waiting: waiting, CanOverride: s.canOverrideWindows(r)})
}

// --- Templates API ---------------------------------------------------

// listDeploymentTemplatesResponse is what GET /api/deploy/templates
// answers.
type listDeploymentTemplatesResponse struct {
	CanOverride bool                       `json:"can_override"`
	Templates   []store.DeploymentTemplate `json:"templates"`
}

func (s *Server) handleListDeploymentTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.store.ListDeploymentTemplates(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSONResponse(w, listDeploymentTemplatesResponse{Templates: templates, CanOverride: s.canOverrideWindows(r)})
}

// saveDeploymentTemplateResponse is what POST /api/deploy/templates and PUT
// /api/deploy/templates/{id} answer.
type saveDeploymentTemplateResponse struct {
	ID string `json:"id"`
}

func (s *Server) handleSaveDeploymentTemplate(w http.ResponseWriter, r *http.Request) {
	var in store.DeploymentTemplate
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "invalid template", 400)
		return
	}
	// A POST creates under an ID minted here, whatever the body says; a
	// PUT updates the template it names, which must exist.
	if id := r.PathValue("id"); id != "" {
		old, err := s.store.GetDeploymentTemplate(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if old == nil {
			http.Error(w, "no such template", 404)
			return
		}
		in.ID = old.ID
	} else {
		in.ID = idgen.New("dtpl-")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", 400)
		return
	}
	if in.Operation != "" && !slices.Contains([]string{"install", "update", "remove", "run"}, in.Operation) {
		http.Error(w, "invalid operation", 400)
		return
	}
	if in.ExpireSeconds < 0 || in.ExpireSeconds > 31536000 {
		http.Error(w, "expiry must be 0–31536000 seconds", 400)
		return
	}
	if in.PackageID != "" {
		pkg, err := s.store.GetSoftwarePackage(r.Context(), in.PackageID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if pkg == nil {
			http.Error(w, "unknown package", 400)
			return
		}
	}
	if in.PlanID != "" {
		plan, err := s.store.GetDeploymentPlan(r.Context(), in.PlanID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if plan == nil {
			http.Error(w, "unknown deployment plan", 400)
			return
		}
	}
	// The override flag is stored with the template but is only honoured
	// at deploy time for a user who holds the permission then; a template
	// cannot launder a permission its user does not have. Refusing it
	// here keeps the saved template honest about what it will do.
	if in.OverrideWindows && !s.canOverrideWindows(r) {
		http.Error(w, "you do not hold "+auth.PermDeployOverride+", so a template you save cannot override maintenance windows", 403)
		return
	}
	if in.Parameters == nil {
		in.Parameters = map[string]string{}
	}
	in.CreatedBy = auth.CurrentUser(r.Context()).Username
	if err := s.store.UpsertDeploymentTemplate(r.Context(), in); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "deployment_template.save", Actor: in.CreatedBy, Target: in.Name, Severity: "info", Detail: map[string]any{"id": in.ID, "default": in.IsDefault}})
	writeJSONResponse(w, saveDeploymentTemplateResponse{ID: in.ID})
}

func (s *Server) handleDeleteDeploymentTemplate(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteDeploymentTemplate(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}

// requireOverride turns a request's override flag into an authorization
// decision: the flag stays set only for a user who may set it.
func (s *Server) requireOverride(w http.ResponseWriter, r *http.Request, override bool) (ok bool) {
	if !override {
		return true
	}
	if s.canOverrideWindows(r) {
		return true
	}
	http.Error(w, fmt.Sprintf("overriding maintenance windows needs the %s permission", auth.PermDeployOverride), 403)
	return false
}
