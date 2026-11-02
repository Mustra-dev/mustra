package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/patchpolicy"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// patchPolicyAgentVersion is the first agent that understands a narrowed
// apply_patches (AgentCommand.Patches). An older agent applies everything
// it has pending, so a run the lists would narrow is refused for it rather
// than quietly dispatched unfiltered.
const patchPolicyAgentVersion = "0.44.0"

// patchWaitLimit is how long a patch action may wait for a maintenance
// window before it expires; a window that never opens should not leave a
// deployment open for a week.
const patchWaitLimit = 24 * time.Hour

// --- policy evaluation ------------------------------------------------

// patchPlan is what one endpoint should be told to apply.
type patchPlan struct {
	Pending    int
	Allowed    []string
	Blocked    map[string]string
	Restricted bool
}

// pendingPatchesByAgent reads every endpoint's cached patches snapshot
// once, decorated with the fleet's first-seen dates and the superseded
// flag, so a bulk evaluation costs one query rather than one per device.
func (s *Server) pendingPatchesByAgent(ctx context.Context) (map[string][]patchpolicy.Patch, error) {
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorPatches))
	if err != nil {
		return nil, err
	}
	seen, err := s.store.ListPatchObservations(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]patchpolicy.Patch{}
	var all []patchpolicy.Patch
	index := map[string][]int{} // agent -> indexes into all
	for _, row := range rows {
		var patches []proto.PatchInfo
		if json.Unmarshal(row.Data, &patches) != nil {
			continue
		}
		for _, p := range patches {
			pp := patchpolicy.Patch{Name: p.Name, NewVersion: p.NewVersion, Severity: p.Severity, OS: row.OS}
			if o, ok := seen[store.PatchObservationKey{OS: row.OS, Name: p.Name, NewVersion: p.NewVersion}]; ok {
				pp.FirstSeen = o.FirstSeen
			}
			index[row.AgentID] = append(index[row.AgentID], len(all))
			all = append(all, pp)
		}
	}
	patchpolicy.MarkSuperseded(all)
	for agent, idx := range index {
		for _, i := range idx {
			out[agent] = append(out[agent], all[i])
		}
	}
	return out, nil
}

// policiesByAgent resolves which lists cover which endpoints.
func (s *Server) policiesByAgent(ctx context.Context) (func(agentID string) []patchpolicy.List, error) {
	policies, err := s.store.ListPatchPolicies(ctx)
	if err != nil {
		return nil, err
	}
	type entry struct {
		list    patchpolicy.List
		members map[string]bool // nil = everyone
	}
	var entries []entry
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		members, err := s.agentsInGroups(ctx, p.GroupIDs)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{list: patchpolicy.List{ID: p.ID, Name: p.Name, Kind: p.Kind, Enabled: true, Rules: p.Rules}, members: members})
	}
	return func(agentID string) []patchpolicy.List {
		var out []patchpolicy.List
		for _, e := range entries {
			if e.members == nil || e.members[agentID] {
				out = append(out, e.list)
			}
		}
		return out
	}, nil
}

// planPatches decides, for a set of endpoints, what each may apply.
func (s *Server) planPatches(ctx context.Context, agentIDs []string) (map[string]patchPlan, error) {
	pending, err := s.pendingPatchesByAgent(ctx)
	if err != nil {
		return nil, err
	}
	covering, err := s.policiesByAgent(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := map[string]patchPlan{}
	for _, id := range agentIDs {
		d := patchpolicy.Evaluate(pending[id], covering(id), now)
		plan := patchPlan{Pending: len(pending[id]), Blocked: d.Blocked, Restricted: d.Restricted}
		for _, p := range d.Allowed {
			plan.Allowed = append(plan.Allowed, p.Name)
		}
		out[id] = plan
	}
	return out, nil
}

// --- lists API ----------------------------------------------------------

// patchPolicyView is an entry of what GET /api/patch-policies answers.
type patchPolicyView struct {
	store.PatchPolicy
	Matches int `json:"matches"`
	Members int `json:"members"`
}

// listPatchPoliciesResponse is what GET /api/patch-policies answers.
type listPatchPoliciesResponse struct {
	Policies []patchPolicyView `json:"policies"`
}

func (s *Server) handleListPatchPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListPatchPolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Each list is shown with how many pending patches it currently
	// matches fleet-wide, which is the fastest way to notice a pattern
	// that matches nothing, or everything.
	pending, perr := s.pendingPatchesByAgent(r.Context())
	now := time.Now()
	out := make([]patchPolicyView, 0, len(policies))
	for _, p := range policies {
		v := patchPolicyView{PatchPolicy: p, Members: -1}
		if perr == nil {
			seen := map[string]bool{}
			for _, ps := range pending {
				for _, x := range ps {
					k := x.OS + "|" + x.Name + "|" + x.NewVersion
					if !seen[k] && p.Rules.Match(x, now) {
						seen[k] = true
						v.Matches++
					}
				}
			}
		}
		if set, err := s.agentsInGroups(r.Context(), p.GroupIDs); err == nil && set != nil {
			v.Members = len(set)
		}
		out = append(out, v)
	}
	writeJSONResponse(w, listPatchPoliciesResponse{Policies: out})
}

func validatePatchPolicy(p *store.PatchPolicy) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Kind != "allow" && p.Kind != "block" {
		return fmt.Errorf("kind must be allow (patch list) or block (block list)")
	}
	for _, sev := range p.Rules.Severities {
		if sev != "security" && sev != "" {
			return fmt.Errorf("severity must be security or blank (unclassified)")
		}
	}
	for _, os := range p.Rules.OS {
		if !slices.Contains([]string{"linux", "windows", "darwin"}, os) {
			return fmt.Errorf("os must be linux, windows or darwin")
		}
	}
	clean := p.Rules.NamePatterns[:0]
	for _, pat := range p.Rules.NamePatterns {
		if pat = strings.TrimSpace(pat); pat != "" {
			clean = append(clean, pat)
		}
	}
	p.Rules.NamePatterns = clean
	if p.Rules.MinAgeDays < 0 || p.Rules.MinAgeDays > 365 {
		return fmt.Errorf("minimum age must be 0–365 days")
	}
	if p.GroupIDs == nil {
		p.GroupIDs = []string{}
	}
	return nil
}

// savePatchPolicyResponse is what POST /api/patch-policies and PUT
// /api/patch-policies/{id} answer.
type savePatchPolicyResponse struct {
	ID string `json:"id"`
}

func (s *Server) handleSavePatchPolicy(w http.ResponseWriter, r *http.Request) {
	var in store.PatchPolicy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "invalid list", 400)
		return
	}
	// A POST creates under an ID minted here, whatever the body says; a
	// PUT updates the list it names, which must exist.
	isNew := r.PathValue("id") == ""
	if isNew {
		in.ID = idgen.New("ppl-")
		in.Enabled = true
	} else {
		old, err := s.store.GetPatchPolicy(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if old == nil {
			http.Error(w, "no such list", 404)
			return
		}
		in.ID = old.ID
	}
	if err := validatePatchPolicy(&in); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if !s.requireKnownGroups(w, r, in.GroupIDs) {
		return
	}
	in.CreatedBy = auth.CurrentUser(r.Context()).Username
	if err := s.store.UpsertPatchPolicy(r.Context(), in); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "patch_policy.save", Actor: in.CreatedBy, Target: in.Name, Severity: "notice", Detail: map[string]any{"id": in.ID, "kind": in.Kind, "enabled": in.Enabled, "new": isNew}})
	writeJSONResponse(w, savePatchPolicyResponse{ID: in.ID})
}

func (s *Server) handleDeletePatchPolicy(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetPatchPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if existing == nil {
		http.NotFound(w, r)
		return
	}
	if err := s.store.DeletePatchPolicy(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "patch_policy.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "notice"})
	w.WriteHeader(204)
}

// exportedPatchList is an entry of what GET /api/patch-policies/export
// answers.
type exportedPatchList struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Description string            `json:"description,omitempty"`
	Enabled     bool              `json:"enabled"`
	Groups      []string          `json:"groups,omitempty"` // by name: IDs are not portable
	Rules       patchpolicy.Rules `json:"rules"`
}

// exportPatchPoliciesResponse is what GET /api/patch-policies/export
// answers.
type exportPatchPoliciesResponse struct {
	ExportedAt time.Time           `json:"exported_at"`
	PatchLists []exportedPatchList `json:"patch_lists"`
	Version    int                 `json:"version"`
}

// handleExportPatchPolicies hands the lists over as JSON an operator can
// keep in version control or carry to another mustra.
func (s *Server) handleExportPatchPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListPatchPolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	groups, _ := s.store.ListComputerGroups(r.Context())
	groupName := func(id string) string {
		for _, g := range groups {
			if g.ID == id {
				return g.Name
			}
		}
		return id
	}
	out := []exportedPatchList{}
	for _, p := range policies {
		e := exportedPatchList{Name: p.Name, Kind: p.Kind, Description: p.Description, Enabled: p.Enabled, Rules: p.Rules}
		for _, gid := range p.GroupIDs {
			e.Groups = append(e.Groups, groupName(gid))
		}
		out = append(out, e)
	}
	w.Header().Set("Content-Disposition", `attachment; filename="mustra-patch-lists.json"`)
	writeJSONResponse(w, exportPatchPoliciesResponse{Version: 1, ExportedAt: time.Now().UTC(), PatchLists: out})
}

// importPatchPoliciesRequest is the body of POST /api/patch-policies/import.
type importPatchPoliciesRequest struct {
	PatchLists []importedPatchList `json:"patch_lists"`
}

// importedPatchList is one list of an export.
type importedPatchList struct {
	// Name and Kind find the list to update, the name in any case; a
	// list that matches none is created.
	Name string `json:"name"`
	// Kind is allow (a patch list) or block (a block list).
	Kind        string `json:"kind"`
	Description string `json:"description"`
	// Enabled left out enables the list.
	Enabled *bool `json:"enabled"`
	// Groups are computer groups by name (or ID), so an export moves
	// between servers. One this server does not have refuses the whole
	// import (400): dropped, the list would cover every endpoint.
	Groups []string `json:"groups"`
	// Rules are which patches the list covers.
	Rules patchpolicy.Rules `json:"rules"`
}

// importPatchPoliciesResponse is what POST /api/patch-policies/import
// answers.
type importPatchPoliciesResponse struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	// Warnings is always empty: an unknown group, the one thing that used
	// to warn, now refuses the import. Kept for clients that read it.
	Warnings []string `json:"warnings"`
}

// handleImportPatchPolicies reads an export back. Lists are matched by
// name and kind and updated in place; groups are matched by name, and one
// this mustra does not have refuses the import with a 400 before anything
// is saved.
func (s *Server) handleImportPatchPolicies(w http.ResponseWriter, r *http.Request) {
	var in importPatchPoliciesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&in); err != nil {
		http.Error(w, "invalid import file", 400)
		return
	}
	existing, err := s.store.ListPatchPolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	groups, err := s.store.ListComputerGroups(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	created, updated := 0, 0
	warnings := []string{}
	for _, item := range in.PatchLists {
		p := store.PatchPolicy{Name: item.Name, Kind: item.Kind, Description: item.Description, Enabled: true, Rules: item.Rules, CreatedBy: who}
		if item.Enabled != nil {
			p.Enabled = *item.Enabled
		}
		for _, gname := range item.Groups {
			// Refused, not dropped: a list whose group was dropped would
			// cover every endpoint, which is not what the file said. The
			// action gate refused this already; the check is kept here so
			// the handler is safe on its own.
			gid, ok := patchPolicyGroupID(groups, gname)
			if !ok {
				http.Error(w, fmt.Sprintf("%s: no group named %q here; create it first, or remove it from the file", item.Name, gname), 400)
				return
			}
			p.GroupIDs = append(p.GroupIDs, gid)
		}
		if err := validatePatchPolicy(&p); err != nil {
			http.Error(w, fmt.Sprintf("%s: %v", item.Name, err), 400)
			return
		}
		if i := slices.IndexFunc(existing, func(e store.PatchPolicy) bool { return e.Kind == p.Kind && strings.EqualFold(e.Name, p.Name) }); i >= 0 {
			p.ID = existing[i].ID
			updated++
		} else {
			p.ID = idgen.New("ppl-")
			created++
		}
		if err := s.store.UpsertPatchPolicy(r.Context(), p); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	s.audit(r.Context(), auditEvent{Action: "patch_policy.import", Actor: who, Target: "patch lists", Severity: "notice", Detail: map[string]any{"created": created, "updated": updated}})
	writeJSONResponse(w, importPatchPoliciesResponse{Created: created, Updated: updated, Warnings: warnings})
}

// patchPreviewEndpoint is an entry of what POST /api/patches/deploy/preview
// answers.
type patchPreviewEndpoint struct {
	AgentID     string `json:"agent_id"`
	Hostname    string `json:"hostname"`
	Pending     int    `json:"pending"`
	Allowed     int    `json:"allowed"`
	Blocked     int    `json:"blocked"`
	Waiting     string `json:"waiting,omitempty"`
	AgentTooOld bool   `json:"agent_too_old,omitempty"`
	// Only lists the pending updates the run would install when the
	// request names only_packages; empty there means nothing to install.
	Only []string `json:"only,omitempty"`
}

// patchDeployPreviewResponse is what POST /api/patches/deploy/preview
// answers.
type patchDeployPreviewResponse struct {
	Endpoints []patchPreviewEndpoint `json:"endpoints"`
	Matched   int                    `json:"matched"`
	Totals    map[string]int         `json:"totals"`
}

// handlePatchDeployPreview answers "what would Deploy now do?" for a
// target: per endpoint, how many pending patches are permitted, how many
// the lists block, whether its window is open, and whether its agent can
// honour a narrowed run.
func (s *Server) handlePatchDeployPreview(w http.ResponseWriter, r *http.Request) {
	var req deployPatchesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	agents, err := s.resolvePatchTargets(r.Context(), req.TargetOS, req.TargetSite, req.TargetAgent, req.TargetVulnID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// The preview has to narrow exactly as the deploy will, or it describes
	// a different run from the one the button fires.
	agents = filterToAgents(agents, req.TargetAgents)
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.AgentID)
	}
	plans, err := s.planPatches(r.Context(), ids)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.invalidateWindowGate()
	now := time.Now()
	rows := make([]patchPreviewEndpoint, 0, len(agents))
	totals := map[string]int{}
	for _, a := range agents {
		p := plans[a.AgentID]
		x := patchPreviewEndpoint{AgentID: a.AgentID, Hostname: a.Hostname, Pending: p.Pending, Allowed: len(p.Allowed), Blocked: len(p.Blocked)}
		if !req.OverrideWindows {
			if v := s.windowCheck(r.Context(), a.AgentID, "patch", now); !v.Allowed {
				x.Waiting = v.Reason
				totals["waiting"]++
			}
		}
		if (p.Restricted || req.OnlyPackages != nil) && versionIsNewer(patchPolicyAgentVersion, a.AgentVersion) {
			x.AgentTooOld = true
			totals["agent_too_old"]++
		}
		if req.OnlyPackages != nil {
			x.Only = onlyPatches(p.Allowed, req.OnlyPackages[a.AgentID])
			if len(x.Only) > 0 {
				totals["only"] += len(x.Only)
			} else {
				totals["nothing_to_update"]++
			}
		}
		totals["pending"] += x.Pending
		totals["allowed"] += x.Allowed
		totals["blocked"] += x.Blocked
		rows = append(rows, x)
	}
	writeJSONResponse(w, patchDeployPreviewResponse{Endpoints: rows, Totals: totals, Matched: len(agents)})
}

// --- waiting actions ---------------------------------------------------

// patchWaitLoop releases patch actions that were held for a maintenance
// window once it opens, and expires the ones that waited too long.
// abandonedActionAfter is when an open action is given up on. Far past
// deploymentStallAfter: a slow Windows Update can take hours, and closing
// a job that then reports would lose its real result.
const abandonedActionAfter = 24 * time.Hour

func (s *Server) patchWaitLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var lastSweep time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if time.Since(lastSweep) >= 10*time.Minute {
			lastSweep = time.Now()
			n, err := s.store.SweepAbandonedActions(ctx, abandonedActionAfter,
				"No result from the endpoint within 24 hours; it probably restarted mid-job (an agent update or a reboot). Run it again if it is still needed.")
			if err != nil {
				s.logger.Warn("sweep abandoned actions", "error", err)
			} else if n > 0 {
				s.logger.Info("closed abandoned actions", "count", n)
			}
		}
		waiting, err := s.store.WaitingAgentActions(ctx, "patch_apply")
		if err != nil {
			s.logger.Warn("list waiting patch actions", "error", err)
			continue
		}
		if len(waiting) == 0 {
			continue
		}
		agents, err := s.store.ListAgents(ctx, s.staleAfter())
		if err != nil {
			continue
		}
		byID := map[string]store.AgentRecord{}
		for _, a := range agents {
			byID[a.AgentID] = a
		}
		now := time.Now()
		for _, act := range waiting {
			if now.Sub(act.StartedAt) > patchWaitLimit {
				_ = s.store.FinishAgentAction(ctx, act.AgentID, act.ID, "expired", "Maintenance window did not open within 24 hours")
				continue
			}
			if v := s.windowCheck(ctx, act.AgentID, "patch", now); !v.Allowed {
				if act.Detail != v.Reason {
					_ = s.store.SetAgentActionProgress(ctx, act.AgentID, act.ID, "waiting", v.Reason)
				}
				continue
			}
			a, ok := byID[act.AgentID]
			if !ok || !a.Online {
				continue // the next tick will try again while the window stays open
			}
			var restart patchRestart
			if mode, warn, err := s.store.ActionRestart(ctx, act.ID); err == nil {
				restart = patchRestart{Mode: mode, WarnMinutes: warn}
			}
			only, err := s.store.ActionPatchOnly(ctx, act.ID)
			if err != nil {
				// Not knowing which packages it was for, the job must not
				// fall back to patching everything.
				_ = s.store.FinishAgentAction(ctx, act.AgentID, act.ID, "failed", "could not read which packages to update: "+err.Error())
				continue
			}
			s.dispatchPatchApply(ctx, a, act.RunID, act.ID, restart, only)
		}
	}
}

// patchUnsupportedReason says why an endpoint can never take an
// apply_patches job, or "" when it can. Home Assistant OS updates as one
// signed image through the Supervisor; its add-on agent sees no apt, dnf
// or yum, so a dispatched job could only fail with "no supported package
// manager". Skipping it with the real reason keeps the deployment honest.
// haosPatchesAgentVersion is the first agent that reports Home Assistant's
// pending updates (OS, Core, Supervisor, add-ons) as its patch list; older
// add-on agents report none, so a rescan of them could only fail.
const haosPatchesAgentVersion = "0.57.15"

func patchUnsupportedReason(a store.AgentRecord) string {
	if a.Platform == "haos" {
		return "Home Assistant OS is not patched package by package; update it from Home Assistant (Settings → System → Updates)"
	}
	return ""
}

// dispatchPatchApply sends one endpoint its apply_patches command with the
// lists applied, recording every way that can not happen as the action's
// outcome. It is the single path every patch deployment goes through:
// bulk, scheduled, single-device, and released-from-waiting.
//
// only, when not nil, narrows the job to the pending updates for those
// packages (patch_only.go).
func (s *Server) dispatchPatchApply(ctx context.Context, a store.AgentRecord, runID, actionID string, restart patchRestart, only []string) (ok bool, reason string) {
	fail := func(status, why string) (bool, string) {
		if err := s.store.FinishAgentAction(ctx, a.AgentID, actionID, status, why); err != nil {
			s.logger.Warn("finish patch action failed", "agent_id", a.AgentID, "error", err)
		}
		return false, why
	}
	if why := patchUnsupportedReason(a); why != "" {
		return fail("skipped", why)
	}
	plans, err := s.planPatches(ctx, []string{a.AgentID})
	if err != nil {
		return fail("failed", "could not evaluate patch lists: "+err.Error())
	}
	plan := plans[a.AgentID]
	if why := restart.unsupportedReason(a); why != "" {
		return fail("failed", why)
	}
	cmd := proto.AgentCommand{Cmd: "apply_patches", RunID: runID, ActionID: actionID, RebootMode: restart.Mode, RebootWarnMinutes: restart.WarnMinutes}
	if a.OS == "darwin" {
		if fleet, _, err := s.fleetConfig(ctx); err == nil && fleet != nil && fleet.canInstallMacOS(ctx, a.PlatformVersion) {
			cmd.MacOSViaMDM = true
		}
	}
	if plan.Restricted {
		if versionIsNewer(patchPolicyAgentVersion, a.AgentVersion) {
			return fail("failed", fmt.Sprintf("agent %s cannot honour patch lists (needs %s or newer); update the agent or remove the lists covering this endpoint", a.AgentVersion, patchPolicyAgentVersion))
		}
		cmd.Selective = true
		cmd.Patches = plan.Allowed
		if len(plan.Allowed) == 0 {
			return fail("skipped", fmt.Sprintf("No pending patches are permitted by the patch lists that cover this endpoint (%d pending, all blocked)", plan.Pending))
		}
	}
	if only != nil {
		// An agent too old to take a list would install everything.
		if versionIsNewer(patchPolicyAgentVersion, a.AgentVersion) {
			return fail("failed", fmt.Sprintf("agent %s cannot update only some packages (needs %s or newer); update the agent, or patch everything pending", a.AgentVersion, patchPolicyAgentVersion))
		}
		picked := onlyPatches(plan.Allowed, only)
		if len(picked) == 0 {
			why := fmt.Sprintf("No pending update for %s on this endpoint", strings.Join(only, ", "))
			if len(plan.Blocked) > 0 {
				why += " that the patch lists permit"
			}
			return fail("skipped", why+"; a patch scan may not have seen the fix yet, or it comes from outside the operating system's updater")
		}
		cmd.Selective = true
		cmd.Patches = picked
	}
	payload, err := json.Marshal(cmd)
	if err != nil {
		return fail("failed", err.Error())
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(a.AgentID), payload)
	if err != nil {
		return fail("failed", "did not respond: "+err.Error())
	}
	var result proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return fail("failed", "malformed response: "+err.Error())
	}
	if !result.OK {
		return fail("failed", "rejected: "+result.Error)
	}
	detail := "Endpoint accepted the job"
	switch {
	case only != nil:
		detail = "Endpoint accepted the job: updating " + strings.Join(cmd.Patches, ", ")
	case cmd.Selective:
		detail = fmt.Sprintf("Endpoint accepted the job: %d of %d pending patches permitted by patch lists, %d blocked", len(plan.Allowed), plan.Pending, len(plan.Blocked))
	}
	_ = s.store.SetAgentActionProgress(ctx, a.AgentID, actionID, "started", detail)
	return true, ""
}

// patchPolicyGroupID finds a computer group by name (case-insensitively)
// or by id, as an import names them.
func patchPolicyGroupID(groups []store.ComputerGroup, name string) (string, bool) {
	i := slices.IndexFunc(groups, func(g store.ComputerGroup) bool { return strings.EqualFold(g.Name, name) || g.ID == name })
	if i < 0 {
		return "", false
	}
	return groups[i].ID, true
}
