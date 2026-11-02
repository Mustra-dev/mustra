package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// endpointActionRoutes is every route that sends work to endpoints, or
// saves a definition the server will later send unattended, with how its
// request names its targets. routeTable.Handle wraps each of these in the
// shared gate (action_authz.go) inside its permission check, and refuses
// to start if one is registered without a permission wrapper.
//
// Adding a route that reaches the bus means adding it here;
// TestEndpointActionRoutesAreGated lists the handlers that dispatch and
// fails when one is registered without a gate.
func (s *Server) endpointActionRoutes() map[string]actionSpec {
	explicitThen := explicitOnlyHandledByCaller
	return map[string]actionSpec{
		// --- deployment ---------------------------------------------------
		// These handlers resolve applicability themselves and call
		// authorizeEndpointAction again with the final list (narrowing a
		// fleet-wide run, then approvals). The gate refuses named
		// endpoints out of reach before any work is done.
		"POST /api/deploy/run":                                     {Module: "deploy", Resolve: explicitThen("agent_ids")},
		"POST /api/deploy/preview":                                 {Module: "deploy", Resolve: explicitThen("agent_ids")},
		"POST /api/deploy/test":                                    {Module: "deploy", Resolve: explicitThen("agent_ids")},
		"POST /api/software/deploy":                                {Module: "deploy", Resolve: explicitThen("agent_ids")},
		"POST /api/software-inventory/product/{key}/remove-unused": {Module: "deploy", Resolve: explicitThen()},
		"POST /api/patches/deploy":                                 {Module: "patches", Resolve: explicitThen("target_agents", "target_agent")},
		"POST /api/patches/deploy/preview":                         {Module: "patches", Resolve: explicitThen("target_agents", "target_agent")},
		"POST /api/playbooks/{id}/run":                             {Module: "playbooks", Resolve: explicitThen("agent_ids")},
		"POST /api/shell/sessions":                                 {Module: "shell", Resolve: explicitThen("agent_id")},
		"POST /api/remote/sessions":                                {Module: "shell", Resolve: explicitThen("agent_id")},
		"POST /api/certificates/managed":                           {Module: "deploy", Resolve: explicitThen("agent_id")},
		"PUT /api/certificates/managed/{id}":                       {Module: "deploy", Resolve: explicitThen("agent_id")},
		"POST /api/certificates/managed/{id}/renew":                {Module: "deploy", Resolve: resolveManagedCert},
		"POST /api/certificates/managed/{id}/upload":               {Module: "deploy", Resolve: resolveManagedCert},
		// An app credential in push mode names an endpoint its renewal
		// writes to and runs a reload command on, unattended once saved.
		"POST /api/certificates/apps/credentials":            {Module: "deploy", Resolve: resolveAppCredSave},
		"PUT /api/certificates/apps/credentials/{id}":        {Module: "deploy", Resolve: resolveAppCredSave},
		"POST /api/certificates/apps/credentials/{id}/renew": {Module: "deploy", Resolve: resolveAppCredRenew},
		"POST /api/jump/requests":                            {Module: "shell", Resolve: explicitThen("agent_id")},
		// Ownership and the Jump Gate window are the handler's; the gate
		// re-applies rights and the shell action group per command.
		"POST /api/shell/sessions/{id}/exec": {Module: "shell", Resolve: resolveShellSession},

		// --- single-endpoint actions --------------------------------------
		"POST /api/agents/{id}/apply-patches": {Module: "patches", Resolve: pathAgent("id")},
		"POST /api/agents/{id}/kill-process":  {Module: "shell", Resolve: pathAgent("id")},
		"POST /api/agents/{id}/update":        {Module: "deploy", Resolve: pathAgent("id")},
		// Intune restarts or syncs the endpoint: an act on it, gated like one.
		"POST /api/agents/{id}/intune/{action}": {Module: "deploy", Resolve: pathAgent("id")},
		"POST /api/sensors/custom/test":         {Module: "deploy", Resolve: bodyAgentsOrFleet([]string{"agent_id"}, nil, false)},
		// The endpoint's own record and settings: management rights only.
		"POST /api/agents/{id}/sensor-interval": {Resolve: pathAgent("id")},
		"DELETE /api/agents/{id}":               {Resolve: pathAgent("id")},
		"POST /api/agents/{id}/managed":         {Resolve: pathAgent("id")},
		"PUT /api/agents/{id}/attributes":       {Resolve: pathAgent("id")},
		// Revoking a credential cuts the endpoint off the bus until it is
		// re-enrolled, and criticality reweights its risk for everyone: both
		// are acts on that endpoint, so both stay inside management rights.
		"POST /api/agents/{id}/revoke-credential": {Resolve: pathAgent("id")},
		"POST /api/risk/criticality":              {Resolve: bodyAgentsOrFleet([]string{"agent_id"}, nil, false)},

		// --- fleet-wide actions -------------------------------------------
		"POST /api/agents/update-outdated": {Module: "deploy", Resolve: fleetOnly},
		// A root set to every endpoint keeps reaching endpoints enrolled
		// later, unattended: a fleet-wide definition.
		"POST /api/certificates/trust/{id}": {Module: "deploy", Resolve: fleetOnly},
		// Each endpoint's own benchmark; named endpoints, else the fleet.
		"POST /api/compliance/scan":              {Resolve: bodyAgentsOrFleet([]string{"agent_ids"}, nil, true)},
		"POST /api/clients/upgrade":              {Module: "deploy", Resolve: fleetOnly},
		"POST /api/clients/profiles/apply":       {Resolve: fleetOnly},
		"PUT /api/deploy/settings":               {Resolve: fleetOnly},
		"POST /api/integrity/watch-status/apply": {Resolve: fleetOnly},
		"POST /api/compliance/policies/{id}/run": {Resolve: fleetOnly},
		"POST /api/enforce/policies/{id}/run":    {Module: "enforce", Resolve: resolveEnforceRun},
		"POST /api/reveal/rules/{id}/run":        {Module: "reveal", Resolve: resolveRevealRun, NarrowField: "agent_ids"},
		"POST /api/reveal/search":                {Module: "reveal", Resolve: bodyAgentsOrFleet([]string{"agent_ids"}, []string{"group_ids"}, true), NarrowField: "agent_ids"},
		"POST /api/eun/{id}/send":                {Module: "deploy", Resolve: bodyAgentsOrFleet([]string{"agent_ids"}, nil, true), NarrowField: "agent_ids"},
		"POST /api/surveys/{id}/send":            {Module: "deploy", Resolve: bodyAgentsOrFleet([]string{"agent_ids"}, []string{"group_id"}, false)},
		"POST /api/schedules/{id}/run":           {Module: "deploy", Resolve: resolveScheduledActionRun},
		"POST /api/catalog/requests/{id}/decide": {Module: "deploy", Resolve: resolveCatalogDecision},

		// --- definitions the server runs later, unattended ----------------
		// Saving one is checked against what it targets now; no approval
		// is asked for (nothing runs yet), and the unattended runs apply
		// the module's action group when they fire.
		"POST /api/schedules":         {Module: "deploy", Resolve: definition(resolveScheduledActionBody)},
		"PUT /api/schedules/{id}":     {Module: "deploy", Resolve: definition(resolveScheduledActionBody)},
		"POST /api/patches/schedules": {Module: "patches", Resolve: definition(bodyAgentsOrFleet([]string{"target_agents", "target_agent"}, nil, false))},
		// A repository list assignment points endpoints at the package
		// repositories their scans and patch runs then install from, as
		// root: an action on every endpoint it matches.
		"POST /api/patches/list-assignments": {Module: "patches", Resolve: definition(resolvePatchListAssignment)},
		// A patch list (allow or block) decides what its groups' endpoints
		// receive; one with no groups decides for every endpoint.
		"POST /api/patch-policies":        {Module: "patches", Resolve: definition(bodyAgentsOrFleet(nil, []string{"group_ids"}, false))},
		"PUT /api/patch-policies/{id}":    {Module: "patches", Resolve: definition(bodyAgentsOrFleet(nil, []string{"group_ids"}, false))},
		"DELETE /api/patch-policies/{id}": {Module: "patches", Resolve: definition(resolvePatchPolicy)},
		"POST /api/patch-policies/import": {Module: "patches", Resolve: definition(resolvePatchPolicyImport)},
		// Re-enabling or deleting a schedule changes what runs unattended
		// on its endpoints, so both cost what creating it cost.
		"POST /api/patches/schedules/{id}/enabled": {Module: "patches", Resolve: definition(resolvePatchSchedule)},
		"DELETE /api/patches/schedules/{id}":       {Module: "patches", Resolve: definition(resolvePatchSchedule)},
		"POST /api/enforce/policies":               {Module: "enforce", Resolve: definition(bodyAgentsOrFleet(nil, []string{"group_id"}, false))},
		"PUT /api/enforce/policies/{id}":           {Module: "enforce", Resolve: definition(bodyAgentsOrFleet(nil, []string{"group_id"}, false))},
		"POST /api/reveal/rules":                   {Module: "reveal", Resolve: definition(bodyAgentsOrFleet(nil, []string{"group_ids"}, false))},
		// A rule set writes its groups onto its rules, so saving one
		// targets exactly as saving a rule does; no groups means the fleet.
		"POST /api/reveal/rule-sets":     {Module: "reveal", Resolve: definition(bodyAgentsOrFleet(nil, []string{"group_ids"}, false))},
		"PUT /api/reveal/rule-sets/{id}": {Module: "reveal", Resolve: definition(bodyAgentsOrFleet(nil, []string{"group_ids"}, false))},
		"POST /api/sensors/custom":       {Resolve: definition(fleetOnly)},
		"PUT /api/sensors/custom/{id}":   {Resolve: definition(fleetOnly)},
		"POST /api/clients/profiles":     {Resolve: definition(bodyAgentsOrFleet(nil, []string{"group_ids"}, false))},
		"PUT /api/clients/profiles/{id}": {Resolve: definition(bodyAgentsOrFleet(nil, []string{"group_ids"}, false))},
	}
}

// definition marks a resolver's action as a saved definition: checked
// for reach, never parked for approval.
func definition(inner func(*Server, *http.Request, []byte) (endpointAction, error)) func(*Server, *http.Request, []byte) (endpointAction, error) {
	return func(s *Server, r *http.Request, body []byte) (endpointAction, error) {
		a, err := inner(s, r, body)
		a.ApprovalByCaller = true
		a.NarrowFleet = false
		return a, err
	}
}

func resolveEnforceRun(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	p, err := s.store.GetEnforcePolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		return endpointAction{}, err
	}
	if p == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such policy"}
	}
	pol := *p
	return endpointAction{Summary: "enforce " + pol.Name, Fleet: func(ctx context.Context) ([]string, error) {
		agents, err := s.enforceTargets(ctx, pol)
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(agents))
		for _, a := range agents {
			ids = append(ids, a.AgentID)
		}
		return ids, nil
	}}, nil
}

func resolveRevealRun(s *Server, r *http.Request, body []byte) (endpointAction, error) {
	rule, err := s.store.GetRevealRule(r.Context(), r.PathValue("id"))
	if err != nil {
		return endpointAction{}, err
	}
	if rule == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such rule"}
	}
	groupIDs := rule.GroupIDs
	return endpointAction{Summary: "reveal " + rule.Name, Explicit: bodyStrings(body, "agent_ids"), NarrowFleet: true,
		Fleet: func(ctx context.Context) ([]string, error) {
			if len(groupIDs) > 0 {
				return s.groupMembers(ctx, groupIDs)
			}
			return s.allAgentIDs(ctx)
		}}, nil
}

func resolveScheduledActionRun(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	act, err := s.store.GetScheduledAction(r.Context(), r.PathValue("id"))
	if err != nil {
		return endpointAction{}, err
	}
	if act == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such schedule"}
	}
	a := scheduledActionTargets(s, act.TargetAgent, act.TargetOS, act.TargetSite)
	a.Summary = "run schedule " + act.Name
	a.Content = []contentRef{{Kind: "packages", ID: act.PackageID, Name: "That package"}}
	return a, nil
}

func resolveScheduledActionBody(s *Server, r *http.Request, body []byte) (endpointAction, error) {
	get := func(f string) string {
		if v := bodyStrings(body, f); len(v) > 0 {
			return v[0]
		}
		return ""
	}
	a := scheduledActionTargets(s, get("target_agent"), get("target_os"), get("target_site"))
	if pkg := get("package_id"); pkg != "" {
		a.Content = []contentRef{{Kind: "packages", ID: pkg, Name: "That package"}}
	}
	return a, nil
}

// scheduledActionTargets mirrors fireScheduledAction's own filter: one
// named endpoint, or every endpoint matching the OS and site.
func scheduledActionTargets(s *Server, agent, os, site string) endpointAction {
	if agent != "" {
		return endpointAction{Explicit: []string{agent}}
	}
	return endpointAction{Fleet: func(ctx context.Context) ([]string, error) {
		agents, err := s.store.ListAgents(ctx, s.staleAfter())
		if err != nil {
			return nil, err
		}
		var ids []string
		for _, a := range agents {
			if (os == "" || a.OS == os) && (site == "" || a.Site == site) {
				ids = append(ids, a.AgentID)
			}
		}
		return ids, nil
	}}
}

func resolveShellSession(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	sess, err := s.store.GetShellSession(r.Context(), r.PathValue("id"))
	if err != nil || sess == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such session"}
	}
	return endpointAction{Explicit: []string{sess.AgentID}, Summary: "shell on " + sess.Hostname, ApprovalByCaller: true}, nil
}

func resolveCatalogDecision(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	cr, err := s.store.GetCatalogRequest(r.Context(), r.PathValue("id"))
	if err != nil {
		return endpointAction{}, err
	}
	if cr == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such request"}
	}
	return endpointAction{Explicit: []string{cr.AgentID}, Summary: "catalog request " + cr.ItemName,
		// Deciding is itself the approval step for a Self Service
		// request; parking it for a second one would be circular.
		ApprovalByCaller: true}, nil
}

func resolveManagedCert(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	mc, err := s.store.GetManagedCert(r.Context(), r.PathValue("id"))
	if err != nil || mc == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such managed certificate"}
	}
	// Renew now is itself the approval for a renewal waiting on one, and
	// an upload is the operator supplying the renewal by hand.
	verb := "renew certificate "
	if strings.HasSuffix(r.URL.Path, "/upload") {
		verb = "install uploaded certificate "
	}
	return endpointAction{Explicit: []string{mc.AgentID}, Summary: verb + mc.Name, ApprovalByCaller: true}, nil
}

// resolvePatchSchedule names what a stored patch schedule reaches: the
// endpoints it selected, or every endpoint its OS, site and vulnerability
// filters match.
// resolvePatchListAssignment names the endpoints an assignment reaches:
// the one it names, or every endpoint at its site and on its platform.
func resolvePatchListAssignment(s *Server, _ *http.Request, body []byte) (endpointAction, error) {
	var b createPatchListAssignmentRequest
	_ = json.Unmarshal(body, &b)
	a := endpointAction{Summary: "assign repository list"}
	if b.TargetAgent != "" {
		a.Explicit = []string{b.TargetAgent}
		return a, nil
	}
	a.Fleet = func(ctx context.Context) ([]string, error) {
		agents, err := s.store.ListAgents(ctx, s.staleAfter())
		if err != nil {
			return nil, err
		}
		var ids []string
		for _, ag := range agents {
			if patchListAssignmentMatches(b, ag) {
				ids = append(ids, ag.AgentID)
			}
		}
		return ids, nil
	}
	return a, nil
}

// resolveAppCredSave names the endpoint an app credential is pushed to:
// saving one in push mode is what later writes the file and runs its
// reload command there, unattended.
func resolveAppCredSave(_ *Server, _ *http.Request, body []byte) (endpointAction, error) {
	var b struct {
		Mode        string `json:"mode"`
		PushAgentID string `json:"push_agent_id"`
		AppName     string `json:"app_name"`
	}
	_ = json.Unmarshal(body, &b)
	a := endpointAction{Summary: "app credential " + b.AppName, ApprovalByCaller: true}
	if b.Mode == "push" && b.PushAgentID != "" {
		a.Explicit = []string{b.PushAgentID}
	}
	return a, nil
}

// resolveAppCredRenew names the endpoint a renewal pushes to. Renewing is
// itself the approval step, as for a managed certificate.
func resolveAppCredRenew(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	c, err := s.store.GetAppCredential(r.Context(), r.PathValue("id"))
	if err != nil {
		return endpointAction{}, err
	}
	if c == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such credential"}
	}
	a := endpointAction{Summary: "renew app credential " + c.AppName, ApprovalByCaller: true}
	if c.Mode == "push" && c.PushAgentID != "" {
		a.Explicit = []string{c.PushAgentID}
	}
	return a, nil
}

func resolvePatchSchedule(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	sched, err := s.store.GetPatchSchedule(r.Context(), r.PathValue("id"))
	if err != nil {
		return endpointAction{}, err
	}
	if sched == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such schedule"}
	}
	a := endpointAction{Summary: "patch schedule " + sched.Name}
	switch {
	case len(sched.TargetAgents) > 0:
		a.Explicit = sched.TargetAgents
	case sched.TargetAgent != "":
		a.Explicit = []string{sched.TargetAgent}
	default:
		a.Fleet = func(ctx context.Context) ([]string, error) {
			agents, err := s.resolvePatchTargets(ctx, sched.TargetOS, sched.TargetSite, "", sched.TargetVulnID)
			if err != nil {
				return nil, err
			}
			ids := make([]string, 0, len(agents))
			for _, ag := range agents {
				ids = append(ids, ag.AgentID)
			}
			return ids, nil
		}
	}
	return a, nil
}

// resolvePatchPolicy names what a stored patch list covers: its groups'
// members, or every endpoint when it has none.
func resolvePatchPolicy(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	p, err := s.store.GetPatchPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		return endpointAction{}, err
	}
	if p == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such patch list"}
	}
	groupIDs := p.GroupIDs
	return endpointAction{Summary: "patch list " + p.Name, Fleet: func(ctx context.Context) ([]string, error) {
		if len(groupIDs) > 0 {
			return s.groupMembers(ctx, groupIDs)
		}
		return s.allAgentIDs(ctx)
	}}, nil
}

// resolvePatchPolicyImport names what an imported file of patch lists
// covers, resolving each list's groups by name as the import does. A
// group this server does not have is refused here rather than dropped:
// dropped, the list would silently cover every endpoint.
func resolvePatchPolicyImport(s *Server, r *http.Request, body []byte) (endpointAction, error) {
	var in importPatchPoliciesRequest
	if err := json.Unmarshal(body, &in); err != nil {
		return endpointAction{}, httpError{http.StatusBadRequest, "invalid import file"}
	}
	groups, err := s.store.ListComputerGroups(r.Context())
	if err != nil {
		return endpointAction{}, err
	}
	fleet := false
	var groupIDs []string
	for _, item := range in.PatchLists {
		if len(item.Groups) == 0 {
			fleet = true
			continue
		}
		for _, gname := range item.Groups {
			gid, ok := patchPolicyGroupID(groups, gname)
			if !ok {
				return endpointAction{}, httpError{http.StatusBadRequest,
					fmt.Sprintf("%s: no group named %q here; create it first, or remove it from the file", item.Name, gname)}
			}
			groupIDs = append(groupIDs, gid)
		}
	}
	return endpointAction{Summary: "import patch lists", Fleet: func(ctx context.Context) ([]string, error) {
		if fleet || len(groupIDs) == 0 {
			return s.allAgentIDs(ctx)
		}
		return s.groupMembers(ctx, groupIDs)
	}}, nil
}
