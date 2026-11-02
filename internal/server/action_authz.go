package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// One authorization path for everything that acts on endpoints.
//
// A permission says "may this person deploy". Management rights, the
// module's action-group ceiling, content sets and approval policies say
// where, with what, and whether somebody else must agree first (see
// access.go). Those used to be applied by a handful of handlers and
// skipped by the rest: a direct POST /api/deploy/run, kill-process, agent
// update, single-device patching, enforce and reveal runs, scheduled
// actions and more reached the bus without them.
//
// Now every route that sends work to an endpoint is registered through
// s.gate (enumerated by TestEndpointActionRoutesAreGated), and the gate
// and the handlers that narrow fleet-wide targets themselves all call the
// same function, authorizeEndpointAction.

// contentRef names one piece of content an operation uses, for content
// sets.
type contentRef struct {
	Kind, ID, Name string
}

// endpointAction is one operation, described for the access checks.
type endpointAction struct {
	// Module is the access module ("deploy", "patches", "shell",
	// "enforce", "reveal", "playbooks"), whose action group and approval
	// policies apply. Empty means management rights only: operations on
	// an endpoint's own record or settings that no module ceiling covers.
	Module string
	// Summary describes the operation for audit rows and approvals.
	Summary string
	// Explicit is what the caller named. Anything out of reach is refused,
	// not dropped: being quietly given thirty of forty endpoints is being
	// told something untrue about the fleet.
	Explicit []string
	// Fleet resolves, when nothing was named, every endpoint the operation
	// would reach. Evaluated only when something could restrict it.
	Fleet func(ctx context.Context) ([]string, error)
	// NarrowFleet lets a fleet-wide operation drop what is out of reach
	// (the caller then acts on what remains); otherwise it is refused.
	NarrowFleet bool
	Content     []contentRef
	// Approval, when set, parks the operation if a policy covers it. The
	// Handler key must be in s.replayable().
	Approval *approvalRef
	// ApprovalByCaller marks a check whose caller applies the approval
	// gate itself, later, once its own targets are final.
	ApprovalByCaller bool
}

type approvalRef struct {
	Handler string
	Body    any
}

// authorizeEndpointAction is the shared check. It returns the endpoints
// the operation may act on and true, or writes the refusal (or the
// "parked for approval" reply) and returns false. For a fleet-wide
// operation nothing restricted, the returned list is nil: nothing was
// narrowed and the caller proceeds with its own full list.
func (s *Server) authorizeEndpointAction(w http.ResponseWriter, r *http.Request, a endpointAction) ([]string, bool) {
	ctx := r.Context()
	u := auth.CurrentUser(ctx)
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	// "agent_ids": [] is how the console asks for every eligible endpoint,
	// exactly like an omitted list. Kept as an empty non-nil slice it came
	// back as the allowed set, and callers that narrow a fleet to what is
	// allowed (software deploy) narrowed an unrestricted caller's fleet to
	// nothing: a 200 with targets=0 and nothing dispatched.
	if len(a.Explicit) == 0 {
		a.Explicit = nil
	}
	scope, err := s.endpointScope(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	var ceiling map[string]bool
	if a.Module != "" {
		if ceiling, err = s.actionCeiling(ctx, a.Module); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, false
		}
	}
	restricted := scope != nil || ceiling != nil
	needPolicyTargets := false
	if a.Module != "" && !a.ApprovalByCaller {
		if _, replaying := approvalGranted(ctx); !replaying {
			needPolicyTargets, err = s.modulePolicyExists(ctx, a.Module)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return nil, false
			}
		}
	}

	targets := a.Explicit
	if len(a.Explicit) == 0 && a.Fleet != nil && (restricted || needPolicyTargets) {
		if targets, err = a.Fleet(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, false
		}
	}
	module := a.Module
	if module == "" {
		module = "endpoint"
	}
	if restricted && len(targets) > 0 {
		var outScope, outCeiling []string
		for _, id := range targets {
			if scope != nil && !scope[id] {
				outScope = append(outScope, id)
			} else if ceiling != nil && !ceiling[id] {
				outCeiling = append(outCeiling, id)
			}
		}
		outside := len(outScope) + len(outCeiling)
		if outside > 0 && (len(a.Explicit) > 0 || !a.NarrowFleet) {
			s.audit(ctx, auditEvent{Action: module + ".denied", Actor: u.Username, Target: firstNonEmptyString(a.Summary, r.URL.Path),
				Outcome: "denied", Severity: "warning",
				Detail: map[string]any{"outside_rights": len(outScope), "outside_action_group": len(outCeiling), "path": r.URL.Path}})
			switch {
			case len(outScope) > 0 && len(a.Explicit) == 0:
				http.Error(w, fmt.Sprintf("%d endpoint(s) this operation would reach are outside your management rights (%s); select endpoints you manage", len(outScope), s.hostnamesFor(ctx, outScope)), http.StatusForbidden)
			case len(outScope) > 0:
				http.Error(w, fmt.Sprintf("%d of those endpoints are outside your management rights (%s)", len(outScope), s.hostnamesFor(ctx, outScope)), http.StatusForbidden)
			default:
				http.Error(w, fmt.Sprintf("%d of those endpoints are outside the %s action group (%s)", len(outCeiling), a.Module, s.hostnamesFor(ctx, outCeiling)), http.StatusForbidden)
			}
			return nil, false
		}
		if outside > 0 {
			kept := make([]string, 0, len(targets)-outside)
			for _, id := range targets {
				if (scope == nil || scope[id]) && (ceiling == nil || ceiling[id]) {
					kept = append(kept, id)
				}
			}
			if len(kept) == 0 {
				http.Error(w, "every endpoint this operation would reach is outside your management rights or the "+module+" action group", http.StatusForbidden)
				return nil, false
			}
			s.logger.Info("targets narrowed by access control", "module", module, "dropped", outside, "remaining", len(kept))
			targets = kept
		}
	}
	for _, c := range a.Content {
		if !s.requireContent(w, r, c.Kind, c.ID, firstNonEmptyString(c.Name, c.ID)) {
			return nil, false
		}
	}
	if a.Module != "" && !a.ApprovalByCaller && needPolicyTargets {
		handler, body := "", any(nil)
		if a.Approval != nil {
			handler, body = a.Approval.Handler, a.Approval.Body
		}
		if s.requireApproval(w, r, a.Module, handler, firstNonEmptyString(a.Summary, r.Method+" "+r.URL.Path), targets, body) {
			return nil, false
		}
	}
	return targets, true
}

// modulePolicyExists reports whether any enabled approval policy names
// the module, which is when an operation's targets must be resolved to ask
// whether it is covered.
func (s *Server) modulePolicyExists(ctx context.Context, module string) (bool, error) {
	if s.store == nil {
		return false, nil
	}
	policies, err := s.store.ListApprovalPolicies(ctx)
	if err != nil {
		return false, err
	}
	for _, p := range policies {
		if p.Enabled && p.Module == module {
			return true, nil
		}
	}
	return false, nil
}

// --- the route gate -------------------------------------------------------

// actionSpec describes how a route's request names its targets.
type actionSpec struct {
	Module string
	// Resolve reads the request (body already buffered) into an
	// endpointAction. Module, Approval and the summary default from the
	// spec when the resolver leaves them empty.
	Resolve func(s *Server, r *http.Request, body []byte) (endpointAction, error)
	// NarrowField, for a fleet-wide request that may be narrowed, is the
	// body field the gate rewrites to the endpoints left in reach, so the
	// handler acts on exactly those.
	NarrowField string
}

// actionGate is the middleware form of authorizeEndpointAction, labelled
// so the route table can show which routes carry it.
type actionGate struct {
	s    *Server
	key  string
	spec actionSpec
	next http.Handler
	// permCheck is the route's permission check. The gate sits inside it,
	// so an approval replay, which calls the gate directly, has to go
	// through it again (replay).
	permCheck func(http.Handler) http.Handler
}

// replay is the gate as an approved request re-enters it: behind the
// route's permission check, so a requester who lost the permission while
// the request waited is refused. A gate with no recorded check refuses
// rather than run unchecked.
func (g *actionGate) replay(w http.ResponseWriter, r *http.Request) {
	if g.permCheck == nil {
		http.Error(w, "forbidden: no permission check is recorded for "+g.key, http.StatusForbidden)
		return
	}
	g.permCheck(g).ServeHTTP(w, r)
}

const maxGatedBody = 4 << 20

func (g *actionGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxGatedBody))
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		body = b
	}
	a, err := g.spec.Resolve(g.s, r, body)
	if err != nil {
		var he httpError
		if asHTTPError(err, &he) {
			http.Error(w, he.msg, he.code)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if a.Module == "" {
		a.Module = g.spec.Module
	}
	if a.Summary == "" {
		a.Summary = g.key
	}
	if a.Approval == nil && !a.ApprovalByCaller {
		raw := json.RawMessage(body)
		if len(bytes.TrimSpace(body)) == 0 {
			raw = json.RawMessage("{}")
		}
		a.Approval = &approvalRef{Handler: g.key, Body: raw}
	}
	targets, ok := g.s.authorizeEndpointAction(w, r, a)
	if !ok {
		return
	}
	if g.spec.NarrowField != "" && len(a.Explicit) == 0 && a.NarrowFleet && targets != nil {
		if b, err := setJSONField(body, g.spec.NarrowField, targets); err == nil {
			body = b
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	g.next.ServeHTTP(w, r)
}

// gate wraps an endpoint-action route. key is the route pattern; it is
// also the name the operation is parked under when an approval policy
// covers it.
func (s *Server) gate(key string, spec actionSpec, h http.Handler, permCheck func(http.Handler) http.Handler) http.Handler {
	g := &actionGate{s: s, key: key, spec: spec, next: h, permCheck: permCheck}
	if s.gatedRoutes == nil {
		s.gatedRoutes = map[string]*actionGate{}
	}
	s.gatedRoutes[key] = g
	return g
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

func asHTTPError(err error, out *httpError) bool {
	he, ok := err.(httpError)
	if ok {
		*out = he
	}
	return ok
}

// setJSONField replaces one top-level field of a JSON object.
func setJSONField(body []byte, field string, v any) ([]byte, error) {
	m := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	m[field] = raw
	return json.Marshal(m)
}

// --- resolvers --------------------------------------------------------------

// bodyStrings reads string or []string fields out of a JSON body.
func bodyStrings(body []byte, fields ...string) []string {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	m := map[string]json.RawMessage{}
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, f := range fields {
		raw, ok := m[f]
		if !ok {
			continue
		}
		var one string
		if json.Unmarshal(raw, &one) == nil {
			add(one)
			continue
		}
		var many []string
		if json.Unmarshal(raw, &many) == nil {
			for _, v := range many {
				add(v)
			}
		}
	}
	return out
}

// pathAgent: the endpoint named in the URL.
func pathAgent(param string) func(*Server, *http.Request, []byte) (endpointAction, error) {
	return func(_ *Server, r *http.Request, _ []byte) (endpointAction, error) {
		id := r.PathValue(param)
		if id == "" {
			return endpointAction{}, httpError{http.StatusBadRequest, "an endpoint id is required"}
		}
		return endpointAction{Explicit: []string{id}, Summary: r.Method + " " + r.URL.Path}, nil
	}
}

// bodyAgentsOrFleet: endpoints named in the body; otherwise the members of
// the groups named in the body; otherwise every endpoint.
func bodyAgentsOrFleet(agentFields, groupFields []string, narrow bool) func(*Server, *http.Request, []byte) (endpointAction, error) {
	return func(s *Server, r *http.Request, body []byte) (endpointAction, error) {
		a := endpointAction{Explicit: bodyStrings(body, agentFields...), NarrowFleet: narrow}
		groupIDs := bodyStrings(body, groupFields...)
		a.Fleet = func(ctx context.Context) ([]string, error) {
			if len(groupIDs) > 0 {
				return s.groupMembers(ctx, groupIDs)
			}
			return s.allAgentIDs(ctx)
		}
		return a, nil
	}
}

// fleetOnly: an operation that reaches every endpoint it decides on itself.
func fleetOnly(s *Server, _ *http.Request, _ []byte) (endpointAction, error) {
	return endpointAction{Fleet: s.allAgentIDs}, nil
}

// explicitOnlyHandledByCaller: the handler narrows fleet-wide targets and
// applies approvals itself, through authorizeEndpointAction, once its own
// target list is final. The gate refuses explicit out-of-reach targets
// early so the caller hears about them rather than about applicability.
func explicitOnlyHandledByCaller(agentFields ...string) func(*Server, *http.Request, []byte) (endpointAction, error) {
	return func(_ *Server, r *http.Request, body []byte) (endpointAction, error) {
		return endpointAction{Explicit: bodyStrings(body, agentFields...), ApprovalByCaller: true}, nil
	}
}

func (s *Server) allAgentIDs(ctx context.Context) ([]string, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(agents))
	for _, a := range agents {
		out = append(out, a.AgentID)
	}
	return out, nil
}

// groupMembers resolves computer groups to endpoints. A group that no
// longer exists contributes nothing, never "everything".
func (s *Server) groupMembers(ctx context.Context, groupIDs []string) ([]string, error) {
	set, err := s.agentsInGroups(ctx, groupIDs)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// endpointActionPrincipal is a context carrying a stored definition's
// author, for work the server runs later on their behalf (a schedule
// firing): the author's management rights and the module ceiling still
// apply. ok is false when the author no longer exists or is inactive.
func (s *Server) endpointActionPrincipal(ctx context.Context, username string) (context.Context, bool) {
	if username == "" {
		return ctx, false
	}
	u, err := s.store.GetUserByUsername(ctx, username)
	if err != nil || u == nil || !u.Active {
		return ctx, false
	}
	return auth.WithUser(ctx, u), true
}
