package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Asset attributes and retention.
//
// An attribute is what an operator knows about an endpoint that no sensor
// can report — who owns it, which cost centre pays for it, whether it may
// be rebooted during the day. It is addressed in a computer-group rule as
// "attr.<name>", which is why the name is constrained to something a rule
// can carry unambiguously.
//
// Retention is the other half: an endpoint that goes quiet is retired
// rather than deleted, so what a decommissioned machine was running is
// still answerable months later.

// listAssetAttributesResponse is what GET /api/asset-attributes answers.
type listAssetAttributesResponse struct {
	Attributes []store.AssetAttribute `json:"attributes"`
	Kinds      []string               `json:"kinds"`
	// PurgeAfterDays is how many days a retired endpoint is kept before
	// it is deleted; 0 means never.
	PurgeAfterDays int            `json:"purge_after_days"`
	Retired        int            `json:"retired"`
	SetCount       map[string]int `json:"set_count"`
}

func (s *Server) handleListAssetAttributes(w http.ResponseWriter, r *http.Request) {
	attrs, err := s.store.ListAssetAttributes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// How many endpoints have each one set, so an attribute nobody fills in
	// is visible as such rather than looking the same as a used one.
	values, err := s.store.AttributeValuesByAgent(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setCount := map[string]int{}
	for _, byName := range values {
		for name := range byName {
			setCount[name]++
		}
	}
	retired, _ := s.store.RetiredAgentCount(r.Context())
	// A purge setting that cannot be read is not "never": the console
	// would show 0 and a save from there would switch purging off.
	purge, err := s.purgeAfterDays(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listAssetAttributesResponse{
		Attributes: attrs, SetCount: setCount, Kinds: []string{"text", "number", "date", "boolean", "select"},
		Retired: retired, PurgeAfterDays: purge,
	})
}

func (s *Server) handleSaveAssetAttribute(w http.ResponseWriter, r *http.Request) {
	var in store.AssetAttribute
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	in.Label = strings.TrimSpace(in.Label)
	if in.Label == "" {
		in.Label = in.Name
	}
	if !store.ValidAttributeName(in.Name) {
		http.Error(w, "name must be lower-case letters, digits and underscores, starting with a letter — it becomes the targeting key attr."+in.Name, http.StatusBadRequest)
		return
	}
	if in.Kind == "" {
		in.Kind = "text"
	}
	if !store.ValidAttributeKind(in.Kind) {
		http.Error(w, "kind must be text, number, date, boolean or select", http.StatusBadRequest)
		return
	}
	clean := []string{}
	for _, o := range in.Options {
		if o = strings.TrimSpace(o); o != "" {
			clean = append(clean, o)
		}
	}
	in.Options = clean
	if in.Kind == "select" && len(in.Options) == 0 {
		http.Error(w, "a select attribute needs at least one option", http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetAssetAttribute(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such attribute", http.StatusNotFound)
			return
		}
		// Renaming would silently break every computer group targeting
		// attr.<old name>, so it is refused rather than cascaded.
		if existing.Name != in.Name {
			http.Error(w, "an attribute's name is its targeting key and cannot change; create a new one", http.StatusBadRequest)
			return
		}
		in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		if existing, _ := s.store.GetAssetAttribute(r.Context(), in.Name); existing != nil {
			http.Error(w, "an attribute named "+in.Name+" already exists", http.StatusConflict)
			return
		}
		in.ID, in.CreatedBy = idgen.New("attr-"), u.Username
	}
	if err := s.store.UpsertAssetAttribute(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "asset_attribute.save", Actor: u.Username, Target: in.Name, Severity: "info",
		Detail: map[string]any{"kind": in.Kind}})
	out, _ := s.store.GetAssetAttribute(r.Context(), in.ID)
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteAssetAttribute(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetAssetAttribute(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such attribute", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteAssetAttribute(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "asset_attribute.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "notice"})
	w.WriteHeader(http.StatusNoContent)
}

// agentAttributesView is what GET /api/agents/{id}/attributes answers:
// every attribute, and this endpoint's values.
type agentAttributesView struct {
	Attributes []store.AssetAttribute `json:"attributes"`
	Values     map[string]string      `json:"values"`
}

// agentAttributesResponse is what PUT /api/agents/{id}/attributes answers.
type agentAttributesResponse struct {
	Values map[string]string `json:"values"`
}

// GET/PUT /api/agents/{id}/attributes
func (s *Server) handleAgentAttributes(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	attrs, err := s.store.ListAssetAttributes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodGet {
		values, err := s.store.AttributeValuesFor(r.Context(), agentID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSONResponse(w, agentAttributesView{Attributes: attrs, Values: values})
		return
	}
	var body map[string]string // attribute id -> value
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	byID := map[string]store.AssetAttribute{}
	for _, a := range attrs {
		byID[a.ID] = a
	}
	who := auth.CurrentUser(r.Context()).Username
	for id, value := range body {
		a, ok := byID[id]
		if !ok {
			http.Error(w, "no such attribute: "+id, http.StatusBadRequest)
			return
		}
		if err := validateAttributeValue(a, value); err != nil {
			http.Error(w, a.Label+": "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.store.SetAssetAttributeValue(r.Context(), agentID, id, value, who); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.audit(r.Context(), auditEvent{Action: "asset_attribute.set", Actor: who, AgentID: agentID,
		Target: s.hostnameFor(r.Context(), agentID), Severity: "info", Detail: map[string]any{"fields": len(body)}})
	values, _ := s.store.AttributeValuesFor(r.Context(), agentID)
	// A warranty end date just entered may already be inside the warning
	// window; say so now rather than at the next sweep.
	go s.checkWarranties(context.WithoutCancel(r.Context()))
	writeJSONResponse(w, agentAttributesResponse{Values: values})
}

// validateAttributeValue keeps a number a number and a select one of its
// options, so a rule comparing them numerically is not defeated by a typo
// somebody made months earlier.
func validateAttributeValue(a store.AssetAttribute, value string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil // clearing is always allowed
	}
	switch a.Kind {
	case "number":
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			return errNotA("a number")
		}
	case "boolean":
		if v != "true" && v != "false" {
			return errNotA(`"true" or "false"`)
		}
	case "date":
		if _, err := time.Parse("2006-01-02", v); err != nil {
			return errNotA("a date as YYYY-MM-DD")
		}
	case "select":
		for _, o := range a.Options {
			if o == v {
				return nil
			}
		}
		return errNotA("one of " + strings.Join(a.Options, ", "))
	}
	return nil
}

type attrValueError string

func (e attrValueError) Error() string { return string(e) }
func errNotA(what string) error        { return attrValueError("must be " + what) }

// setAgentManagedRequest is the body of POST /api/agents/{id}/managed.
type setAgentManagedRequest struct {
	Managed bool   `json:"managed"`
	Reason  string `json:"reason"`
}

// setAgentManagedResponse is what POST /api/agents/{id}/managed answers.
type setAgentManagedResponse struct {
	AgentID string `json:"agent_id"`
	Managed bool   `json:"managed"`
}

// POST /api/agents/{id}/managed {"managed":bool,"reason":""} — retire or
// restore one endpoint by hand.
func (s *Server) handleSetAgentManaged(w http.ResponseWriter, r *http.Request) {
	var body setAgentManagedRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	agentID := r.PathValue("id")
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "retired by hand"
	}
	if err := s.store.SetAgentManaged(r.Context(), agentID, body.Managed, reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "asset.retire"
	if body.Managed {
		action = "asset.restore"
	}
	s.audit(r.Context(), auditEvent{Action: action, Actor: auth.CurrentUser(r.Context()).Username,
		AgentID: agentID, Target: s.hostnameFor(r.Context(), agentID), Severity: "notice",
		Detail: map[string]any{"reason": reason}})
	s.refreshAgentHub(r.Context())
	writeJSONResponse(w, setAgentManagedResponse{AgentID: agentID, Managed: body.Managed})
}

// setPurgeAfterRequest is the body of POST /api/assets/purge-after.
type setPurgeAfterRequest struct {
	Days int `json:"days"`
}

// setPurgeAfterResponse is what POST /api/assets/purge-after answers.
type setPurgeAfterResponse struct {
	PurgeAfterDays int `json:"purge_after_days"`
}

// POST /api/assets/purge-after {"days":n} — 0 means never.
func (s *Server) handleSetPurgeAfter(w http.ResponseWriter, r *http.Request) {
	var body setPurgeAfterRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.Days < 0 {
		body.Days = 0
	}
	who := auth.CurrentUser(r.Context()).Username
	if err := s.store.SetSetting(r.Context(), assetPurgeAfterSetting, strconv.Itoa(body.Days), who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "assets.purge_after", Actor: who,
		Target: strconv.Itoa(body.Days) + " days", Severity: "notice"})
	writeJSONResponse(w, setPurgeAfterResponse{PurgeAfterDays: body.Days})
}
