package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Reveal rule sets: the compliance regime as an operator works in it.
//
// A rule is the unit of scanning and stays exactly as it was. A set is the
// unit of deciding: "PCI-DSS" is a few rules aimed at a few groups, turned
// on or off together. Enabling a set writes its group targeting onto its
// rules and enables them, so there is still one definition of where a rule
// runs — the set does not become a second, competing source of truth that
// could disagree with the rule it points at.

// revealRegimes are the regimes offered in the editor. Free text is
// allowed; these are the ones worth spelling consistently.
var revealRegimes = []string{"PCI-DSS", "HIPAA", "GDPR", "CCPA", "SOX", "Custom"}

// listRevealRuleSetsResponse is what GET /api/reveal/rule-sets answers.
type listRevealRuleSetsResponse struct {
	Regimes  []string              `json:"regimes"`
	RuleSets []store.RevealRuleSet `json:"rule_sets"`
	Rules    []map[string]string   `json:"rules"`
}

func (s *Server) handleListRevealRuleSets(w http.ResponseWriter, r *http.Request) {
	sets, err := s.store.ListRevealRuleSets(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rules, err := s.store.ListRevealRules(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Only real rules can be in a set; a quick search is a one-off.
	named := make([]map[string]string, 0, len(rules))
	for _, rl := range rules {
		if rl.Kind == "quick" {
			continue
		}
		named = append(named, map[string]string{"id": rl.ID, "name": rl.Name})
	}
	writeJSONResponse(w, listRevealRuleSetsResponse{RuleSets: sets, Rules: named, Regimes: revealRegimes})
}

// saveRevealRuleSetResponse is what POST /api/reveal/rule-sets and PUT
// /api/reveal/rule-sets/{id} answer.
type saveRevealRuleSetResponse struct {
	RuleSet      *store.RevealRuleSet `json:"rule_set"`
	RulesUpdated int                  `json:"rules_updated"`
}

func (s *Server) handleSaveRevealRuleSet(w http.ResponseWriter, r *http.Request) {
	var in store.RevealRuleSet
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if len(in.RuleIDs) == 0 {
		http.Error(w, "a rule set needs at least one rule", http.StatusBadRequest)
		return
	}
	for _, id := range in.RuleIDs {
		rule, err := s.store.GetRevealRule(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rule == nil {
			http.Error(w, "no such rule: "+id, http.StatusBadRequest)
			return
		}
	}
	u := auth.CurrentUser(r.Context())
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetRevealRuleSet(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such rule set", http.StatusNotFound)
			return
		}
		in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		in.ID, in.CreatedBy = idgen.New("rset-"), u.Username
	}
	if err := s.store.UpsertRevealRuleSet(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	applied, err := s.applyRevealRuleSet(r.Context(), in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "reveal_rule_set.save", Actor: u.Username, Target: in.Name, Severity: "notice",
		Detail: map[string]any{"regime": in.Regime, "rules": len(in.RuleIDs), "groups": len(in.GroupIDs), "enabled": in.Enabled}})
	out, _ := s.store.GetRevealRuleSet(r.Context(), in.ID)
	writeJSONResponse(w, saveRevealRuleSetResponse{RuleSet: out, RulesUpdated: applied})
}

// applyRevealRuleSet writes the set's decision onto its rules: its groups
// become their targeting and its enabled flag becomes theirs. Doing it
// here rather than at scan time keeps one definition of where a rule runs
// — the rule's own — so the Rules tab never disagrees with the set.
func (s *Server) applyRevealRuleSet(ctx context.Context, set store.RevealRuleSet) (int, error) {
	n := 0
	for _, id := range set.RuleIDs {
		rule, err := s.store.GetRevealRule(ctx, id)
		if err != nil {
			return n, err
		}
		if rule == nil {
			continue
		}
		rule.GroupIDs = append([]string{}, set.GroupIDs...)
		rule.Enabled = set.Enabled
		if err := s.store.UpsertRevealRule(ctx, *rule); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *Server) handleDeleteRevealRuleSet(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetRevealRuleSet(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such rule set", http.StatusNotFound)
		return
	}
	// Deleting the set disables the rules it turned on. Leaving them
	// running after their reason is gone is how a fleet ends up scanning
	// for something nobody remembers asking about.
	if existing.Enabled {
		off := *existing
		off.Enabled = false
		if _, err := s.applyRevealRuleSet(r.Context(), off); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := s.store.DeleteRevealRuleSet(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "reveal_rule_set.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: existing.Name, Severity: "notice", Detail: map[string]any{"rules_disabled": len(existing.RuleIDs)}})
	w.WriteHeader(http.StatusNoContent)
}
