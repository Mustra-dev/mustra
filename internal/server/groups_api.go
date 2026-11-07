package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Computer groups are reusable, named slices of the fleet that everything
// else can target: patch deployments, scan-management assignments, and (see
// docs/ROADMAP.md) which packages a device is offered in Self Service.
// Dynamic groups are evaluated live rather than materialized — membership
// is derived from inventory and cached sensor data, both of which change
// on their own, so a stored member list would be wrong almost immediately.

// sensorRows normalizes a sensor snapshot to rows. Sensors publish an
// array, but a single-row sensor is easy to write as a bare object by
// mistake, and that mistake is invisible: the snapshot stores and displays
// fine, and only group matching and questions quietly stop seeing it.
// Accepting both shapes means one agent's slip can't silently remove a
// whole sensor from every rule in the system.
func sensorRows(data []byte) ([]map[string]any, error) {
	var items []map[string]any
	if err := json.Unmarshal(data, &items); err == nil {
		return items, nil
	}
	var single map[string]any
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, err
	}
	return []map[string]any{single}, nil
}

// devicesForMatching builds the evaluation input for every agent: its
// inventory row plus whatever sensor snapshots it has published.
func (s *Server) devicesForMatching(ctx context.Context) ([]groups.Device, map[string]store.AgentRecord, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, nil, err
	}

	// One query per sensor kind rather than one per agent: four queries for
	// the whole fleet instead of four hundred.
	sensorsByAgent := map[string]map[string][]map[string]any{}
	for _, kind := range []proto.SensorKind{
		proto.SensorInstalledApps, proto.SensorServices, proto.SensorProcesses, proto.SensorPatches,
		proto.SensorDisks, proto.SensorNetwork, proto.SensorUsers, proto.SensorHardware,
		proto.SensorPrivileges, proto.SensorNeighbors, proto.SensorCertificates,
		proto.SensorPerformance, proto.SensorLocalAdmins, proto.SensorSecurityPosture, proto.SensorContainers,
	} {
		rows, err := s.store.ListSensorDataForSensor(ctx, string(kind))
		if err != nil {
			s.logger.Warn("loading sensor data for group matching failed", "sensor", kind, "error", err)
			continue
		}
		for _, row := range rows {
			items, err := sensorRows(row.Data)
			if err != nil {
				// Log rather than skip in silence: a sensor that stops
				// contributing without a word looks exactly like an endpoint
				// that has nothing to report, and the two are very different.
				s.logger.Warn("sensor snapshot not usable for matching",
					"sensor", kind, "agent_id", row.AgentID, "error", err)
				continue
			}
			if sensorsByAgent[row.AgentID] == nil {
				sensorsByAgent[row.AgentID] = map[string][]map[string]any{}
			}
			sensorsByAgent[row.AgentID][string(kind)] = items
		}
	}

	// The directory sensor is nested (users, each with groups); targeting
	// sees one flat row per endpoint with list-valued fields instead.
	if rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorDirectory)); err != nil {
		s.logger.Warn("loading directory data for group matching failed", "error", err)
	} else {
		for _, row := range rows {
			flat, err := directoryTargetRow(row.Data)
			if err != nil {
				s.logger.Warn("directory snapshot not usable for matching", "agent_id", row.AgentID, "error", err)
				continue
			}
			if sensorsByAgent[row.AgentID] == nil {
				sensorsByAgent[row.AgentID] = map[string][]map[string]any{}
			}
			sensorsByAgent[row.AgentID][string(proto.SensorDirectory)] = flat
		}
	}

	// Operator-maintained attributes, for "attr.<name>" rules. One query
	// for the fleet rather than one per endpoint.
	attrs, err := s.store.AttributeValuesByAgent(ctx)
	if err != nil {
		return nil, nil, err
	}

	byID := make(map[string]store.AgentRecord, len(agents))
	devices := make([]groups.Device, 0, len(agents))
	for _, a := range agents {
		byID[a.AgentID] = a
		devices = append(devices, groups.Device{
			AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Arch: a.Arch, Site: a.Site,
			Platform: a.Platform, PlatformVersion: a.PlatformVersion, KernelVersion: a.KernelVersion,
			AgentVersion: a.AgentVersion, IPs: a.IPs, CPUCount: a.CPUCount,
			MemTotalMB: a.MemTotalMB, Online: a.Online, Managed: a.Managed,
			Attributes: attrs[a.AgentID], Sensors: sensorsByAgent[a.AgentID],
		})
	}
	if err := s.addCustomMatching(ctx, devices); err != nil {
		return nil, nil, err
	}
	return devices, byID, nil
}

// resolveGroupMembers returns the agent IDs currently in a group.
func (s *Server) resolveGroupMembers(ctx context.Context, g store.ComputerGroup) ([]string, error) {
	if g.Kind == "static" {
		return g.MemberIDs, nil
	}
	devices, _, err := s.devicesForMatching(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range devices {
		if groups.Matches(d, g.Rules, g.MatchMode != "any") {
			out = append(out, d.AgentID)
		}
	}
	return out, nil
}

// requireKnownGroups answers 400 "unknown group <id>" for the first ID that
// names no computer group, or 500 if the groups can't be read, and reports
// whether the save may go on. A mistyped or deleted ID would leave the
// record scoped to nothing while the console calls it saved.
func (s *Server) requireKnownGroups(w http.ResponseWriter, r *http.Request, ids []string) bool {
	if len(ids) == 0 {
		return true
	}
	all, err := s.store.ListComputerGroups(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	for _, id := range ids {
		if !slices.ContainsFunc(all, func(g store.ComputerGroup) bool { return g.ID == id }) {
			http.Error(w, "unknown group "+id, http.StatusBadRequest)
			return false
		}
	}
	return true
}

type groupView struct {
	store.ComputerGroup
	MemberCount int `json:"member_count"`
}

// listComputerGroupsResponse is what GET /api/groups answers.
type listComputerGroupsResponse struct {
	Fields []groups.FieldSpec `json:"fields"`
	Groups []groupView        `json:"groups"`
}

func (s *Server) handleListComputerGroups(w http.ResponseWriter, r *http.Request) {
	all, err := s.store.ListComputerGroups(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Evaluate once for the whole page rather than per group.
	devices, _, err := s.devicesForMatching(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]groupView, 0, len(all))
	for _, g := range all {
		count := len(g.MemberIDs)
		if g.Kind != "static" {
			count = 0
			for _, d := range devices {
				if groups.Matches(d, g.Rules, g.MatchMode != "any") {
					count++
				}
			}
		}
		out = append(out, groupView{ComputerGroup: g, MemberCount: count})
	}
	fields, err := s.sensorFields(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSONResponse(w, listComputerGroupsResponse{Groups: out, Fields: fields})
}

// getComputerGroupMembersResponse is what GET /api/groups/{id}/members
// answers.
type getComputerGroupMembersResponse struct {
	Group   *store.ComputerGroup `json:"group"`
	Members []store.AgentRecord  `json:"members"`
}

func (s *Server) handleGetComputerGroupMembers(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.GetComputerGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if g == nil {
		http.Error(w, "no such group", http.StatusNotFound)
		return
	}
	ids, err := s.resolveGroupMembers(r.Context(), *g)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, byID, err := s.devicesForMatching(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	members := make([]store.AgentRecord, 0, len(ids))
	for _, id := range ids {
		if a, ok := byID[id]; ok {
			members = append(members, a)
		}
	}
	writeJSONResponse(w, getComputerGroupMembersResponse{Group: g, Members: members})
}

type upsertGroupRequest struct {
	ID          string        `json:"id"`
	Name        string        `json:"name" api:"required"`
	Description string        `json:"description"`
	Kind        string        `json:"kind"`
	MatchMode   string        `json:"match_mode"`
	Rules       []groups.Rule `json:"rules"`
	MemberIDs   []string      `json:"member_ids"`
}

func validateGroupRequest(req *upsertGroupRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if req.Kind != "static" {
		req.Kind = "dynamic"
	}
	if req.MatchMode != "any" {
		req.MatchMode = "all"
	}
	if req.Kind == "dynamic" {
		if len(req.Rules) == 0 {
			return fmt.Errorf("a dynamic group needs at least one rule — otherwise it matches nothing")
		}
		for i, rule := range req.Rules {
			if err := rule.Validate(); err != nil {
				return fmt.Errorf("rule %d: %w", i+1, err)
			}
		}
	}
	return nil
}

func (s *Server) handleUpsertComputerGroup(w http.ResponseWriter, r *http.Request) {
	var req upsertGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if id := r.PathValue("id"); id != "" {
		req.ID = id
	}
	if err := s.validateCustomFields(r.Context(), nil, req.Rules, ""); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// A group's membership answers its rules, so a rule on a sensor the
	// caller may not read is refused like asking about it directly.
	if err := s.checkSensorFields(r.Context(), nil, req.Rules); err != nil {
		writeSensorFieldsError(w, err)
		return
	}
	if err := validateGroupRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		req.ID = idgen.New("cgrp-")
	}

	u := auth.CurrentUser(r.Context())
	g, err := s.store.UpsertComputerGroup(r.Context(), store.ComputerGroup{
		ID: req.ID, Name: req.Name, Description: req.Description, Kind: req.Kind,
		MatchMode: req.MatchMode, Rules: req.Rules, MemberIDs: req.MemberIDs, CreatedBy: u.Username,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("computer group saved", "group", g.Name, "kind", g.Kind, "rules", len(g.Rules), "saved_by", u.Username)
	s.audit(r.Context(), auditEvent{
		Action: "group.save", Actor: u.Username, Target: g.Name,
		Detail: map[string]any{"kind": g.Kind, "rules": len(g.Rules)},
	})
	writeJSONResponse(w, g)
}

// deleteComputerGroupResponse is what DELETE /api/groups/{id} answers.
type deleteComputerGroupResponse struct {
	Deleted                 string `json:"deleted"`
	DisabledEnforcePolicies int    `json:"disabled_enforce_policies"`
	DisabledPlaybooks       int    `json:"disabled_playbooks"`
}

func (s *Server) handleDeleteComputerGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Anything targeted at this group is disabled in the same transaction,
	// because a policy or playbook that loses its group would otherwise
	// widen to the whole fleet. See DeleteComputerGroupAndOrphans.
	policies, playbooks, err := s.store.DeleteComputerGroupAndOrphans(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policies > 0 || playbooks > 0 {
		who := auth.CurrentUser(r.Context()).Username
		s.logger.Warn("computer group deleted; targeting disabled", "group_id", id,
			"enforce_policies", policies, "playbooks", playbooks, "deleted_by", who)
		s.audit(r.Context(), auditEvent{
			Action: "group.delete.orphaned", Actor: who, Target: id, Severity: "warning",
			Detail: map[string]any{"enforce_policies": policies, "playbooks": playbooks},
		})
	}
	writeJSONResponse(w, deleteComputerGroupResponse{
		Deleted: id, DisabledEnforcePolicies: policies, DisabledPlaybooks: playbooks,
	})
}

type previewGroupRequest struct {
	MatchMode string        `json:"match_mode"`
	Rules     []groups.Rule `json:"rules"`
}

// previewComputerGroupResponse is what POST /api/groups/preview answers.
type previewComputerGroupResponse struct {
	Matched int                 `json:"matched"`
	Members []store.AgentRecord `json:"members"`
	Total   int                 `json:"total"`
}

// handlePreviewComputerGroup evaluates an unsaved rule set so the builder
// can show what it actually matches before anyone commits to it — the
// difference between writing rules and guessing at them.
func (s *Server) handlePreviewComputerGroup(w http.ResponseWriter, r *http.Request) {
	var req previewGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	for i, rule := range req.Rules {
		if err := rule.Validate(); err != nil {
			http.Error(w, fmt.Sprintf("rule %d: %v", i+1, err), http.StatusBadRequest)
			return
		}
	}
	if err := s.checkSensorFields(r.Context(), nil, req.Rules); err != nil {
		writeSensorFieldsError(w, err)
		return
	}
	devices, byID, err := s.devicesForMatching(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	matched := make([]store.AgentRecord, 0)
	for _, d := range devices {
		if groups.Matches(d, req.Rules, req.MatchMode != "any") {
			matched = append(matched, byID[d.AgentID])
		}
	}
	writeJSONResponse(w, previewComputerGroupResponse{
		Matched: len(matched), Total: len(devices), Members: matched,
	})
}

// groupMemberIDSet is what patch targeting uses to expand a group into the
// agents it currently contains.
func (s *Server) groupMemberIDSet(ctx context.Context, groupID string) (map[string]bool, error) {
	g, err := s.store.GetComputerGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, fmt.Errorf("no such computer group: %s", groupID)
	}
	ids, err := s.resolveGroupMembers(ctx, *g)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

// directoryTargetRow flattens a directory snapshot into the single row
// targeting rules read: join facts as strings, and the signed-in users,
// their groups and departments, and the computer's groups as lists.
func directoryTargetRow(data []byte) ([]map[string]any, error) {
	var infos []proto.DirectoryInfo
	if err := json.Unmarshal(data, &infos); err != nil {
		return nil, err
	}
	if len(infos) == 0 {
		return []map[string]any{}, nil
	}
	d := infos[0]
	list := func(v []string) []any {
		out := []any{}
		seen := map[string]bool{}
		for _, x := range v {
			if x != "" && !seen[strings.ToLower(x)] {
				seen[strings.ToLower(x)] = true
				out = append(out, x)
			}
		}
		return out
	}
	var users, groups, departments []string
	for _, u := range d.Users {
		users = append(users, u.Name)
		if u.UPN != "" {
			users = append(users, u.UPN)
		}
		groups = append(groups, u.Groups...)
		departments = append(departments, u.Department)
	}
	return []map[string]any{{
		"joined": d.Joined, "kind": d.Kind, "domain": d.Domain, "site": d.Site, "ou": d.ComputerOU,
		"computer_dn": d.ComputerDN, "computer_groups": list(d.ComputerGroups), "users": list(users),
		"user_groups": list(groups), "user_departments": list(departments), "entra_tenant": d.EntraTenant,
	}}, nil
}
