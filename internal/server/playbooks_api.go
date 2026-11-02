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

// HTTP surface for Playbooks. Reading is open to any signed-in user;
// authoring and running take deploy.manage, because a playbook is a
// sequence of the most consequential things mustra can do and the schedule
// makes it unattended.

// listPlaybooksResponse is what GET /api/playbooks answers.
type listPlaybooksResponse struct {
	Playbooks []store.Playbook    `json:"playbooks"`
	Runs      []store.PlaybookRun `json:"runs"`
}

func (s *Server) handleListPlaybooks(w http.ResponseWriter, r *http.Request) {
	playbooks, err := s.store.ListPlaybooks(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runs, err := s.store.ListPlaybookRuns(r.Context(), 25)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listPlaybooksResponse{Playbooks: playbooks, Runs: runs})
}

// playbookResponse is what GET /api/playbooks/{id}, POST /api/playbooks
// and PUT /api/playbooks/{id} answer.
type playbookResponse struct {
	Playbook *store.Playbook `json:"playbook"`
}

func (s *Server) handleGetPlaybook(w http.ResponseWriter, r *http.Request) {
	pb, err := s.store.GetPlaybook(r.Context(), r.PathValue("id"))
	if err != nil || pb == nil {
		http.Error(w, "no such playbook", http.StatusNotFound)
		return
	}
	writeJSONResponse(w, playbookResponse{Playbook: pb})
}

// listPlaybookRunsResponse is what GET /api/playbooks/runs answers.
type listPlaybookRunsResponse struct {
	Runs []store.PlaybookRun `json:"runs"`
}

func (s *Server) handleListPlaybookRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := s.store.ListPlaybookRuns(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listPlaybookRunsResponse{Runs: runs})
}

// getPlaybookRunResponse is what GET /api/playbooks/runs/{id} answers.
type getPlaybookRunResponse struct {
	Results []store.PlaybookStepResult `json:"results"`
	Run     *store.PlaybookRun         `json:"run"`
}

// handleGetPlaybookRun is what the live view polls: the run, its copied
// steps, and every per-endpoint result recorded so far.
func (s *Server) handleGetPlaybookRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetPlaybookRun(r.Context(), r.PathValue("id"))
	if err != nil || run == nil {
		http.Error(w, "no such run", http.StatusNotFound)
		return
	}
	results, err := s.store.ListPlaybookStepResults(r.Context(), run.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, getPlaybookRunResponse{Run: run, Results: results})
}

type playbookRequest struct {
	ID           string         `json:"id"`
	Name         string         `json:"name" api:"required"`
	Description  string         `json:"description"`
	OS           string         `json:"os"`
	GroupID      string         `json:"group_id"`
	Enabled      *bool          `json:"enabled"`
	Steps        []playbookStep `json:"steps" api:"required"`
	ScheduleKind string         `json:"schedule_kind"`
	TimeOfDay    string         `json:"time_of_day"`
	Weekday      *int           `json:"weekday"`
}

func (s *Server) handleSavePlaybook(w http.ResponseWriter, r *http.Request) {
	var req playbookRequest
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
	if err := checkClientID("playbook", req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "a playbook needs a name", http.StatusBadRequest)
		return
	}
	if !enforcePlatforms[req.OS] {
		http.Error(w, "platform must be blank, linux, windows or darwin", http.StatusBadRequest)
		return
	}
	steps, err := s.validatePlaybookSteps(r, req.Steps, req.OS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.GroupID != "" {
		if g, gerr := s.store.GetComputerGroup(r.Context(), req.GroupID); gerr != nil || g == nil {
			http.Error(w, "no such computer group", http.StatusBadRequest)
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

	encoded, err := json.Marshal(steps)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.ID == "" {
		req.ID = idgen.New("pb-")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	who := auth.CurrentUser(r.Context()).Username
	existing, _ := s.store.GetPlaybook(r.Context(), req.ID)

	if err := s.store.UpsertPlaybook(r.Context(), store.Playbook{
		ID: req.ID, Name: req.Name, Description: strings.TrimSpace(req.Description),
		OS: req.OS, GroupID: req.GroupID, Steps: encoded, Enabled: enabled,
		ScheduleKind: req.ScheduleKind, TimeOfDay: req.TimeOfDay, Weekday: req.Weekday,
		UpdatedBy: who,
	}, next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "playbook.update"
	if existing == nil {
		action = "playbook.create"
	}
	s.audit(r.Context(), auditEvent{
		Action: action, Actor: who, Target: req.Name,
		Detail: map[string]any{"steps": len(steps), "schedule": req.ScheduleKind,
			"platform": req.OS, "group": req.GroupID, "enabled": enabled},
	})
	saved, _ := s.store.GetPlaybook(r.Context(), req.ID)
	writeJSONResponse(w, playbookResponse{Playbook: saved})
}

var playbookRunIf = map[string]bool{"": true, "always": true, "previous_succeeded": true, "previous_failed": true}
var playbookOnFailure = map[string]bool{"": true, "stop": true, "continue": true}
var playbookOperations = map[string]bool{"": true, "install": true, "update": true, "remove": true, "run": true}

// validatePlaybookSteps refuses the steps that would fail at 3am rather
// than at save time. Every reference is resolved now, because a step
// pointing at a package somebody deleted last week is a run that stops
// halfway through with a confusing message.
func (s *Server) validatePlaybookSteps(r *http.Request, steps []playbookStep, targetOS ...string) ([]playbookStep, error) {
	if len(steps) == 0 {
		return nil, fmt.Errorf("a playbook needs at least one step")
	}
	for i := range steps {
		st := &steps[i]
		st.Name = strings.TrimSpace(st.Name)
		if st.ID == "" {
			st.ID = idgen.New("pbs-")
		}
		if err := checkClientID(st.label(i)+": step", st.ID); err != nil {
			return nil, err
		}
		if !playbookRunIf[st.RunIf] {
			return nil, fmt.Errorf("%s: run_if must be always, previous_succeeded or previous_failed", st.label(i))
		}
		if !playbookOnFailure[st.OnFailure] {
			return nil, fmt.Errorf("%s: on_failure must be stop or continue", st.label(i))
		}
		switch st.Kind {
		case "package":
			if !playbookOperations[st.Operation] {
				return nil, fmt.Errorf("%s: operation must be install, update or remove", st.label(i))
			}
			pkg, err := s.store.GetSoftwarePackage(r.Context(), st.PackageID)
			if err != nil || pkg == nil {
				return nil, fmt.Errorf("%s: no such package", st.label(i))
			}
			if pkg.DeployRevision != "" {
				if st.Operation == "" {
					if pkg.Kind == store.KindAction {
						st.Operation = "run"
					} else {
						st.Operation = "install"
					}
				}
				if st.RevisionID == "" || st.FollowLatest {
					st.RevisionID = pkg.DeployRevision
				}
				rev, e := s.store.GetDeployRevision(r.Context(), st.RevisionID)
				if e != nil {
					return nil, e
				}
				if rev == nil || !rev.Published || rev.Retired || rev.PackageID != pkg.ID {
					return nil, fmt.Errorf("%s: select an active published version", st.label(i))
				}
				if e = validateRevisionInputs(rev.Definition, st.Operation, func() string {
					if len(targetOS) > 0 {
						return targetOS[0]
					}
					return ""
				}(), st.Params); e != nil {
					return nil, e
				}
			} else if _, err := resolveParameters(pkg.Parameters, st.Params); err != nil {
				return nil, fmt.Errorf("%s: %w", st.label(i), err)
			}
		case "patch":
			// Nothing to configure — it applies whatever is pending.
		case "notify":
			msg, err := s.store.GetEUNMessage(r.Context(), st.MessageID)
			if err != nil || msg == nil {
				return nil, fmt.Errorf("%s: no such message", st.label(i))
			}
		case "enforce":
			p, err := s.store.GetEnforcePolicy(r.Context(), st.PolicyID)
			if err != nil || p == nil {
				return nil, fmt.Errorf("%s: no such enforce policy", st.label(i))
			}
		case "check":
			var rules []string
			for _, rule := range st.Rules {
				if rule = strings.TrimSpace(rule); rule != "" {
					rules = append(rules, rule)
				}
			}
			if len(rules) == 0 {
				return nil, fmt.Errorf("%s: a check with no rules gates nothing", st.label(i))
			}
			st.Rules = rules
			switch strings.ToLower(strings.TrimSpace(st.Condition)) {
			case "", "all", "any", "none":
			default:
				return nil, fmt.Errorf("%s: condition must be all, any or none", st.label(i))
			}
		case "wait":
			if st.WaitSeconds <= 0 && !st.WaitForOnline {
				return nil, fmt.Errorf("%s: a wait needs a duration, or to wait for the endpoint to check in", st.label(i))
			}
			if st.WaitSeconds < 0 {
				return nil, fmt.Errorf("%s: a wait cannot be negative", st.label(i))
			}
		case "approval":
			// A gate that is last in the playbook approves nothing: every
			// endpoint stops there, somebody is asked, and whatever they
			// say the run has no steps left to take. Better to be told now
			// than to find out when the approval comes back.
			if i == len(steps)-1 {
				return nil, fmt.Errorf("%s: an approval is the last step, so there is nothing for it to gate", st.label(i))
			}
			if st.ApprovalHours < 0 || st.ApprovalHours > approvalMaxHours {
				return nil, fmt.Errorf("%s: give up after between 1 and %d hours", st.label(i), approvalMaxHours)
			}
			st.ApprovalReason = strings.TrimSpace(st.ApprovalReason)
		default:
			return nil, fmt.Errorf("%s: unknown step kind %q", st.label(i), st.Kind)
		}
	}
	return steps, nil
}

// deletePlaybookResponse is what DELETE /api/playbooks/{id} answers.
type deletePlaybookResponse struct {
	Deleted string `json:"deleted"`
}

func (s *Server) handleDeletePlaybook(w http.ResponseWriter, r *http.Request) {
	pb, _ := s.store.GetPlaybook(r.Context(), r.PathValue("id"))
	if pb == nil {
		http.Error(w, "no such playbook", http.StatusNotFound)
		return
	}
	if err := s.store.DeletePlaybook(r.Context(), pb.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "playbook.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: pb.Name, Severity: "notice",
	})
	writeJSONResponse(w, deletePlaybookResponse{Deleted: pb.Name})
}

// runPlaybookResponse is what POST /api/playbooks/{id}/run answers.
type runPlaybookResponse struct {
	Endpoints int    `json:"endpoints"`
	Playbook  string `json:"playbook"`
	RunID     string `json:"run_id"`
}

func (s *Server) handleRunPlaybook(w http.ResponseWriter, r *http.Request) {
	pb, err := s.store.GetPlaybook(r.Context(), r.PathValue("id"))
	if err != nil || pb == nil {
		http.Error(w, "no such playbook", http.StatusNotFound)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	// Resolve the targeting first so access control and any approval see
	// the endpoints this run would actually reach.
	planned, err := s.playbookTargets(r.Context(), *pb)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	plannedIDs := make([]string, 0, len(planned))
	for _, a := range planned {
		plannedIDs = append(plannedIDs, a.AgentID)
	}
	if !s.checkTargets(w, r, "playbooks", plannedIDs) {
		return
	}
	if s.requireApproval(w, r, "playbooks", "playbooks.run",
		fmt.Sprintf("run playbook %s on %d endpoint(s)", pb.Name, len(plannedIDs)), plannedIDs, map[string]any{}) {
		return
	}
	runID, targets, err := s.launchPlaybook(r.Context(), *pb, who)
	if err != nil {
		// A conflict, not a bad request: nothing about the call was wrong,
		// and trying again once the current run finishes is the right move.
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "already running") {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}
	writeJSONResponse(w, runPlaybookResponse{
		RunID: runID, Endpoints: targets, Playbook: pb.Name,
	})
}
