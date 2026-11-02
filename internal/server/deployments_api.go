package server

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// A deployment is one identified event that targeted some set of devices.
// Everything that touches endpoints creates one — a schedule firing, a bulk
// patch deploy, a one-off apply to a single machine, a Self Service install
// — so this is the single place to answer "what has mustra done, to what,
// on whose say-so, and did it work".
//
// Status is derived rather than stored: a run whose per-device actions are
// all finished is done; one with any action still open is running; one
// whose actions never appeared (an agent that was offline when the command
// went out) ages into "no response" rather than hanging as running forever.

// deploymentStallAfter is how long a run may sit with work still open
// before it is called stalled. It must stay comfortably longer than the
// agent's own patchApplyTimeout (2h) — a legitimate cumulative update on a
// badly out-of-date machine will run for hours, and calling that "stalled"
// while it is still installing is exactly the kind of false reading this
// whole path is meant to stop telling.
const deploymentStallAfter = 3 * time.Hour

type deploymentSummary struct {
	store.PatchJobRun
	Status   string         `json:"status"`
	Outcomes map[string]int `json:"outcomes"`
	Kind     string         `json:"kind"`
	// Category is what the run did, so a page can list its own kind of
	// deployment: "patch", "software", "playbook" or "other". Derived from
	// the work dispatched, not from the run's name, which an action package
	// sets to anything.
	Category string `json:"category"`
	// ConsoleOutput is set when the run queued catalog deploy jobs, whose
	// per-endpoint console output is kept under Software → Deployment
	// progress (keyed by the same ID as the endpoint's action). Legacy
	// package runs keep only the detail on the action itself.
	ConsoleOutput bool `json:"console_output,omitempty"`
}

// listDeploymentsResponse is what GET /api/patches/deployments answers.
type listDeploymentsResponse struct {
	Active      []deploymentSummary `json:"active"`
	Deployments []deploymentSummary `json:"deployments"`
	Inactive    []deploymentSummary `json:"inactive"`
}

func (s *Server) handleListDeployments(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.ListPatchJobRuns(r.Context(), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ids := make([]string, 0, len(runs))
	for _, run := range runs {
		ids = append(ids, run.ID)
	}
	counts, err := s.store.RunOutcomeCounts(r.Context(), ids)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	kinds, err := s.store.RunActionKinds(r.Context(), ids)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := make([]deploymentSummary, 0, len(runs))
	for _, run := range runs {
		c := counts[run.ID]
		if c == nil {
			c = map[string]int{}
		}
		out = append(out, deploymentSummary{
			PatchJobRun:   run,
			Outcomes:      c,
			Status:        deploymentStatus(run, c),
			Kind:          deploymentKind(run),
			Category:      deploymentCategory(run, kinds[run.ID]),
			ConsoleOutput: slices.Contains(kinds[run.ID], "deploy_job"),
		})
	}

	// "Active" and "inactive" as the console shows them: anything still
	// working is active, everything else is history.
	active, inactive := []deploymentSummary{}, []deploymentSummary{}
	for _, d := range out {
		if deploymentActive(d.Status) {
			active = append(active, d)
		} else {
			inactive = append(inactive, d)
		}
	}
	writeJSONResponse(w, listDeploymentsResponse{
		Deployments: out, Active: active, Inactive: inactive,
	})
}

// getDeploymentResponse is what GET /api/patches/deployments/{id} answers.
type getDeploymentResponse struct {
	Deployment deploymentSummary           `json:"deployment"`
	Devices    []store.AgentActionWithHost `json:"devices"`
}

func (s *Server) handleGetDeployment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := s.store.GetPatchJobRun(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if run == nil {
		http.Error(w, "no deployment with id "+id, http.StatusNotFound)
		return
	}
	actions, err := s.store.ActionsForRun(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts := map[string]int{}
	for _, a := range actions {
		counts[a.Status]++
	}
	kinds, err := s.store.RunActionKinds(r.Context(), []string{id})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if actions == nil {
		actions = []store.AgentActionWithHost{}
	}
	writeJSONResponse(w, getDeploymentResponse{
		Deployment: deploymentSummary{
			PatchJobRun: *run, Outcomes: counts,
			Status: deploymentStatus(*run, counts), Kind: deploymentKind(*run),
			Category:      deploymentCategory(*run, kinds[id]),
			ConsoleOutput: slices.Contains(kinds[id], "deploy_job"),
		},
		Devices: actions,
	})
}

// deploymentActive: a run still working, whichever stage it reports.
func deploymentActive(status string) bool {
	return status == "running" || status == "downloading" || status == "installing"
}

func deploymentStatus(run store.PatchJobRun, counts map[string]int) string {
	total := 0
	for _, n := range counts {
		total += n
	}
	failures := counts["failed"] + counts["cancelled"] + counts["interrupted"] + counts["expired"] + counts["unsupported"]
	// Skipped (nothing permitted by patch lists) and pending restart
	// (installed, reboot outstanding) are both non-failures; the second
	// is called out on its own when it is all a run has to show.
	successes := counts["succeeded"] + counts["skipped"] + counts["pending_restart"]
	open := counts["started"] + counts["running"] + counts["pending"] + counts["downloading"] + counts["installing"]
	stale := time.Since(run.StartedAt) > deploymentStallAfter
	switch {
	case total == 0 && stale:
		return "no response"
	case total == 0:
		return "running"
	// "started" is what StartAgentAction records; a run with any action
	// still open is in progress, whatever the wording.
	case open > 0:
		if stale {
			return "stalled"
		}
		// Say which stage, not just that something is open: installing
		// outranks downloading, which outranks a job that has only started.
		switch {
		case counts["installing"] > 0:
			return "installing"
		case counts["downloading"] > 0:
			return "downloading"
		}
		return "running"
	// Held for a maintenance window: not stalled, however long it takes,
	// because the wait itself is bounded by patchWaitLoop.
	case counts["waiting"] > 0:
		return "waiting"
	// A device the agent stopped waiting on didn't necessarily fail — the
	// update may still be installing — so it reads as its own outcome
	// rather than being folded into success or failure.
	case counts["timed_out"] > 0 && failures == 0 && successes == 0 && counts["no_response"] == 0:
		return "timed out"
	// Every endpoint that was asked was offline: nothing ran anywhere,
	// which is neither a failure of the package nor a timeout.
	case counts["no_response"] > 0 && counts["timed_out"] == 0 && failures == 0 && successes == 0:
		return "no response"
	case (failures > 0 || counts["timed_out"] > 0 || counts["no_response"] > 0) && successes > 0:
		return "partial"
	case failures > 0 || counts["timed_out"] > 0 || counts["no_response"] > 0:
		return "failed"
	case counts["pending_restart"] > 0 && counts["succeeded"] == 0 && counts["skipped"] == 0:
		return "pending restart"
	default:
		return "succeeded"
	}
}

// deploymentKind labels a run by where it came from, so the Deployments
// list can be read without opening each one.
// deploymentCategory names what a run did. A playbook is its own category
// even when its steps install software or patch, because it is read as one
// thing on its own page. A patch schedule that fired while every target was
// offline dispatched nothing, and its schedule is what says it was patching.
func deploymentCategory(run store.PatchJobRun, kinds []string) string {
	if strings.HasPrefix(run.ScheduleName, "Playbook: ") {
		return "playbook"
	}
	software, patch := false, false
	for _, k := range kinds {
		switch {
		case k == "patch_apply":
			patch = true
		case strings.HasPrefix(k, "software_"), k == "catalog_install", k == "deploy_job":
			software = true
		}
	}
	switch {
	case software:
		return "software"
	case patch, len(kinds) == 0 && run.ScheduleID != "":
		return "patch"
	}
	return "other"
}

func deploymentKind(run store.PatchJobRun) string {
	switch {
	case strings.HasPrefix(run.ScheduleName, "Self Service:"):
		return "self service"
	case run.ScheduleID != "":
		return "scheduled"
	case run.AgentCount == 1:
		return "single device"
	default:
		return "bulk"
	}
}
