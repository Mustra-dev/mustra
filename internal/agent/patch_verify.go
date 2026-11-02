package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/shirou/gopsutil/v4/host"
)

// A patch job that installed updates waiting on a restart ends at "pending
// restart", and nothing used to close it: whether the restart finished the
// updates was left for someone to check by hand. The agent now remembers
// each such job across the restart and, once the endpoint is back up,
// checks the updates again and reports how it ended.

// patchVerification is one job waiting on a restart.
type patchVerification struct {
	RunID    string    `json:"run_id"`
	ActionID string    `json:"action_id"`
	Names    []string  `json:"names"`
	Saved    time.Time `json:"saved"`
}

const (
	maxPatchVerifications = 20
	// A record that never saw a restart in a month is not going to.
	patchVerificationMaxAge = 30 * 24 * time.Hour
	// Windows Update is busy right after boot finishing what the restart
	// started; asked too early, it still lists updates being completed.
	patchVerifySettle = 2 * time.Minute
)

var patchVerifyMu sync.Mutex

func (a *Agent) loadPatchVerifications() []patchVerification {
	raw, err := a.store.LoadPatchVerifications()
	if err != nil || len(raw) == 0 {
		return nil
	}
	var out []patchVerification
	_ = json.Unmarshal(raw, &out)
	return out
}

func (a *Agent) savePatchVerifications(list []patchVerification) {
	raw, _ := json.Marshal(list)
	if err := a.store.SavePatchVerifications(raw); err != nil {
		a.logger.Warn("saving patch verifications failed", "error", err)
	}
}

// rememberPatchVerification records a job to check after the next restart.
func (a *Agent) rememberPatchVerification(v patchVerification) {
	if a.store == nil || len(v.Names) == 0 {
		return
	}
	patchVerifyMu.Lock()
	defer patchVerifyMu.Unlock()
	list := append(a.loadPatchVerifications(), v)
	if len(list) > maxPatchVerifications {
		list = list[len(list)-maxPatchVerifications:]
	}
	a.savePatchVerifications(list)
}

// verifyPatchesAfterRestart runs once at startup. Jobs saved before the
// endpoint last booted have had their restart: each is checked against the
// current patch list and closed. Jobs saved since are still waiting.
func (a *Agent) verifyPatchesAfterRestart(ctx context.Context) {
	if a.store == nil || len(a.loadPatchVerifications()) == 0 {
		return
	}
	bootSecs, err := host.BootTimeWithContext(ctx)
	if err != nil {
		return
	}
	boot := time.Unix(int64(bootSecs), 0)
	if wait := patchVerifySettle - time.Since(boot); wait > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}

	patchVerifyMu.Lock()
	defer patchVerifyMu.Unlock()
	var keep []patchVerification
	var after []proto.PatchInfo
	collected := false
	for _, v := range a.loadPatchVerifications() {
		if time.Since(v.Saved) > patchVerificationMaxAge {
			continue
		}
		if !v.Saved.Before(boot) {
			keep = append(keep, v)
			continue
		}
		if !collected {
			if after, err = collectPatches(ctx, a.nc, a.agentID); err != nil {
				a.logger.Warn("patch check after restart failed", "error", err)
				return // all kept; the next start tries again
			}
			collected = true
		}
		res, again := patchVerificationResult(v, after)
		if again {
			v.Saved = time.Now()
			keep = append(keep, v)
		}
		a.logger.Info("patch job checked after restart", "run_id", v.RunID, "ok", res.OK, "detail", res.Detail)
		a.reportActionResult(ctx, res)
	}
	a.savePatchVerifications(keep)
}

// patchVerificationResult turns one check into the action's final report.
// again is true when the updates want yet another restart (a .NET update
// can take two), in which case the job stays pending and is kept.
func patchVerificationResult(v patchVerification, after []proto.PatchInfo) (res proto.AgentActionResult, again bool) {
	res = proto.AgentActionResult{RunID: v.RunID, ActionID: v.ActionID, Kind: "patch_apply", Verification: true}
	needRestart, notInstalled := patchesStillPending(v.Names, after)
	switch {
	case len(notInstalled) > 0:
		res.Detail = fmt.Sprintf("After the restart, %d of %d update(s) are still pending: %s",
			len(notInstalled), len(v.Names), strings.Join(notInstalled, ", "))
	case len(needRestart) > 0:
		res.OK, res.RebootRequired = true, true
		res.Detail = "After the restart, still waiting on another restart: " + strings.Join(needRestart, ", ")
		return res, true
	default:
		res.OK = true
		res.Detail = fmt.Sprintf("Verified after the restart: all %d update(s) are installed.", len(v.Names))
	}
	return res, false
}
