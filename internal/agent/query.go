package agent

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"sync/atomic"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// subscribeQueries subscribes to every mustra.q.* subject this agent's
// identity matches (all, its OS, its site, and itself individually) and
// answers matching queries. These are plain core-NATS subscriptions, not
// JetStream: a live query that arrives while the agent is offline is
// expected to simply go unanswered (the console shows it as not responded),
// so there is nothing to buffer or replay here.
func (a *Agent) subscribeQueries(ctx context.Context) (func(), error) {
	subjects := []string{
		bnats.QAll(),
		bnats.QOS(a.info.OS),
		bnats.QSite(a.info.Site),
		bnats.QAgent(a.agentID),
	}

	var subs []*gonats.Subscription
	for _, subj := range subjects {
		sub, err := a.nc.Subscribe(subj, a.handleQuery(ctx))
		if err != nil {
			for _, s := range subs {
				s.Unsubscribe()
			}
			return nil, err
		}
		subs = append(subs, sub)
	}

	return func() {
		for _, s := range subs {
			s.Unsubscribe()
		}
	}, nil
}

// maxAnswerDelay caps the spread a server may ask for, so a bad envelope
// cannot hold an answer (and its goroutine) for long.
const maxAnswerDelay = 30 * time.Second

func (a *Agent) handleQuery(ctx context.Context) gonats.MsgHandler {
	return func(msg *gonats.Msg) {
		var q proto.QueryEnvelope
		if err := json.Unmarshal(msg.Data, &q); err != nil {
			a.logger.Warn("discarding malformed query envelope", "error", err)
			return
		}
		if !q.Predicate.Match(a.info) {
			return
		}
		// A fleet-wide query asks the fleet to spread its answers
		// (QueryEnvelope.AnswerWithinMs); a query to this agent alone is
		// answered at once.
		if d := answerDelay(q.AnswerWithinMs, msg.Subject == bnats.QAgent(a.agentID)); d > 0 {
			go func() {
				select {
				case <-ctx.Done():
				case <-time.After(d):
					a.answerQuery(ctx, q)
				}
			}()
			return
		}
		a.answerQuery(ctx, q)
	}
}

// answerDelay is a random wait within the requested window, capped.
func answerDelay(withinMs int, direct bool) time.Duration {
	if direct || withinMs <= 0 {
		return 0
	}
	window := min(time.Duration(withinMs)*time.Millisecond, maxAnswerDelay)
	return rand.N(window)
}

func (a *Agent) answerQuery(ctx context.Context, q proto.QueryEnvelope) {

	result := proto.QueryResult{
		QueryID:   q.QueryID,
		AgentID:   a.agentID,
		Timestamp: time.Now().UTC(),
	}

	switch q.Kind {
	case proto.QueryKindFacts:
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		facts, err := collectFacts(fctx, a.agentID, a.info, a.cfg.AgentVersion)
		cancel()
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Facts = &facts
		}
	case proto.QueryKindProcesses:
		pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		procs, err := collectProcesses(pctx)
		cancel()
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Processes = procs
		}
	case proto.QueryKindServices:
		sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		svcs, err := collectServices(sctx)
		cancel()
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Services = svcs
		}
	case proto.QueryKindInstalledApps:
		actx, cancel := context.WithTimeout(ctx, 30*time.Second)
		apps, err := collectInstalledApps(actx)
		cancel()
		if err != nil {
			result.Error = err.Error()
		} else {
			result.InstalledApps = apps
		}
	case proto.QueryKindPatches:
		// A Windows Update search regularly takes longer than a rescan
		// waits (dc01 and dc02 never answered in 30s). The search runs with
		// the sensor's own budget; if it is not done in time the answer says
		// so, and the finished search is published as the patches sensor.
		patches, pending, err := a.rescanPatches(ctx, 30*time.Second)
		if pending {
			result.Pending = true
			result.Error = "still searching (Windows Update can take a few minutes); the list updates when it finishes"
		} else if err != nil {
			result.Error = err.Error()
		} else {
			result.Patches = patches
		}
	default:
		result.Error = "unsupported query kind: " + string(q.Kind)
	}

	payload, err := json.Marshal(result)
	if err != nil {
		a.logger.Error("marshal query result failed", "error", err, "query_id", q.QueryID)
		return
	}
	if err := a.nc.Publish(a.resultSubject(q.QueryID), payload); err != nil {
		a.logger.Error("publish query result failed", "error", err, "query_id", q.QueryID)
	}
}

// resultSubject is where this agent answers a fleet question: the per-agent
// form when it has its own credential, so the server can attribute the
// answer from the subject; the legacy form otherwise, which is all a server
// that predates enrollment listens on.
func (a *Agent) resultSubject(queryID string) string {
	if a.cred != nil {
		return bnats.ResultFrom(queryID, a.cred.AgentID)
	}
	return bnats.Result(queryID)
}

var patchRescanBusy atomic.Bool

// rescanPatches collects patches for a rescan, waiting up to wait. A
// search still running then carries on in the background and publishes
// its result; only one runs at a time.
func (a *Agent) rescanPatches(ctx context.Context, wait time.Duration) ([]proto.PatchInfo, bool, error) {
	if !patchRescanBusy.CompareAndSwap(false, true) {
		return nil, true, nil
	}
	type res struct {
		patches []proto.PatchInfo
		err     error
	}
	done := make(chan res, 1)
	go func() {
		defer patchRescanBusy.Store(false)
		bg := context.WithoutCancel(ctx)
		cctx, cancel := context.WithTimeout(bg, sensorTimeout(proto.SensorPatches))
		p, err := a.collectPatchesReported(cctx)
		cancel()
		done <- res{p, err}
		if err == nil {
			a.publishSensor(bg, proto.SensorPatches, p)
		}
	}()
	select {
	case r := <-done:
		return r.patches, false, r.err
	case <-time.After(wait):
		return nil, true, nil
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}
