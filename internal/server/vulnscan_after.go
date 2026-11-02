package server

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// After a patch or software run, the vulnerability findings it fixed should
// go away within minutes, not at the next six-hourly scan; otherwise a
// briefing still lists an endpoint as vulnerable after the fix is in, and
// the remediation looks as if it did nothing.
//
// Two things have to be fresh for that: the endpoint's installed software
// (what the scan reads) and then the scan itself. A software run makes the
// agent republish its installed apps; apply_patches does not (it republishes
// only the patches sensor), so for patches the server asks the endpoint for
// its list directly, which works with every agent version.

const (
	// vulnRescanSettle is how long a requested scan waits for the rest of a
	// run's endpoints to report before it starts.
	vulnRescanSettle = 90 * time.Second
	// remediatedWindow is how long after a run an endpoint's new software
	// list still counts as that run's result.
	remediatedWindow = 30 * time.Minute
	// installedAppsWait is how long to wait for an endpoint's software list.
	installedAppsWait = 60 * time.Second
)

// requestVulnScan asks vulnScanLoop for a scan soon. Requests made while
// one is pending fold into it.
func (s *Server) requestVulnScan() {
	if s.vulnKick == nil {
		return
	}
	select {
	case s.vulnKick <- struct{}{}:
	default:
	}
}

// markRemediated records that a run just changed agentID's software, so its
// next installed-apps snapshot asks for a scan.
func (s *Server) markRemediated(agentID string) {
	s.remediated.Store(agentID, time.Now())
}

// remediatedRecently reports, once, whether agentID was changed by a run in
// the last remediatedWindow.
func (s *Server) remediatedRecently(agentID string) bool {
	v, ok := s.remediated.LoadAndDelete(agentID)
	if !ok {
		return false
	}
	at, _ := v.(time.Time)
	return time.Since(at) < remediatedWindow
}

// afterRemediation refreshes an endpoint's software list once a patch or
// software run on it has finished (or a patch was verified after its
// restart) and asks for a scan. It returns at once; the work runs detached
// from the message that reported the result.
func (s *Server) afterRemediation(ctx context.Context, agentID string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), installedAppsWait+10*time.Second)
		defer cancel()
		if err := s.refreshInstalledApps(ctx, agentID); err != nil {
			// The agent's own periodic snapshot catches up later; mark it so
			// that snapshot still triggers the scan.
			s.logger.Info("could not refresh installed apps after patching; waiting for the next snapshot",
				"agent_id", agentID, "error", err)
			s.markRemediated(agentID)
			return
		}
		s.requestVulnScan()
	}()
}

// refreshInstalledApps asks one endpoint for its installed software and
// stores the answer as its installed_apps snapshot.
func (s *Server) refreshInstalledApps(ctx context.Context, agentID string) error {
	if s.queryMgr == nil {
		return errNoQueryManager
	}
	aq, err := s.queryMgr.Start(proto.QueryKindInstalledApps, nil, bnats.QAgent(agentID), 1)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(installedAppsWait)
	for {
		snap := aq.snapshot()
		for _, r := range snap.Results {
			if r.AgentID != agentID {
				continue
			}
			if r.Error != "" {
				return errors.New(r.Error)
			}
			if r.InstalledApps == nil {
				// Not "nothing installed": an empty answer must not wipe the
				// inventory the scan and the Software pages read.
				return errors.New("the endpoint returned no software list")
			}
			raw, err := json.Marshal(r.InstalledApps)
			if err != nil {
				return err
			}
			data, err := normalizeSnapshotData(proto.SensorInstalledApps, raw)
			if err != nil {
				return err
			}
			return s.store.UpsertSensorData(ctx, agentID, string(proto.SensorInstalledApps), time.Now().UTC(), data)
		}
		if time.Now().After(deadline) {
			return errors.New("no answer within " + installedAppsWait.String())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

var errNoQueryManager = errors.New("no query manager")
