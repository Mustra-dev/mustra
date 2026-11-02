package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Real-time file events, server half.
//
// This is the one place mustra learns something the moment it happens
// rather than at the next collection, and the difference is worth being
// precise about. A hunt matches indicators against cached sensor data on a
// fifteen-minute timer, so a file that lands and is deleted between two
// sweeps is invisible to it. An event arrives seconds after the write, and
// is matched against the same indicators here — so a known-bad filename
// dropped into /etc/cron.d raises its finding while it is still there.
//
// What this deliberately does not claim is attribution. The event says a
// path changed and when; it does not say which process did it. That needs
// kernel plumbing mustra does not have (ETW, eBPF, EndpointSecurity), and
// a plausible guess would be worse than the honest gap.

func (s *Server) consumeFileEvents(ctx context.Context) (jetstream.ConsumeContext, error) {
	cons, err := s.js.CreateOrUpdateConsumer(ctx, bnats.AgentStreamName, jetstream.ConsumerConfig{
		Durable:       "server-file-events",
		FilterSubject: bnats.AgentFileEventsWildcard(),
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("create file event consumer: %w", err)
	}
	return cons.Consume(func(msg jetstream.Msg) {
		var batch proto.FileEventBatch
		if err := json.Unmarshal(msg.Data(), &batch); err != nil {
			s.logger.Warn("discarding malformed file event batch", "error", err)
			msg.Term()
			return
		}
		// Attributed from the subject; see natsauth_ingest.go.
		id, err := attributeFromSubject(msg.Subject(), batch.AgentID)
		if err != nil {
			s.logger.Warn("discarding misattributed file event batch", "error", err)
			msg.Term()
			return
		}
		batch.AgentID = id
		if err := s.handleFileEvents(ctx, batch); err != nil {
			s.retryOrTerm(msg, "file events", err)
			return
		}
		msg.Ack()
	})
}

func (s *Server) handleFileEvents(ctx context.Context, batch proto.FileEventBatch) error {
	// Indicators are read once per batch rather than once per event: a
	// package install can produce two hundred paths, and two hundred
	// round-trips to answer the same question is how a security feature
	// becomes the reason the database is busy.
	iocs, err := s.store.ListIOCs(ctx)
	if err != nil {
		return err
	}
	var pathIOCs []store.IOC
	for _, i := range iocs {
		if i.Enabled && i.Kind == store.IOCFilePath && strings.TrimSpace(i.Value) != "" {
			pathIOCs = append(pathIOCs, i)
		}
	}

	rows := make([]store.FileEvent, 0, len(batch.Events)+1)
	hits := map[string][]string{} // ioc id -> paths it matched here
	byID := map[string]store.IOC{}
	for _, i := range iocs {
		byID[i.ID] = i
	}

	for _, ev := range batch.Events {
		row := store.FileEvent{
			AgentID: batch.AgentID, Path: ev.Path, Op: ev.Op, At: ev.At, Count: 1,
		}
		lower := strings.ToLower(ev.Path)
		for _, ioc := range pathIOCs {
			if strings.Contains(lower, strings.ToLower(ioc.Value)) {
				row.MatchedIOC = ioc.ID
				hits[ioc.ID] = append(hits[ioc.ID], ev.Path)
				break
			}
		}
		if sig := s.matchSignals(ctx, batch.AgentID, "file", fileFields(ev), ev.Op+" "+ev.Path, 1); sig != "" && row.MatchedIOC == "" {
			row.MatchedIOC = sig
		}
		row.Labels, _, _ = s.labelChange(ctx, batch.AgentID, ev.Path, ev.Op, ev.At)
		rows = append(rows, row)
	}
	if batch.Suppressed > 0 {
		// Recorded as a row of its own so a quiet-looking window is never a
		// lie. The events themselves are gone; the fact that there were
		// many is not.
		rows = append(rows, store.FileEvent{
			AgentID: batch.AgentID, Op: "suppressed", At: batch.Until,
			Count: batch.Suppressed,
		})
	}
	if err := s.store.InsertFileEvents(ctx, rows); err != nil {
		return err
	}
	if len(batch.Events) > 0 || batch.Suppressed > 0 {
		s.logger.Debug("file events recorded", "agent_id", batch.AgentID,
			"events", len(batch.Events), "suppressed", batch.Suppressed,
			"watching", batch.Watching)
	}

	if len(hits) == 0 {
		return nil
	}
	// Resolved only once there is something to announce: this is a full
	// agents scan, and doing it per batch per endpoint every five seconds
	// in steady state is a lot of database for nothing.
	hostname := s.hostnameFor(ctx, batch.AgentID)
	for iocID, paths := range hits {
		ioc := byID[iocID]
		newHere := false
		for _, path := range paths {
			isNew, err := s.store.RecordIOCFinding(ctx, store.IOCFinding{
				ID: idgen.New("ioc-f-"), IOCID: iocID, AgentID: batch.AgentID,
				MatchedValue: path,
				Context:      fmt.Sprintf("seen in real time: %s was written to %s", ioc.Value, path),
			})
			if err != nil {
				s.logger.Warn("could not record a real-time finding", "ioc", ioc.Name, "error", err)
				continue
			}
			newHere = newHere || isNew
		}
		if !newHere {
			continue
		}
		severity := ioc.Severity
		if severity != "critical" && severity != "info" {
			severity = "warning"
		}
		s.logger.Warn("indicator matched in real time", "ioc", ioc.Name,
			"host", hostname, "paths", len(paths))
		s.notify(ctx, severity, "Threat Response",
			"Indicator seen as it happened: "+ioc.Name,
			fmt.Sprintf("%s on %s, within seconds of the write.",
				summariseCount(paths, "paths"), hostname), "/hunt#findings")
	}

	return nil
}

// hostnameFor resolves a hostname for a message, falling back to the agent
// ID. A notification naming an opaque identifier is one somebody has to go
// and look up before they can act on it.
//
// One row: this runs for every file and process event batch, on their
// consumers, where a whole-table read per batch grows with the fleet.
func (s *Server) hostnameFor(ctx context.Context, agentID string) string {
	h, err := s.store.GetAgentHostname(ctx, agentID)
	if err != nil || h == "" {
		return agentID
	}
	return h
}

// fileEventPruneLoop keeps the table a fortnight deep. Hourly rather than
// on every insert: the work is a range delete on an indexed column, and
// doing it in the hot path of a burst is the wrong time to do it.
func (s *Server) fileEventPruneLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := s.store.PruneFileEvents(ctx, store.FileEventRetention)
			if err != nil {
				s.logger.Warn("prune file events failed", "error", err)
				continue
			}
			if n > 0 {
				s.logger.Info("pruned old file events", "rows", n)
			}
		}
	}
}

// --- HTTP ---

// listFileEventsResponse is what GET /api/file-events answers.
type listFileEventsResponse struct {
	Events        []store.FileEvent      `json:"events"`
	RetentionDays int                    `json:"retention_days"`
	Summary       store.FileEventSummary `json:"summary"`
}

func (s *Server) handleListFileEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.store.ListFileEvents(r.Context(),
		r.URL.Query().Get("agent"), r.URL.Query().Get("matched") != "", limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := s.store.FileEventSummary(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listFileEventsResponse{
		Events: events, Summary: summary,
		RetentionDays: int(store.FileEventRetention.Hours() / 24),
	})
}
