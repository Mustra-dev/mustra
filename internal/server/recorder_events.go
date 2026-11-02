package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Recorder events, server half: registry, network, DNS and logon events
// stored on the same terms as process events (a short timeline, matches
// kept for a month) and run through Signals as they arrive.

func (s *Server) consumeRecorderEvents(ctx context.Context) (jetstream.ConsumeContext, error) {
	cons, err := s.js.CreateOrUpdateConsumer(ctx, bnats.AgentStreamName, jetstream.ConsumerConfig{
		Durable:       "server-recorder-events",
		FilterSubject: bnats.AgentRecorderEventsWildcard(),
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("create recorder event consumer: %w", err)
	}
	return cons.Consume(func(msg jetstream.Msg) {
		var batch proto.RecorderBatch
		if err := json.Unmarshal(msg.Data(), &batch); err != nil {
			s.logger.Warn("discarding malformed recorder batch", "error", err)
			msg.Term()
			return
		}
		// Attributed from the subject; see natsauth_ingest.go.
		id, err := attributeFromSubject(msg.Subject(), batch.AgentID)
		if err != nil {
			msg.Term()
			return
		}
		batch.AgentID = id
		if err := s.handleRecorderEvents(ctx, batch); err != nil {
			s.retryOrTerm(msg, "recorder events", err)
			return
		}
		msg.Ack()
	})
}

// recorderFields flattens an event into the object.property map Signals
// evaluate, and the fields column the console shows.
func recorderFields(ev proto.RecorderEvent) map[string]string {
	f := map[string]string{}
	switch ev.Kind {
	case "registry":
		f["registry.key"], f["registry.value"], f["registry.data"], f["registry.op"] = ev.Key, ev.ValueName, ev.Data, ev.Op
		f["registry.process"], f["registry.user"] = ev.Process, ev.User
	case "network":
		f["network.protocol"], f["network.direction"] = ev.Protocol, ev.Op
		f["network.local_ip"], f["network.local_port"] = ev.LocalIP, strconv.Itoa(ev.LocalPort)
		f["network.remote_ip"], f["network.remote_port"] = ev.RemoteIP, strconv.Itoa(ev.RemotePort)
		f["network.process"], f["network.user"] = ev.Process, ev.User
	case "dns":
		f["dns.query"], f["dns.answers"], f["dns.process"] = ev.Query, ev.Answers, ev.Process
	case "logon":
		f["logon.user"], f["logon.domain"], f["logon.source"] = ev.User, ev.Domain, ev.Source
		f["logon.type"], f["logon.outcome"], f["logon.reason"] = ev.LogonType, ev.Op, ev.Reason
	}
	return f
}

func (s *Server) handleRecorderEvents(ctx context.Context, batch proto.RecorderBatch) error {
	rows := make([]store.RecorderEvent, 0, len(batch.Events)+1)
	perKind := map[string]int{}
	for _, ev := range batch.Events {
		if ev.Kind == "" {
			continue
		}
		perKind[ev.Kind]++
		fields := recorderFields(ev)
		row := store.RecorderEvent{
			AgentID: batch.AgentID, Kind: ev.Kind, At: ev.At, Count: max(ev.Count, 1), PID: ev.PID,
			Process: ev.Process, Username: ev.User, Op: ev.Op, Summary: ev.Summary, Fields: fields,
			Source: batch.Sources[ev.Kind],
		}
		if hit := s.matchSignals(ctx, batch.AgentID, ev.Kind, fields, ev.Summary, max(ev.Count, 1)); hit != "" {
			row.MatchedSignal = hit
		}
		rows = append(rows, row)
	}
	rows = append(rows, suppressedRecorderRows(batch)...)
	if err := s.store.InsertRecorderEvents(ctx, rows); err != nil {
		return err
	}
	if len(rows) > 0 {
		s.logger.Debug("recorder events recorded", "agent_id", batch.AgentID, "kinds", perKind, "suppressed", batch.Suppressed)
	}
	return nil
}

func (s *Server) recorderEventPruneLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := s.store.PruneRecorderEvents(ctx, store.RecorderEventRetention, store.RecorderEventMatchedRetention); err != nil {
				s.logger.Warn("prune recorder events failed", "error", err)
			} else if n > 0 {
				s.logger.Info("pruned old recorder events", "rows", n)
			}
		}
	}
}

// --- HTTP ---

// listRecorderEventsResponse is what GET /api/recorder-events answers.
type listRecorderEventsResponse struct {
	Events               []store.RecorderEvent                `json:"events"`
	MatchedRetentionDays int                                  `json:"matched_retention_days"`
	RetentionHours       int                                  `json:"retention_hours"`
	Summary              map[string]store.RecorderKindSummary `json:"summary"`
}

func (s *Server) handleListRecorderEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	kind := r.URL.Query().Get("kind")
	events, err := s.store.ListRecorderEvents(r.Context(), kind, r.URL.Query().Get("agent"),
		strings.TrimSpace(r.URL.Query().Get("q")), r.URL.Query().Get("matched") != "", limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := s.store.RecorderEventSummary(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listRecorderEventsResponse{
		Events: events, Summary: summary,
		RetentionHours:       int(store.RecorderEventRetention.Hours()),
		MatchedRetentionDays: int(store.RecorderEventMatchedRetention.Hours() / 24),
	})
}

// suppressedRecorderRows records what the agent dropped past its batch
// cap, one row per event kind with that kind's source, so a DNS or
// registry storm shows under its own kind. An agent that sends only the
// total (older than suppressed_by_kind) has its drops booked as network
// events, as before; so is any part of the total the split leaves out.
func suppressedRecorderRows(batch proto.RecorderBatch) []store.RecorderEvent {
	row := func(kind string, n int) store.RecorderEvent {
		return store.RecorderEvent{AgentID: batch.AgentID, Kind: "suppressed", Op: kind, At: batch.Until, Count: n,
			Source:  batch.Sources[kind],
			Summary: fmt.Sprintf("%d more %s events in this window, not reported individually", n, kind)}
	}
	var out []store.RecorderEvent
	rest := batch.Suppressed
	kinds := make([]string, 0, len(batch.SuppressedByKind))
	for k := range batch.SuppressedByKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		n := batch.SuppressedByKind[k]
		if n <= 0 || k == "" {
			continue
		}
		out = append(out, row(k, n))
		rest -= n
	}
	if rest > 0 {
		out = append(out, row("network", rest))
	}
	return out
}
