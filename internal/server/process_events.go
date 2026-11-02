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

// Real-time process events, server half.
//
// The mirror of file events, and the more consequential of the two: a hunt
// matches indicators against the processes sensor, which is a snapshot on a
// timer, so a process that runs and exits between two collections is
// invisible to it — and "runs and exits" describes most of what somebody
// who should not be there does. Matching here catches it at exec.
//
// A matched process is *not* killed automatically, and that is deliberate.
// mustra can kill a process (see live_response.go) and an operator can, in
// one click, from the finding. Doing it on a name match with no human in
// the loop would mean a mistyped indicator takes out a domain controller's
// LSASS at three in the morning, and the blast radius of a false positive
// would be set by whoever typed the indicator rather than by anyone
// watching.

func (s *Server) consumeProcessEvents(ctx context.Context) (jetstream.ConsumeContext, error) {
	cons, err := s.js.CreateOrUpdateConsumer(ctx, bnats.AgentStreamName, jetstream.ConsumerConfig{
		Durable:       "server-process-events",
		FilterSubject: bnats.AgentProcessEventsWildcard(),
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("create process event consumer: %w", err)
	}
	return cons.Consume(func(msg jetstream.Msg) {
		var batch proto.ProcessEventBatch
		if err := json.Unmarshal(msg.Data(), &batch); err != nil {
			s.logger.Warn("discarding malformed process event batch", "error", err)
			msg.Term()
			return
		}
		// Attributed from the subject; see natsauth_ingest.go.
		id, err := attributeFromSubject(msg.Subject(), batch.AgentID)
		if err != nil {
			s.logger.Warn("discarding misattributed process event batch", "error", err)
			msg.Term()
			return
		}
		batch.AgentID = id
		if err := s.handleProcessEvents(ctx, batch); err != nil {
			s.retryOrTerm(msg, "process events", err)
			return
		}
		msg.Ack()
	})
}

func (s *Server) handleProcessEvents(ctx context.Context, batch proto.ProcessEventBatch) error {
	iocs, err := s.store.ListIOCs(ctx)
	if err != nil {
		return err
	}
	var nameIOCs []store.IOC
	byID := map[string]store.IOC{}
	for _, i := range iocs {
		byID[i.ID] = i
		if i.Enabled && i.Kind == store.IOCProcessName && strings.TrimSpace(i.Value) != "" {
			// Trimmed here, not only tested: the value is compared exactly
			// below, so an indicator saved as "mimikatz.exe " passed this
			// filter and then matched nothing, for ever, silently.
			i.Value = strings.TrimSpace(i.Value)
			nameIOCs = append(nameIOCs, i)
		}
	}

	rows := make([]store.ProcessEvent, 0, len(batch.Events)+2)
	hits := map[string][]proto.ProcessEvent{}

	for _, ev := range batch.Events {
		row := store.ProcessEvent{
			AgentID: batch.AgentID, PID: ev.PID, PPID: ev.PPID, Name: ev.Name,
			Cmdline: ev.Cmdline, Username: ev.Username, At: ev.At,
			Source: batch.Source, Kind: "start", Count: max(ev.Count, 1),
		}
		for _, ioc := range nameIOCs {
			// Exact on the name, matching the hunt's matcher: a substring
			// rule would make an indicator for "ps" match every process on
			// the box. The command line is searchable separately, by hand.
			if strings.EqualFold(ev.Name, ioc.Value) {
				row.MatchedIOC = ioc.ID
				hits[ioc.ID] = append(hits[ioc.ID], ev)
				break
			}
		}
		// Signals see the same event; a rule hit is recorded on its own
		// findings list and, when no indicator claimed the row, marks it.
		what := ev.Name
		if ev.Cmdline != "" {
			what = ev.Name + " " + ev.Cmdline
		}
		if sig := s.matchSignals(ctx, batch.AgentID, "process", processFields(ev), what, max(ev.Count, 1)); sig != "" && row.MatchedIOC == "" {
			row.MatchedIOC = sig
		}
		rows = append(rows, row)
	}
	if batch.Suppressed > 0 {
		rows = append(rows, store.ProcessEvent{
			AgentID: batch.AgentID, At: batch.Until, Source: batch.Source,
			Kind: "suppressed", Count: batch.Suppressed,
		})
	}
	if batch.Unidentified > 0 {
		rows = append(rows, store.ProcessEvent{
			AgentID: batch.AgentID, At: batch.Until, Source: batch.Source,
			Kind: "unidentified", Count: batch.Unidentified,
		})
	}
	if err := s.store.InsertProcessEvents(ctx, rows); err != nil {
		return err
	}

	if len(hits) == 0 {
		return nil
	}
	hostname := s.hostnameFor(ctx, batch.AgentID)
	for iocID, evs := range hits {
		ioc := byID[iocID]
		newHere := false
		for _, ev := range evs {
			what := ev.Name
			if ev.Cmdline != "" {
				what = ev.Cmdline
			}
			isNew, err := s.store.RecordIOCFinding(ctx, store.IOCFinding{
				ID: idgen.New("ioc-f-"), IOCID: iocID, AgentID: batch.AgentID,
				MatchedValue: ev.Name,
				Context: fmt.Sprintf("started at %s as %s: %s",
					ev.At.UTC().Format(time.RFC3339), userOrUnknown(ev.Username), what),
			})
			if err != nil {
				s.logger.Warn("could not record a real-time process finding",
					"ioc", ioc.Name, "error", err)
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
		s.logger.Warn("indicator process started", "ioc", ioc.Name,
			"host", hostname, "starts", len(evs))
		s.notify(ctx, severity, "Threat Response",
			"Indicator ran: "+ioc.Name,
			fmt.Sprintf("%s started on %s, caught at exec.", ioc.Value, hostname),
			"/hunt#activity")
	}
	return nil
}

func userOrUnknown(u string) string {
	if strings.TrimSpace(u) == "" {
		return "an unknown user"
	}
	return u
}

func (s *Server) processEventPruneLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := s.store.PruneProcessEvents(ctx,
				store.ProcessEventRetention, store.ProcessEventMatchedRetention)
			if err != nil {
				s.logger.Warn("prune process events failed", "error", err)
				continue
			}
			if n > 0 {
				s.logger.Info("pruned old process events", "rows", n)
			}
		}
	}
}

// --- HTTP ---

// listProcessEventsResponse is what GET /api/process-events answers.
type listProcessEventsResponse struct {
	Events               []store.ProcessEvent      `json:"events"`
	MatchedRetentionDays int                       `json:"matched_retention_days"`
	RetentionHours       int                       `json:"retention_hours"`
	Summary              store.ProcessEventSummary `json:"summary"`
}

func (s *Server) handleListProcessEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.store.ListProcessEvents(r.Context(),
		r.URL.Query().Get("agent"), strings.TrimSpace(r.URL.Query().Get("q")),
		r.URL.Query().Get("matched") != "", limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := s.store.ProcessEventSummary(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listProcessEventsResponse{
		Events: events, Summary: summary,
		RetentionHours:       int(store.ProcessEventRetention.Hours()),
		MatchedRetentionDays: int(store.ProcessEventMatchedRetention.Hours() / 24),
	})
}
