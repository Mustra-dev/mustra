package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// queryExpiry bounds how long a query stays in memory after being issued.
// Long enough for any reasonable console session to watch it, short enough
// that a console left open overnight doesn't leak memory one query at a
// time.
const queryExpiry = 5 * time.Minute

// activeQuery tracks one in-flight (or recently completed) fan-out query:
// what was asked, how many agents were expected to answer, and the results
// collected so far.
type activeQuery struct {
	ID       string
	Expected int
	IssuedAt time.Time

	mu        sync.Mutex
	responded map[string]bool
	results   []proto.QueryResult

	hub *hub
}

func (aq *activeQuery) snapshot() querySnapshot {
	aq.mu.Lock()
	defer aq.mu.Unlock()
	results := make([]proto.QueryResult, len(aq.results))
	copy(results, aq.results)
	return querySnapshot{
		QueryID:   aq.ID,
		Expected:  aq.Expected,
		Responded: len(results),
		IssuedAt:  aq.IssuedAt,
		Results:   results,
	}
}

// querySnapshot is what the HTTP/SSE layer sends to the console — a full
// point-in-time view of one query, not a delta. Simple to reason about and
// cheap at the result volumes a single live query produces.
type querySnapshot struct {
	QueryID   string              `json:"query_id"`
	Expected  int                 `json:"expected"`
	Responded int                 `json:"responded"`
	IssuedAt  time.Time           `json:"issued_at"`
	Results   []proto.QueryResult `json:"results"`
}

// queryManager issues live queries to the fleet and collects results
// streamed back on the shared result-wildcard subscription.
type queryManager struct {
	nc     *gonats.Conn
	logger *slog.Logger

	mu     sync.Mutex
	active map[string]*activeQuery
}

func newQueryManager(nc *gonats.Conn, logger *slog.Logger) *queryManager {
	return &queryManager{nc: nc, logger: logger, active: make(map[string]*activeQuery)}
}

// Start mints a query ID, publishes the envelope to mustra.q.all, and
// registers it to collect results. expected is the online-agent count at
// issue time, shown to the console as the denominator of a responded/
// expected counter. targetSubject is the mustra.q.* subject to publish to
// (bnats.QAll() for the whole fleet, bnats.QAgent(id) to target one agent,
// etc.) — the caller resolves targeting to a subject and an accurate
// expected count.
func (qm *queryManager) Start(kind proto.QueryKind, predicate *proto.Predicate, targetSubject string, expected int) (*activeQuery, error) {
	env := proto.QueryEnvelope{
		QueryID:        newID("q-"),
		Kind:           kind,
		IssuedAt:       time.Now().UTC(),
		Predicate:      predicate,
		AnswerWithinMs: answerWindowMs(kind, expected),
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	aq := &activeQuery{
		ID:        env.QueryID,
		Expected:  expected,
		IssuedAt:  env.IssuedAt,
		responded: make(map[string]bool),
		hub:       newHub(),
	}
	qm.mu.Lock()
	qm.active[aq.ID] = aq
	qm.mu.Unlock()

	if err := qm.nc.Publish(targetSubject, payload); err != nil {
		qm.mu.Lock()
		delete(qm.active, aq.ID)
		qm.mu.Unlock()
		return nil, err
	}

	time.AfterFunc(queryExpiry, func() {
		qm.mu.Lock()
		delete(qm.active, aq.ID)
		qm.mu.Unlock()
	})

	return aq, nil
}

// answerWindowMs is how long agents should spread their answers over, from
// how many are expected and roughly how large one answer of this kind is.
//
// The broker cuts a client whose unread data passes 64 MB (max_pending),
// and a fleet answering at once delivers everything within a second: in a
// load test 5,000 endpoints' processes (~28 KB each), services and
// installed apps all lost most of their answers that way, and with the
// answers spread over five seconds every one arrived. The budget is a
// conservative read rate for the control plane; a fleet whose answers fit
// in a quarter of a second answers at once, as before.
func answerWindowMs(kind proto.QueryKind, expected int) int {
	const (
		budgetBytesPerSec = 32 << 20
		minWindow         = 250 * time.Millisecond
		maxWindow         = 15 * time.Second
	)
	size := map[proto.QueryKind]int{
		proto.QueryKindFacts:         1 << 10,
		proto.QueryKindPatches:       4 << 10,
		proto.QueryKindServices:      24 << 10,
		proto.QueryKindProcesses:     32 << 10,
		proto.QueryKindInstalledApps: 72 << 10,
	}[kind]
	if size == 0 {
		size = 32 << 10
	}
	window := time.Duration(float64(expected) * float64(size) / budgetBytesPerSec * float64(time.Second))
	if window < minWindow {
		return 0
	}
	return int(min(window, maxWindow) / time.Millisecond)
}

// Get returns the active query by ID, if it exists and hasn't expired.
func (qm *queryManager) Get(id string) (*activeQuery, bool) {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	aq, ok := qm.active[id]
	return aq, ok
}

// subscribeResults opens the single, long-lived subscription that collects
// results for every in-flight query, demultiplexed by QueryResult.QueryID.
// One subscription for all queries — not one per query — so query volume
// doesn't multiply subscription count.
// attributeQueryResult sets result.AgentID to the identity the result may
// be attributed to, and reports whether to accept it. An enrolled agent
// answers on beacon.r.<query>.<its id>, which only it may publish, so the
// subject names the sender. The legacy subject names nobody and the body's
// agent_id is whatever a shared-credential holder typed; it is accepted
// only while legacy is allowed, and never when it claims an identity that
// has enrolled (that agent answers on its own subject, so this is a
// forgery).
func (s *Server) attributeQueryResult(ctx context.Context, subject string, result *proto.QueryResult) bool {
	if id, ok := bnats.ResultAgentFromSubject(subject); ok {
		result.AgentID = id
		return true
	}
	if !s.legacySubjectsAccepted(ctx) {
		return false
	}
	if bnats.ValidAgentID(result.AgentID) {
		enrolled, err := s.store.AgentHasCredential(ctx, result.AgentID)
		if err != nil {
			s.logger.Warn("credential lookup failed; dropping legacy query result", "agent_id", result.AgentID, "error", err)
			return false
		}
		if enrolled {
			s.logger.Warn("dropping a legacy query result that claims an enrolled identity", "agent_id", result.AgentID)
			return false
		}
	}
	return true
}

func (s *Server) subscribeResults(ctx context.Context) (*gonats.Subscription, error) {
	conn := s.resultsNC
	if conn == nil {
		conn = s.nc
	}
	sub, err := conn.Subscribe(bnats.ResultWildcard(), func(msg *gonats.Msg) {
		var result proto.QueryResult
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			s.logger.Warn("discarding malformed query result", "error", err)
			return
		}
		if !s.attributeQueryResult(ctx, msg.Subject, &result) {
			return
		}
		aq, ok := s.queryMgr.Get(result.QueryID)
		if !ok {
			return // query already expired or unknown; drop
		}

		aq.mu.Lock()
		if aq.responded[result.AgentID] {
			aq.mu.Unlock()
			return // duplicate response (e.g. agent retried); ignore
		}
		aq.responded[result.AgentID] = true
		aq.results = append(aq.results, result)
		aq.mu.Unlock()

		// A notification, not the snapshot: encoding every result so far
		// on every arrival is O(fleet²) bytes per query — tens of
		// gigabytes for a processes query across two thousand endpoints —
		// on the one goroutine that is receiving the results. Each stream
		// encodes the current snapshot itself, at a bounded rate
		// (handleQueryStream).
		aq.hub.Publish(nil)
	})
	if err != nil {
		return nil, err
	}
	// Room for a whole fleet's answers to one query (nats.go's default is
	// 64 MB), so a burst queues here rather than being dropped while the
	// handler decodes it.
	if err := sub.SetPendingLimits(-1, resultsPendingBytes); err != nil {
		return nil, err
	}
	return sub, nil
}

// resultsPendingBytes bounds the live-query answers buffered unread: 5,000
// endpoints' installed-apps lists at ~70 KB each.
const resultsPendingBytes = 512 << 20
