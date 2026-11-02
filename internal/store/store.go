// Package store is the server's Postgres access layer: current-state agent
// inventory. Historical time series (heartbeat/facts history) belongs in
// VictoriaMetrics, not here — see docs/ARCHITECTURE.md.
//
// Uses pgx directly (no ORM, no sqlc codegen step) since Slice 1 has exactly
// one table and a handful of queries; sqlc is worth adopting once the
// query surface grows enough that keeping SQL and Go in sync by hand gets
// error-prone.
package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mustra-dev/mustra/internal/proto"
)

//go:embed schema.sql
var schemaSQL string

// Store wraps a Postgres connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// defaultMaxConns is the pool size when the DSN does not choose one
// (pool_max_conns). pgxpool's own default is the number of CPUs, minimum
// four — on a small control-plane host, four connections shared by seven
// JetStream consumers, the auth callout, registration and the console. In
// a reconnect storm of 2,000 agents 13 of the 16 callout workers sat
// waiting for one, and the broker refused the connections they were
// deciding. Postgres allows 100 connections by default.
const defaultMaxConns = 16

// poolConfig parses dsn, raising the pool size to defaultMaxConns unless
// the DSN sets it.
func poolConfig(dsn string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(dsn, "pool_max_conns") && cfg.MaxConns < defaultMaxConns {
		cfg.MaxConns = defaultMaxConns
	}
	return cfg, nil
}

// Open connects to Postgres at dsn and applies the schema (idempotent).
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := poolConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if err := applySchema(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{pool: pool}, nil
}

// schemaLockKey is the advisory lock that serializes schema application.
// Two processes opening the same database at once (a server and the
// console binary, two replicas, parallel test packages) otherwise ran the
// migrations concurrently and could deadlock on their ALTERs.
const schemaLockKey = 0x6d757374 // "must"

func applySchema(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, schemaLockKey); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, schemaLockKey)
	}()
	_, err = conn.Exec(ctx, schemaSQL)
	return err
}

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// Ping reports whether Postgres is answering. Used by /healthz: a server
// process that is up but cannot reach its database is not serving, and a
// container healthcheck that only proves the port is open would say it is.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// AgentRecord is the persisted, current-state view of one agent. Online is
// computed at query time from LastHeartbeat, not stored.
type AgentRecord struct {
	AgentID         string     `json:"agent_id"`
	Hostname        string     `json:"hostname"`
	OS              string     `json:"os"`
	Arch            string     `json:"arch"`
	Site            string     `json:"site"`
	AgentVersion    string     `json:"agent_version"`
	Platform        string     `json:"platform"`
	PlatformVersion string     `json:"platform_version"`
	KernelVersion   string     `json:"kernel_version"`
	CPUCount        int        `json:"cpu_count"`
	MemTotalMB      int64      `json:"mem_total_mb"`
	IPs             []string   `json:"ips"`
	FirstSeen       time.Time  `json:"first_seen"`
	LastHeartbeat   *time.Time `json:"last_heartbeat"`
	LastFacts       *time.Time `json:"last_facts"`
	Online          bool       `json:"online"`
	// Settings is what the agent last reported it runs with (facts).
	Settings json.RawMessage `json:"settings,omitempty"`
	// WatchRevision is the integrity watch set the agent reports running.
	WatchRevision string `json:"watch_revision,omitempty"`
	// Managed is false for an endpoint that has been quiet long enough to
	// be retired. Its row and history stay; it simply is not part of the
	// fleet any operation acts on until it comes back.
	Managed       bool       `json:"managed"`
	RetiredAt     *time.Time `json:"retired_at,omitempty"`
	RetiredReason string     `json:"retired_reason,omitempty"`
	// Attributes are the operator-maintained fields for this endpoint,
	// keyed by attribute name. Filled by callers that ask for them.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// UpsertOnRegister records or reconfirms an agent's identity. Called
// synchronously while handling a registration request, so the row exists
// before any heartbeat or facts message for this agent can arrive.
func (s *Store) UpsertOnRegister(ctx context.Context, agentID string, info proto.AgentInfo) error {
	const q = `
INSERT INTO agents (agent_id, hostname, os, arch, site, agent_version, first_seen, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, now(), now())
ON CONFLICT (agent_id) DO UPDATE SET
    hostname = EXCLUDED.hostname,
    os = EXCLUDED.os,
    arch = EXCLUDED.arch,
    site = EXCLUDED.site,
    agent_version = EXCLUDED.agent_version,
    managed = true,
    retired_at = NULL,
    retired_reason = '',
    updated_at = now()`
	_, err := s.pool.Exec(ctx, q, agentID, info.Hostname, info.OS, info.Arch, info.Site, info.Version)
	if err != nil {
		return fmt.Errorf("upsert agent on register: %w", err)
	}
	return nil
}

// RecordHeartbeat updates last_heartbeat for an agent.
// ErrUnknownAgent is returned when a message arrives for an agent with no
// row. It is a sentinel rather than a string because the caller's right
// response is to discard quietly and wait: a heartbeat carries only an ID
// and a time, which is not enough to describe an endpoint, but the same
// agent's next facts publish is — and that one heals the row. Retrying the
// heartbeat in the meantime just prints the same warning every two seconds.
// SetCriticality returns it too, so the API can answer 404 rather than 500.
var ErrUnknownAgent = errors.New("no such agent")

func (s *Store) RecordHeartbeat(ctx context.Context, agentID string, at time.Time) error {
	// An endpoint that is talking to us is managed, whatever the retirement
	// sweeper decided while it was quiet — being here is the evidence.
	const q = `UPDATE agents SET last_heartbeat = $2, updated_at = now(),
	    managed = true, retired_at = NULL, retired_reason = ''
	    WHERE agent_id = $1`
	tag, err := s.pool.Exec(ctx, q, agentID, at)
	if err != nil {
		return fmt.Errorf("record heartbeat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("heartbeat for %q: %w", agentID, ErrUnknownAgent)
	}
	return nil
}

// RecordFacts stores an agent's self-description, re-creating its row if it
// is gone.
//
// It used to be a plain UPDATE, which meant an endpoint that had been
// offline long enough for offlineExpiryLoop to drop it could never come
// back: registration happens once, at first start, so a returning agent
// keeps publishing heartbeats and facts against a row that no longer
// exists, every one of them failing, forever. The machine is up, reachable
// and talking, and invisible. That is the worst possible shape for an
// inventory bug — it looks like an endpoint that is simply gone.
//
// The upsert is not a widening of the trust boundary. Facts arrive on a
// subject any holder of the agent credential can already publish to (see
// the wildcard note in deploy/nats/nats.conf), and that same credential can
// re-enrol through beacon.register. This changes how a returning endpoint
// heals, not who may claim to be one.
func (s *Store) RecordFacts(ctx context.Context, facts proto.Facts) error {
	const q = `
INSERT INTO agents (agent_id, hostname, os, arch, site, agent_version, platform,
                    platform_version, kernel_version, cpu_count, mem_total_mb, ips, last_facts, settings, watch_revision)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (agent_id) DO UPDATE SET
    hostname = $2,
    os = $3,
    arch = $4,
    site = $5,
    agent_version = $6,
    platform = $7,
    platform_version = $8,
    kernel_version = $9,
    cpu_count = $10,
    mem_total_mb = $11,
    ips = $12,
    last_facts = $13,
    settings = $14,
    watch_revision = $15,
    managed = true,
    retired_at = NULL,
    retired_reason = '',
    updated_at = now()`
	// A nil slice reaches Postgres as NULL, and ips is NOT NULL — so an
	// agent that reports no addresses (an interface enumeration that came
	// back empty, a host with only loopback) failed this write forever on
	// redelivery rather than simply recording "no addresses".
	ips := facts.IPs
	if ips == nil {
		ips = []string{}
	}
	settings := []byte("{}")
	if facts.Settings != nil {
		if b, err := json.Marshal(facts.Settings); err == nil {
			settings = b
		}
	}
	tag, err := s.pool.Exec(ctx, q,
		facts.AgentID, facts.Hostname, facts.OS, facts.Arch, facts.Site, facts.AgentVer,
		facts.Platform, facts.PlatformVer, facts.KernelVer, facts.CPUCount, int64(facts.MemTotalMB),
		ips, facts.Timestamp, settings, facts.WatchRevision,
	)
	if err != nil {
		return fmt.Errorf("record facts: %w", err)
	}
	_ = tag
	// Only an agent that reports its zone changes it: an older agent's
	// facts leave what is stored (nothing, usually) alone.
	if facts.Timezone != "" || facts.UTCOffsetSeconds != nil {
		if _, err := s.pool.Exec(ctx, `UPDATE agents SET timezone = $2, utc_offset_seconds = $3 WHERE agent_id = $1`,
			facts.AgentID, facts.Timezone, facts.UTCOffsetSeconds); err != nil {
			return fmt.Errorf("record agent time zone: %w", err)
		}
	}
	return nil
}

// AgentZone is an endpoint's time zone as its agent reported it.
type AgentZone struct {
	OS               string
	Timezone         string // IANA name, or "" when the agent could not tell
	UTCOffsetSeconds *int   // nil until a reporting agent
}

// AgentZones returns every agent's OS and reported time zone, for
// maintenance windows that are evaluated per endpoint.
func (s *Store) AgentZones(ctx context.Context) (map[string]AgentZone, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, os, timezone, utc_offset_seconds FROM agents`)
	if err != nil {
		return nil, fmt.Errorf("agent zones: %w", err)
	}
	defer rows.Close()
	out := map[string]AgentZone{}
	for rows.Next() {
		var id string
		var z AgentZone
		if err := rows.Scan(&id, &z.OS, &z.Timezone, &z.UTCOffsetSeconds); err != nil {
			return nil, err
		}
		out[id] = z
	}
	return out, rows.Err()
}

// ListAgents returns every agent, newest-hostname-first is not guaranteed —
// callers needing an order should sort. Online is computed as
// last_heartbeat within staleAfter of now.
func (s *Store) ListAgents(ctx context.Context, staleAfter time.Duration) ([]AgentRecord, error) {
	const q = `
SELECT agent_id, hostname, os, arch, site, agent_version, platform, platform_version,
       kernel_version, cpu_count, mem_total_mb, ips, first_seen, last_heartbeat, last_facts, settings, watch_revision,
       managed, retired_at, retired_reason
FROM agents
ORDER BY hostname`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	now := time.Now()
	var out []AgentRecord
	for rows.Next() {
		var r AgentRecord
		var settings []byte
		if err := rows.Scan(
			&r.AgentID, &r.Hostname, &r.OS, &r.Arch, &r.Site, &r.AgentVersion, &r.Platform, &r.PlatformVersion,
			&r.KernelVersion, &r.CPUCount, &r.MemTotalMB, &r.IPs, &r.FirstSeen, &r.LastHeartbeat, &r.LastFacts, &settings, &r.WatchRevision,
			&r.Managed, &r.RetiredAt, &r.RetiredReason,
		); err != nil {
			return nil, fmt.Errorf("scan agent row: %w", err)
		}
		if len(settings) > 2 {
			r.Settings = json.RawMessage(settings)
		}
		r.Online = r.Managed && r.LastHeartbeat != nil && now.Sub(*r.LastHeartbeat) < staleAfter
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAgentPlatformSite returns just the two fields ResolvePatchListForAgent
// needs to match targeting rules — cheaper than ListAgents' full scan when
// all a caller wants is one agent's platform/site.
func (s *Store) GetAgentPlatformSite(ctx context.Context, agentID string) (platform, site string, err error) {
	err = s.pool.QueryRow(ctx, `SELECT platform, site FROM agents WHERE agent_id = $1`, agentID).Scan(&platform, &site)
	if err != nil {
		return "", "", fmt.Errorf("get agent platform/site: %w", err)
	}
	return platform, site, nil
}

// GetAgentOSArch returns one agent's OS and architecture, or empty strings
// (and no error) when there is no such agent. For per-agent request paths
// that ListAgents would turn into a whole-table read per request.
func (s *Store) GetAgentOSArch(ctx context.Context, agentID string) (osName, arch string, err error) {
	err = s.pool.QueryRow(ctx, `SELECT os, arch FROM agents WHERE agent_id = $1`, agentID).Scan(&osName, &arch)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("get agent os/arch: %w", err)
	}
	return osName, arch, nil
}

// GetAgentHostname returns one agent's hostname, or "" (and no error) when
// there is no such agent.
func (s *Store) GetAgentHostname(ctx context.Context, agentID string) (string, error) {
	var h string
	err := s.pool.QueryRow(ctx, `SELECT hostname FROM agents WHERE agent_id = $1`, agentID).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get agent hostname: %w", err)
	}
	return h, nil
}

// DeleteAgent removes one endpoint from inventory, cascading to its sensor
// data exactly as expiry does.
//
// It exists because uninstalling the agent does not remove the row: the
// endpoint simply stops reporting and sits there until offline expiry, and a
// machine that is reinstalled registers fresh — so the console shows the same
// hostname twice, once dead and once alive. The operator needs to be able to
// say "this one is gone" without waiting an hour.
func (s *Store) DeleteAgent(ctx context.Context, agentID string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM agents WHERE agent_id = $1`, agentID); err != nil {
		return fmt.Errorf("delete agent: %w", err)
	}
	return nil
}

// Deleting an endpoint because it went quiet was how this used to work.
// It is gone on purpose: see RetireOfflineAgents in assets.go, which keeps
// the row and its history and only clears `managed`. The one path that
// still destroys inventory is PurgeRetiredAgents, which is off by default
// and acts on how long something has been *retired*, not offline.

// QueryRowInt runs a query returning a single integer. A convenience for
// the handful of places that want one count and nothing else.
func (s *Store) QueryRowInt(ctx context.Context, q string, out *int) error {
	return s.pool.QueryRow(ctx, q).Scan(out)
}
