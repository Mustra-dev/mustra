# Architecture

mustra is an open-source fleet management / endpoint operations platform: a
lightweight agent on every device reports facts and metrics, answers live
queries in near-real-time, deploys packages and enforces desired state. A central control plane ("the datacenter") monitors and controls
everything through NATS, with no inbound ports on any endpoint.

This document explains how it is built and the reasoning behind the design
decisions. It grew alongside the code, so some sections describe the first
vertical slice and say so; [CONCEPTS.md](CONCEPTS.md) describes current
product behavior, and the code is the final word. See
[ROADMAP.md](ROADMAP.md) for what is still deferred.

## Components

```
                    ┌──────────────┐
   endpoints  ───▶  │     NATS     │  ◀───  server (control plane)
  (agents,           │  (JetStream, │         │
   outbound only)    │   TLS+auth)  │         ├─▶ Postgres (all control-plane state)
                    └──────────────┘         └─▶ named volumes (package payloads, output)
                                                    │
                                               HTTP/SSE API
                                                    │
                                              console (web UI)
```

- **Agent** (`cmd/agent`, `internal/agent`): connects outbound to NATS,
  registers, heartbeats, publishes facts, answers live queries. Buffers to a
  local bbolt file when NATS is unreachable.
- **Server** (`cmd/server`, `internal/server`): consumes registration/
  heartbeat/facts off NATS, persists current-state inventory to Postgres,
  dispatches live queries and collects results, serves an HTTP+SSE API.
- **Console**: the web UI, embedded in and served by the server process
  (`internal/server/static`). `cmd/console` starts the same server package
  — see the "console/server split" tradeoff below.
- **NATS + JetStream**: the message backbone. Core NATS pub/sub for
  ephemeral traffic (queries, results, registration request/reply);
  JetStream for anything that must survive a control-plane outage
  (heartbeats, facts).

## NATS subject scheme

All subject strings are built in `internal/nats` — nothing else in the
codebase hand-builds one. This is the addressing system the whole platform
is organized around:

| Subject | Direction | Transport |
|---|---|---|
| `beacon.register` | agent → server | core NATS, request/reply |
| `beacon.agent.<id>.heartbeat` | agent → server | JetStream |
| `beacon.agent.<id>.facts` | agent → server | JetStream |
| `beacon.q.all` / `.os.<os>` / `.site.<site>` / `.agent.<id>` | server → agents | core NATS, fan-out |
| `beacon.r.<query_id>` | agent → server | core NATS |
| `beacon.cmd.<id>` | server → agent | core NATS, request/reply |

The table lists the founding subjects; `internal/nats` has the full set,
and `deploy/nats/nats.conf` grants each role only the subjects it needs.

**Why `beacon.*`?** The project was called beacon before it was renamed
mustra. Subjects (and the `BEACON_*` JetStream stream names) are a deployed
wire protocol: every running agent publishes and subscribes on them, and
agents and servers upgrade independently. Renaming them would need a
transition in which servers speak both namespaces until no agent uses the
old one, with matching broker permissions, for no functional gain. So the
prefix stays. The same reason keeps the `BEACON_*` environment-variable
fallbacks working where the entrypoints support them.

The `beacon.q.*` subjects let a publisher hit a slice of the fleet without
the server resolving a target list — each agent subscribes to the subjects
that match its own identity (all, its OS, its site, itself). An optional
`Predicate` inside the `QueryEnvelope` lets a query narrow further (e.g.
"windows agents at site X") without needing a new coarse subject for every
possible combination; agents evaluate it locally and simply don't respond
if it doesn't match.

Query results all land on `beacon.r.*`. The server opens **one** long-lived
subscription on that wildcard at startup and demultiplexes by
`QueryResult.QueryID`, rather than subscribing per query — subscription
count doesn't grow with query volume.

## Agent design

Startup sequence: open bbolt store → connect NATS (infinite reconnect) →
register (retry with backoff until it succeeds — the server or NATS may not
be up yet) → subscribe to query subjects → start heartbeat/facts/flush
loops.

**Identity** is a single bbolt key (`meta/agent_id`). On registration the
agent sends whatever ID it has (empty on first run); the server either
mints a new one or reconfirms the existing one, and the agent persists
whatever comes back. This means an agent's identity survives process
restarts and even a full reinstall as long as the data directory survives.

**Store-and-forward**: `internal/agent/publisher.go` wraps JetStream
publish with a bbolt-backed outbox. `Publish` tries a direct JetStream
publish (which waits for a server ack) if connected; on any failure —
including "not connected" — it enqueues to bbolt instead of returning an
error, since buffering is the expected path during an outage, not an
exceptional one. A background loop (5s tick) drains the outbox **in FIFO
order**, stopping at the first failed publish within a tick so a partial
flush can never reorder messages — it just retries from where it stopped on
the next tick. Verified end-to-end during development: killing NATS for
~24s buffered 11 heartbeats + 4 facts messages, and every one was flushed
in order within one tick of reconnecting.

Live queries are **not** buffered — a query that arrives while an agent is
offline is answered by nobody, which is exactly what "responded 3/5" should
show. Buffering a stale answer to an expired query would be actively
misleading.

**Facts** collection is deliberately narrow (gopsutil's `host`, `cpu`, `mem`
packages plus stdlib `net` for IP addresses — gopsutil's `net` package
targets IO counters, not addressing, so pulling in more of it for this
would cost footprint for nothing gained).

Footprint: a static cross-compiled binary is ~9-10MB (gopsutil + nats.go +
bbolt). No goroutine leaks — every background loop takes a `context.Context`
and exits on cancellation. Facts are polled on a slow timer (default 60s),
not continuously.

## Server design

**Durability**: heartbeat and facts consumption uses durable JetStream
consumers (`server-heartbeat`, `server-facts`), not ephemeral — a server
restart resumes from where it left off rather than silently skipping
messages that arrived while it was down. The stream itself
(`BEACON_AGENTS`, subjects `beacon.agent.*.>`) uses `LimitsPolicy` retention
with a 24h `MaxAge` rather than `WorkQueue` retention: limits-based
retention lets multiple independent consumers read the same messages (the
staleness tracker today, a metrics writer later) without one consumer's ack
deleting a message another still needs.

**Staleness is computed at read time**, not written: `ListAgents` compares
`last_heartbeat` against a threshold (`StaleAfter`, default 30s — a small
multiple of the agent's heartbeat interval) on every query, rather than
running a job that flips a stored `online` flag. This avoids write
amplification for something that's cheap to compute on read. The one thing
this can't do on its own is *notify* viewers when an agent goes silent,
since "no new heartbeat arrived" isn't an event — that's what the 5-second
staleness sweep loop is for for (`stalenessSweepLoop` in `server.go`): it
periodically re-broadcasts the current agent list to SSE subscribers so an
agent that stops heartbeating flips to "offline" in the console within a
few seconds, not just the next time something else happens to change.

**Long-offline agents are deleted, not just marked offline.** A separate
`offlineExpiryLoop` (`server.go`, every 5 minutes) removes any agent whose
`last_heartbeat` — or `first_seen`, if it registered but never got that
far — is older than `OfflineExpiry` (default 1h). This is a deliberate
choice for a fleet tool: a box that's been gone for an hour is far more
often decommissioned, reimaged, or a one-off VM than genuinely "still ours
but napping," and letting dead entries accumulate forever makes the
endpoint list actively misleading. `ON DELETE CASCADE` on
`agent_sensor_data` keeps that cleanup a single query. Re-registering is
always safe and instant — the agent just reappears as a fresh row, same as
its very first connection — so there's no real cost to expiring
aggressively versus keeping stale rows around "just in case."

**SSE updates are full snapshots, not deltas.** Every broadcast (agent
list or query results) sends the complete current state; the browser
just replaces its table. This is the simplest thing that's correct, and at
small-to-low-thousands scale a full agent list is a few KB — cheap to
resend on every heartbeat. It will not scale cleanly to tens of thousands
of agents; see ROADMAP.md.

**Inventory is current state.** The `agents` row and the sensor cache hold
what is true now, not a time series. History that the product needs is
kept in purpose-built tables instead (agent version history, file and
process events, integrity changes, audit events, question history). There
is no separate metrics store: an early plan for VictoriaMetrics was never
wired up (see "Data store choices" below).

**Bus authentication.** The first slice ran NATS with no authentication.
That is no longer the case: the shipped broker configuration
(`deploy/nats/nats.conf`) requires TLS and a credential on every
connection, and separates a server role (which alone may publish commands
and queries) from an agent role (which may only report and receive work).
Agents verify the broker against the CA `deploy/nats/gen-certs.sh`
generates. How agents are credentialed, and what one agent's credential
lets it do, is described in `nats.conf` and [SECURITY.md](../SECURITY.md);
the latter is the threat model this design is held to. The console has its
own authentication — see below.

## Console authentication

The console's HTTP/SSE API is fully gated behind a session cookie
(`internal/server/auth`); every route except the login flow and `/scim/v2/*`
goes through `Auth.RequireAuth`. Three ways in:

1. **OIDC SSO** against any standards-compliant IdP (built and wired against
   Authentik, but nothing in `internal/server/auth/oidc.go` is
   Authentik-specific — it's generic discovery + authorization-code-flow via
   `coreos/go-oidc` and `golang.org/x/oauth2`). A successful login upserts a
   `users` row keyed on the IdP's `sub` claim (not email or username, since
   either can change at the IdP) and issues a session.
2. **Local break-glass account.** A single username/password pair, configured
   via `MUSTRA_BREAKGLASS_USERNAME`/`MUSTRA_BREAKGLASS_PASSWORD` (or
   `MUSTRA_BREAKGLASS_PASSWORD_FILE`; the older `MUSTRA_BACKDOOR_*` and
   `BEACON_BACKDOOR_*` names are still read, with a deprecation warning) and re-synced
   (bcrypt-hashed) to Postgres on every server startup. This is a
   deliberately separate code path from OIDC — `HandleLocalLogin` never
   touches the IdP — so it keeps working when Authentik is down, misconfigured,
   or simply hasn't finished OIDC discovery yet. That last case matters: OIDC
   discovery happens in a background retry loop (`discoverOIDCWithRetry`) so
   a slow or temporarily-unreachable IdP never blocks server startup or takes
   down the break-glass login with it — the console just shows "SSO unavailable"
   until discovery succeeds.
3. **SCIM-provisioned identities** (below) can also log in locally if a
   password is set for them, but SCIM as implemented here only ever sets
   `source='scim'` with no password — provisioned users are expected to
   authenticate via SSO. (Nothing stops a future admin action from setting
   one; the schema doesn't forbid it.)

Sessions are server-side rows in Postgres (`sessions` table), not JWTs — the
cookie carries only an opaque 32-byte token. That makes revocation trivial
(delete the row) at the cost of a DB lookup per authenticated request, which
is a fine trade at this scale and keeps logout actually mean something
instead of "wait for expiry."

## SCIM provisioning

`internal/server/scim` implements enough of SCIM 2.0 (RFC 7643/7644) for an
IdP's outbound SCIM provider — built and tested against Authentik's, but
protocol-generic — to provision console users and groups: discovery
endpoints (`ServiceProviderConfig`, `ResourceTypes`, `Schemas`), and full
CRUD + a minimal PATCH on `/scim/v2/Users` and `/scim/v2/Groups`. Auth is a
single static bearer token (`MUSTRA_SCIM_TOKEN`), checked with
`crypto/subtle.ConstantTimeCompare` — simpler than per-client OAuth2 client
credentials, and appropriate since there's exactly one SCIM client (the IdP)
per deployment.

Deliberately **not** RFC-complete: the SCIM filter grammar (only
`attr eq "value"` is parsed — the one shape provisioning clients actually
send to check "does this already exist" before creating) and the PATCH
path-expression grammar (only `active`, `displayName`, and `members` /
`members[value eq "id"]` are handled — again, the shapes real clients send).
An unrecognized PATCH op is logged and skipped rather than failing the
whole request, so one op provisioning software doesn't understand about
this server can't fail an entire sync that also carries ops it does
understand. See ROADMAP.md for filling out the rest of the grammar if a
different IdP needs it.

SCIM-provisioned groups take part in authorization: a role can be assigned
to a group, and members get that role's permissions (see "RBAC" below).

## Public exposure

A public hostname of your choosing reaches the console through a dedicated
Cloudflare Tunnel (`cloudflared`, container in the compose stack) rather
than a host port opened to the internet — consistent with the "agents never
accept inbound connections" principle applied to the console too.
`deploy/cloudflared/config.yml` is a template: the operator creates their
own tunnel with `cloudflared tunnel create` and fills in its ID and
hostname (deploy/README.md). Because
`cloudflared` terminates TLS at Cloudflare's edge and forwards to the
`server` container over plain HTTP inside the compose network, the *browser*
sees HTTPS (so `CookieSecure` session cookies work correctly) even though
the origin-to-container hop is not itself encrypted — that hop never leaves
the docker-compose bridge network, so this is the same trust boundary any
tunnel-fronted service on a single host relies on.

## Sensors: on-demand vs. auto-refreshing

Facts (hostname/OS/IPs/etc.) drive core inventory columns and have their
own dedicated flow — `internal/agent/facts.go`, the `AgentFacts` subject,
`RecordFacts`. Everything added after Slice 1 (processes, services,
installed apps) goes through a second, more general mechanism instead of
growing that same path three more times:

- **`QueryKind`** (`internal/proto`) is "ask every matching agent right
  now, once" — the live-query mechanism from Slice 1, just no longer
  hardcoded to facts. `POST /api/query` takes a `kind` field
  (`internal/server/httpapi.go`); the agent's `handleQuery` switches on it
  (`internal/agent/query.go`).
- **`SensorKind`** is "keep this agent's cached answer fresh." Each agent
  runs one `runSensorLoop` goroutine per sensor (`internal/agent/
  sensor_loop.go`), publishing a `SensorSnapshot` to
  `beacon.agent.<id>.sensor.<kind>` on a timer — 15 minutes by default,
  a periodic-refresh model. The server's `consumeSensors`
  durable consumer upserts each snapshot into `agent_sensor_data` (one row
  per agent+sensor, JSONB payload, no history — a snapshot table, not a
  time series). `GET /api/agents/{id}/sensor/{kind}` serves the cached
  value with no live round-trip.
- **The interval is adjustable at runtime, not just at startup.** Each
  sensor loop holds a `chan time.Duration`; `beacon.cmd.<id>` (reserved
  since Slice 1, now used for the first time) carries a
  `set_sensor_interval` command that the agent applies via
  `time.Ticker.Reset` — no restart, no reconnect. A one-time immediate
  refresh doesn't need any of this machinery — it's just a live query.

Collecting processes is genuinely cross-platform via gopsutil's `process`
package. Services and installed-apps are not — there's no single library
that covers systemd, launchd, and the Windows SCM/registry, so
`internal/agent/sensors.go` shells out to each platform's native inventory
command (`systemctl list-units`, `launchctl list`, PowerShell's
`Get-Service`/registry `Uninstall` key enumeration) rather than pulling in
three more dependencies for something this footprint-sensitive.

## Agent deployment

The console's `/agents` page and the `install.sh`/`install.ps1` routes
(`internal/server/deploy.go`) all funnel through the same install-script
templates, so "copy-paste a one-liner" and "click Deploy after a network
scan" are the same code path, not two implementations to keep in sync.
Cross-compiled agent binaries for every supported OS/arch are built once at
Docker image build time (`deploy/Dockerfile.server`'s `agents` stage) and
served unauthenticated at `/downloads/` — a `curl`/`irm` one-liner carries
no browser session cookie to send, and the binaries themselves have no
secrets baked in (NATS URL and site are runtime flags).

**Network-scan-and-push** (`internal/server/netscan.go`,
`internal/server/sshdeploy.go`) is explicit and opt-in — a human submits
one CIDR at a time; nothing scans automatically. Discovered hosts get the
install script pushed over SSH directly (`golang.org/x/crypto/ssh`), OS
detected via a `uname -s` probe (falls back to assuming Windows, since
OpenSSH Server on Windows defaults to `cmd.exe`, not bash) — same
`install.sh`/`install.ps1` templates, piped over stdin for the POSIX case
and passed via PowerShell's `-EncodedCommand` for Windows (avoids the shell
-escaping mess of trying to pipe a script containing quotes through an SSH
exec string). One bug this surfaced during testing and fixed: re-installing
over an already-running agent failed with `ETXTBSY` — you can't
truncate+write a binary a running process is currently mapped from — fixed
by stopping the service before overwriting the file rather than after.

**Credentials are a dedicated encrypted vault**, not passed through the UI
each time (the user's explicit choice over a one-time-paste flow) —
`internal/server/vault`, AES-256-GCM, key from
`MUSTRA_CREDENTIAL_ENCRYPTION_KEY`. Plaintext exists only transiently,
decrypted immediately before an SSH connection attempt and never logged,
cached, or returned by any API once stored — `GetDeployCredentialCipher`
is the only store method that can retrieve a secret, and only the vault
package calls it. Host keys are **not** verified
(`ssh.InsecureIgnoreHostKey()`) — a deliberate simplification for a tool
scanning your own LAN, not a general-purpose SSH client; see ROADMAP.md for
trust-on-first-use pinning if that tradeoff ever needs revisiting.

## RBAC: roles, permissions, admin settings

A fixed, code-defined set of permission keys
(`internal/server/auth/permissions.go`, the authoritative list; it has
grown since this section was written) gates everything with real blast
radius. The original four were `settings.manage` (the Settings
tab, including SSO), `users.manage` (the Admin tab), `patches.manage`
(applying patches), `deploy.manage` (the credential vault, network scan,
and SSH push). Everything else an authenticated user can reach — the
endpoint list, live queries, cached sensor reads — stays ungated; the
fleet-visibility half of the product is deliberately not something you'd
need to provision per-user in a small deployment. Permissions themselves are **not**
an admin-manageable resource, only roles are: a role is a name plus a
subset of that fixed list, assignable to a user directly or to a group
(`user_roles`/`group_roles`, unioned in `Store.EffectivePermissions`). This
is the opposite of a fully generic permissions system on purpose — adding a
new gated feature later means adding one Go constant, not a database
migration to a permissions table, and there's no way to "create" a
permission that doesn't correspond to a real check somewhere in the code.
Two roles are builtin (`is_builtin`, undeletable/unrenamable): "admin"
(reseeded to the complete permission set on every startup, so it can't be
crippled by an accidental edit — not that edits are allowed at all, the API
rejects any change to a builtin role) and "user" (seeded once with zero
permissions, left alone after that so an admin's customization sticks).

The legacy `users.is_admin` boolean (predates this table, was the break-glass
account's only privilege flag) survives as a fast-path super-admin switch
independent of role assignment — `Auth.HasPermission` checks it first
before ever querying roles. **Migration note:** before this feature
shipped, nothing was gated — every authenticated user already had full
access to deploy/credentials/etc. Introducing permissions and defaulting
new accounts to zero access would have silently locked out every existing
SCIM/OIDC user the moment the server restarted. `Store.GrandfatherAllUsersAdminOnce`
runs exactly once (tracked by a settings-table sentinel) on the first boot
that has RBAC at all: every existing user is flipped to `is_admin`,
matching the access they already had, and only accounts created after that
point start with nothing. An admin can freely revoke it afterward from the
Users tab.

**Settings are Postgres-backed and live-editable**, not just env vars
(`internal/server/settings.go`, the `settings` table). On a from-scratch
deploy, `seedAndLoadSettings` copies the env/flag-derived values in once
(`SetSettingIfAbsent` — never overwrites); from then on Postgres is
authoritative and env vars only matter if the database is ever wiped. The
harder part is that some of these settings back live subsystems that don't
normally expect to be reconfigured after `Run` starts:
- `auth.Auth` gained a `sync.RWMutex` plus a discovery-generation counter
  (`atomic.Uint64`) so `SetOIDCConfig` can clear the currently-discovered
  OIDC provider and kick off fresh discovery against a new issuer without a
  restart, while a stale discovery goroutine from before the change (still
  retrying against the old issuer) detects it's been superseded and exits
  quietly instead of racing the new one to set the fields last.
- `scim.Server.token` gained the same mutex-guarded pattern (`SetToken`).
- `StaleAfter`/`OfflineExpiry`/`AgentNATSURL` live in a small
  `liveConfig` struct on `Server` (its own `sync.RWMutex`) rather than
  mutating `Config` in place, since `Config` is otherwise treated as
  immutable-after-`Run` everywhere else in the codebase and blurring that
  for three fields felt like the wrong precedent to set.
- The break-glass password is never round-tripped as plaintext once set —
  only its bcrypt hash lives in `settings`, so a settings-page reload
  always shows the password field blank ("leave blank to keep unchanged")
  by construction, not by convention.

## Patches: a narrow, non-arbitrary command, not a query

Available-updates is a sensor like processes/services/installed_apps
(`SensorPatches`, `internal/agent/patches.go`) — apt/dnf on Linux,
`softwareupdate -l` on macOS, the Windows Update Agent COM API's
`CreateUpdateSearcher` on Windows — cached centrally so the Patches tab
renders from Postgres, not a live fan-out. **Applying** patches is the
first thing in this codebase that reaches past "read something back" into
"change agent state," which is exactly the category ROADMAP.md's query/
command language section flags as needing a real signing/authz story
before it's safe as *general* command execution. `apply_patches` sidesteps
that by not being general: the agent command carries no text to execute at
all, just a command name, and the agent-side handler runs exactly one
hardcoded, OS-native "install everything pending" invocation — there is no
code path from a NATS message to an arbitrary shell command. That's what
makes it reasonable to ship gated behind `patches.manage` alone rather than
waiting on agent identity signing. The reply only acknowledges the job
*started* (a real `apt-get upgrade` can run for minutes); the agent
republishes the patches sensor when it finishes so the console's cached
view catches up on its own.

## Risk & Compliance: real CVE data, not a fabricated score

The Risk tab needed an actual vulnerability data source, not a made-up
composite number — a "risk score" that's really just decoration would be
worse than not having the feature. `internal/server/osv` is a small client
for [osv.dev](https://osv.dev): free, public, no API key, aggregates GitHub
Security Advisories plus the Debian/Ubuntu/Alpine security trackers among
others, and — critically for this — has a batch query endpoint that takes
(ecosystem, package name, version) tuples and returns matching
vulnerability IDs directly, so mustra doesn't need to solve CPE matching
itself (the genuinely hard, error-prone part of building a vulnerability
scanner from raw NVD data).

**Data flow** (`vulnscan.go`): the periodic scan reads every agent's
already-cached `installed_apps` sensor snapshot (no new agent-side
collection needed — this is the same data the Installed Apps sensor
already gathers), maps each agent's platform to an OSV ecosystem
(`ecosystemForPlatform` — currently Debian/Ubuntu/Alpine only, see below),
and deduplicates package+version pairs *across the whole fleet* before
querying OSV, so a library every host shares only costs one lookup.
Matches come back as bare vulnerability IDs; full details (severity,
summary, CVE aliases) are fetched per-ID and cached indefinitely in
`vuln_details_cache` — a CVE's severity doesn't change after publication,
so a vulnerability seen on a previous scan costs zero additional OSV calls
on the next one. Runs every 6 hours (`vulnScanLoop`) plus on demand via
"Scan now" (`patches.manage`-gated, same tradeoff as Patches' "Deploy
now" — synchronous, can take a while on a large fleet's first scan).

**Severity comes from a real CVSS v3.1 base score calculation**
(`cvssV3BaseScore` in the osv package), not a library — the formula is a
fixed, well-specified 8-metric calculation from the CVSS spec, and
implementing it directly avoided pulling in a dependency for something this
self-contained. Falls back to the ecosystem's own severity string
(`database_specific.severity`, common in GHSA/Debian/Ubuntu-sourced
entries) when a CVE has no published CVSS vector.

**Tradeoff — why OSV over each distro's own security tracker:** the
Debian Security Tracker and Ubuntu Security Notices are more authoritative
for their own distro specifically — they know when a CVE was fixed via a
backport without the upstream version number changing, which a generic
version-comparison against OSV/NVD data can occasionally get wrong (rare,
but real). OSV was chosen anyway because it's *one* integration covering
every supported OS uniformly, matching the project's existing "one query
mechanism, not N per-thing" pattern (see the query/sensor design above) —
switching to or adding distro-native trackers per OS is a plausible
follow-up if false positives from backport mismatches turn out to matter
in practice.

**Scope, deliberately**: only Debian/Ubuntu/Alpine hosts are scanned —
these are OSV's actual OS-package coverage. RHEL-family and Windows/macOS
hosts are skipped outright rather than silently returning zero
vulnerabilities, which would look identical to "fully patched" and be
actively misleading. Extending coverage means either adding a RHEL/OVAL
data source or accepting OSV's (currently thinner) coverage there — not
something to fake by reporting a clean bill of health for an unscanned
host.

## Data store choices

| Store | Holds | Why this one |
|---|---|---|
| Postgres | Everything the control plane knows: inventory, sensor cache, policies, packages, playbooks, roles, audit | Relational integrity across inventory and policy, and a type system rich enough for the shapes sensors actually produce |
| Named volume (`package-files`) | Package payloads — the installers staged to endpoints | A 400 MB MSI in a Postgres row is carried by every backup and every replica thereafter |
| Named volume (`output`) | Rendered reports, Connect file exports, backup archives | Files an operator asked for; losing them on redeploy would be a trap rather than a limitation |
| bbolt | Per-agent local identity + outbox | Single-file, zero-dependency, embedded — no separate process needed on the endpoint |

Earlier revisions of this document listed VictoriaMetrics for metrics and
MinIO for payloads. Neither was ever wired up, and the two named volumes
above are what actually runs.

### Postgres is required, not merely the default

mustra runs on Postgres and nothing else. That is a deliberate limit rather
than an unfinished abstraction, and it is worth stating plainly because
"which databases do you support" is a reasonable first question.

The store is handwritten SQL over pgx — no ORM, no query builder, no
dialect layer — and it leans on Postgres wherever leaning is the simplest
correct thing:

- **JSONB** for sensor payloads, whose shape is defined by the sensor rather
  than by the schema, with indexes into their keys.
- **Array columns** for the small ordered sets that would otherwise be join
  tables earning nothing.
- **`INSERT … ON CONFLICT DO UPDATE`** for the upsert that every ingestion
  path performs, and `ON CONFLICT DO NOTHING` for one-shot claims where the
  question is who got there first.
- **Partial and expression indexes** for the filtered reads the console
  makes constantly.
- **`now()` and interval arithmetic** in SQL, so staleness is computed by
  the database that holds the timestamps rather than by whichever process
  asked.

Supporting a second engine means none of that can be used directly. The
work is not a connection string: it is a dialect layer over every query, a
second schema kept in step with the first, JSONB rewritten as whatever the
target offers, `MERGE` in place of `ON CONFLICT` on SQL Server, and a test
matrix that runs the suite once per engine — followed, permanently, by
every new feature costing as much again and every bug needing reproduction
on each engine.

The honest trade is that Postgres is not a burden worth spreading that cost
to avoid. It ships in the compose stack, `init.sh` configures it, and an
operator who wants it elsewhere sets `MUSTRA_POSTGRES_DSN` at any Postgres
16 or newer — managed, containerized or on metal. Anyone who genuinely
needs MySQL or SQL Server is better served by that being a clear no than by
a port that works for the first month.

## Design tradeoffs at ambiguous forks

Picked the simpler option at each of these; noting the tradeoff so it's a
deliberate choice, not an oversight:

1. **Agent-presented ID trusted at registration, unsigned.** Simple now;
   must be replaced with real agent identity/signing before exposure beyond
   a trusted network (ROADMAP.md).
2. **SSE full-snapshot broadcast instead of deltas.** Simple and correct at
   current scale; will need pagination/diffing before tens of thousands of
   agents.
3. **JetStream `LimitsPolicy` + time-bounded retention** instead of
   `WorkQueue`, so multiple independent consumers can read the same
   history.
4. **Staleness computed at read time**, made visible via a periodic sweep
   broadcast rather than a writer job that flips a stored flag.
5. **Single server instance assumed.** The register/result subscriptions
   aren't in a NATS queue group, so running multiple server replicas today
   would process every registration and result multiple times. Fine for
   the single `docker compose` instance this ships as; needs queue groups
   before horizontally scaling the server (ROADMAP.md).
6. **`cmd/server` and `cmd/console` are identical processes** that both call
   `internal/server.Run` — deliberate duplication now so the eventual split
   (console scaled independently from the API server) is a matter of
   diverging two thin `main.go` files, not restructuring `internal/server`.
7. **bbolt outbox drains strictly FIFO, stopping at the first failure**
   rather than skipping past a failed message to keep draining — preserves
   ordering (a heartbeat from 5 minutes ago should never publish after one
   from just now) at the cost of one stuck message blocking the rest until
   the next tick.
8. **Server-side sessions in Postgres, not JWTs.** A DB lookup per request
   instead of stateless verification, in exchange for logout/revocation
   that's actually instant rather than "wait for token expiry."
9. **One static SCIM bearer token, not per-client OAuth2 credentials.**
   There's exactly one SCIM client per deployment (the IdP); a rotatable
   static token is the right amount of complexity for that, not a full
   OAuth2 client-credentials grant.
10. **SCIM implements the request shapes real IdPs send, not the full RFC
    7644 grammar.** Filter and PATCH-path parsing are pragmatic subsets;
    unrecognized PATCH ops are skipped-and-logged rather than failing the
    whole request, so a sync carrying both understood and not-yet-understood
    ops still makes forward progress on the parts it can.
