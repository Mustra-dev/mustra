# Roadmap

This file is partly a historical record. The "first vertical slice" list
and the deferred list below were written as the project grew, and many
deferred items have since shipped; where that is known it is marked
inline. For what mustra does today, read [CONCEPTS.md](CONCEPTS.md); the
code, configuration and tests are the final word. Security properties and
how to report a problem are in [SECURITY.md](../SECURITY.md).

## Done: the first vertical slice, and what followed

- Agent: connect → register (persisted identity via bbolt) → heartbeat →
  publish facts → subscribe to `beacon.q.*` for its identity → buffer to
  bbolt on outage, flush in order on reconnect.
- Server: consume registration/heartbeat/facts, persist current state to
  Postgres, compute online/offline from heartbeat staleness, HTTP+SSE API.
- Console: live endpoint list over SSE; a query button that fans a fixed,
  safe facts query out to `beacon.q.all` and streams results back with a
  responded/expected counter.
- `deploy/docker-compose.yml`: NATS+JetStream, Postgres, the server/console,
  and an optional `cloudflared` tunnel container, with healthchecks and a
  README. (The first version also stood up VictoriaMetrics and MinIO; neither
  was ever wired up, and both were removed.)
- Console authentication: OIDC SSO (Authentik or any standards-compliant
  IdP) with background discovery retry, a local break-glass backdoor
  account independent of the IdP, and SCIM 2.0 user/group provisioning.
  Optional public exposure of the console via a dedicated Cloudflare
  Tunnel.
- Sensor framework beyond facts: processes, services, and installed-apps —
  each queryable on demand (live query, same mechanism as facts) and
  auto-refreshed centrally every 15 minutes by default (per-sensor,
  adjustable at runtime via a `beacon.cmd.<id>` command, no agent restart
  needed), cached server-side in Postgres JSONB so the console shows current
  data without a live round-trip every time.
- Agent deployment: cross-compiled binaries for every OS/arch served at
  `/downloads/`, one-liner install scripts (`/install.sh`, `/install.ps1`)
  that set up a systemd/launchd/Windows-service unit, an encrypted SSH
  credential vault, a network scanner (TCP-22 sweep of a CIDR), and a
  one-click SSH push that runs the same install script directly against a
  discovered host — all on a dedicated `/agents` console page.
- Console UI: mobile-responsive layout, client-side endpoint search, a
  sensor-kind selector on the query panel, and a shared nav/theme/user-chip
  layer (`static/app.js`) across pages.
- Offline agent expiry: an agent offline longer than `OfflineExpiry`
  (`MUSTRA_OFFLINE_EXPIRY`, default 1h) is removed from inventory entirely,
  not just shown offline, on a 5-minute sweep. Re-registering brings it
  right back.
- RBAC: roles (a named, admin-creatable bundle of a fixed set of permission
  keys — `settings.manage`, `users.manage`, `patches.manage`,
  `deploy.manage`) assignable to a user directly or to a group, plus the
  builtin "admin" (everything, reseeded to the full permission set every
  startup) and "user" (nothing, customizable) roles. Gates the Settings,
  Admin, Patches-apply, and Deploy tabs; the endpoint list and live queries
  stay open to any authenticated user. Existing users were grandfathered to
  admin in a one-time migration on first boot with RBAC (see
  `GrandfatherAllUsersAdminOnce`) since nothing was gated before.
- Admin Settings tab: SSO/backdoor/SCIM/agent-staleness config is now
  Postgres-backed and live-editable with no restart — env vars only matter
  as the very first boot's seed value. `internal/server/auth.Auth` hot-swaps
  its discovered OIDC provider on a settings change (mutex + a generation
  counter to abandon a superseded in-flight discovery).
- Admin Users/Groups/Roles tab: view/manage local + SCIM/OIDC-provisioned
  users, create local security groups (in addition to SCIM-synced ones),
  and tie roles to either.
- Patches tab: a fleet-wide "which patches are missing on which devices"
  view built from each agent's cached patches sensor (processes/services/
  installed_apps' "keep an answer fresh centrally" model, not a live
  query), plus a narrow, non-arbitrary `apply_patches` agent command (runs
  exactly one OS-native "install everything pending" invocation — apt-get
  upgrade, dnf/yum upgrade, softwareupdate -i -a, or the Windows Update COM
  API — never free-text) gated behind `patches.manage`.
- Deploy page: an "Auto scan" button that guesses the LAN subnet from
  `MUSTRA_AGENT_NATS_URL`'s host (falls back to an outbound-UDP-dial route
  guess, assumed /24, if that's unset) instead of requiring a typed CIDR —
  deliberately not guessed from the server container's own network
  interfaces, which under docker-compose's default bridge networking
  reflect the bridge subnet, not the real LAN. The credential vault's
  private-key field also accepts a file upload (read client-side into the
  same secret field — no new upload endpoint needed).
- Sidebar redesign: a permanent icon rail plus a flyout menu (tap-to-expand
  subcategories, pin to dock permanently) instead of a top tab bar; a
  persistent secondary sub-nav on multi-section pages (Administration,
  Patches) showing one section of `<main>` at a time instead of one long
  scrolling page; a home dashboard (collapsible groups of
  stat/mini-chart cards: Environment Status, Patch Status, Risk &
  Compliance) plus a permission-filtered Modules launcher grid.
- Risk & Compliance tab: real CVE matches from osv.dev against every
  Debian/Ubuntu/Alpine host's installed packages (`internal/server/osv`,
  `vulnscan.go`) — deduplicated fleet-wide before querying, severity from
  an actual CVSS v3.1 base-score calculation, rescanned every 6 hours or
  on demand. See ARCHITECTURE.md's Risk section for why OSV over each
  distro's own tracker, and the deliberate RHEL/Windows/macOS coverage gap
  (skipped outright rather than silently reporting them as clean).

See [ARCHITECTURE.md](ARCHITECTURE.md) for how it's built and the
tradeoffs made along the way.

## Deferred after the first slice

Written as the follow-up list for the first slice, roughly in the order
it'd make sense to tackle them. Items marked **Done** or **Superseded**
are kept for the reasoning; check the code before relying on any entry.

### Security
- **NATS auth and TLS. Done.** The production broker
  (`deploy/nats/nats.conf`) requires TLS and a credential on every
  connection, with separate server and agent roles: only the server may
  publish commands and queries. The remaining step is per-agent
  credentials issued at enrollment, so one compromised agent cannot publish
  as another; [SECURITY.md](../SECURITY.md) describes the intended model.
  (This is independent of the console's own authentication, which gates
  the HTTP/SSE API, not the bus.)
- **Agent identity.** Registration originally trusted whatever `agent_id`
  an agent presented. Enrollment tokens and per-agent credentials are the
  answer; see the item above.
- **TLS for the console.** The HTTP API is plain HTTP on `:8080` and is
  meant to sit behind a TLS-terminating reverse proxy or the optional
  Cloudflare Tunnel, with `MUSTRA_COOKIE_SECURE=true`. Postgres stays on
  the compose-internal network.

### Console auth hardening
- **RBAC by SCIM group. Done:** roles can be assigned to groups. Original
  note: groups exist and sync via SCIM, but nothing
  reads them yet — every authenticated user can do everything an
  authenticated user can do. Wire `is_admin` / group membership into actual
  authorization checks once there's a feature worth gating (e.g. command
  execution, once that exists).
- **Full SCIM filter/PATCH grammar.** Only `attr eq "value"` filters and a
  handful of PATCH paths (`active`, `displayName`, `members`) are
  implemented — the shapes Authentik's SCIM provider actually sends. A
  different IdP might send filter `and`/`or`, other operators, or PATCH
  paths not yet handled; those are currently silently skipped rather than
  applied.
- **CSRF tokens on state-changing forms.** Planned for the public release
  (see SECURITY.md); verify against the code. Original note: `/login/local` and `/logout`
  currently rely on `SameSite=Lax` cookies (which already block the
  cross-site POST case that would matter) rather than an explicit
  per-request CSRF token. Fine for now; add explicit tokens before this
  is a multi-admin, higher-stakes deployment.
- **Login rate limiting.** No throttling on `/login/local` attempts yet —
  bcrypt's cost factor is the only friction against brute-forcing the
  backdoor password.
- **Admin promotion workflow. Superseded** by roles, assignable in the
  console. Original note: the only way to make a user `is_admin` today
  is a direct DB write; no console UI or API for it.
- **Cloudflare Tunnel credential rotation.** A tunnel created from an
  origin cert (`cloudflared login`) needs a fresh login, or a Cloudflare API
  token, to be recreated if that cert is rotated or revoked. Document a
  token-based path for operators who prefer it.

### Deploy page follow-ups
- **SSH push is synchronous and one-host-at-a-time.** Pushing to many
  discovered hosts means clicking Deploy on each; no bulk "deploy to all
  scanned hosts" action yet, and a slow host blocks the request for up to
  the 3-minute timeout. Worth making concurrent/streamed (SSE, matching the
  live-query pattern) if the credential vault sees real multi-host use.
- **`pushAgentViaSSH`'s captured output is occasionally empty on success**
  (observed once during testing — the operation genuinely succeeded,
  confirmed via the remote service's status, but the SSH session's
  stdout/stderr buffer came back empty). Cosmetic — the console still shows
  the correct ok/fail state — but worth root-causing if it recurs.
- **Host key checking is disabled** (`ssh.InsecureIgnoreHostKey()`) for the
  push flow — acceptable for scanning your own LAN, not for anything
  reaching further. Trust-on-first-use with a pinned-key store would close
  this without requiring a known_hosts file.
- **Windows install-script coverage is untested end-to-end** in this
  session (no Windows host was available to push to) — the PowerShell
  script and `-EncodedCommand` path were written and reviewed but not run
  against a real Windows/OpenSSH target. Linux was verified twice, real
  end-to-end (manual `curl | bash` and the SSH-push API path, including
  hitting and fixing an `ETXTBSY` re-install bug).
- **Network scan is TCP-22-only.** No credential-free "is this even a
  mustra-compatible host" probe beyond "SSH is open" — a scanned host might
  have SSH open but not be a fleet target at all.

### Query & command language
- A real, constrained query language (not the fixed `facts`-only kind used
  in the first slice; Interact's rule-based targeting and saved questions
  have since covered much of this) — something like an allowlisted expression language over
  gopsutil fields, not arbitrary code execution.
- Targeted command execution. **Done** in several narrow forms (patching,
  Deploy packages, enforcement, Direct Connect), all gated by server-side
  permissions and audited. Original note: (`beacon.cmd.<id>`) needs the same signing/authz story as agent identity before it's safe:
  a command channel is a remote-code-execution primitive by design, so it
  must not ship without server-side authz and ideally agent-side allowlists
  of what commands even mean.
- osquery as an **optional plugin** once the query language exists — not a
  core dependency, as specified from the start.

### Fleet operations
- Package deployment. **Done:** Deploy and action packages, with payloads
  on a named volume served by the server (see DEPLOY.md and
  ACTION-PACKAGES.md); MinIO was never used.
- Desired-state enforcement. **Done:** Enforce policies with report mode,
  remediation and drift reporting.
- Agent auto-update. **Done:** agent updates from Deploy Agents.
- Agent as a proper OS service. **Done:** the install scripts set up a
  systemd unit, launchd daemon or Windows service.

### Metrics
- Time-series metrics (CPU, memory over time). `facts` are a point-in-time
  snapshot published infrequently. The original plan was Prometheus
  remote-write into VictoriaMetrics; that was never wired up and is not in
  the stack.
- Dashboards in the console. **Done** for fleet state (see CONCEPTS.md);
  not for time series.

### Scale
- **Server horizontal scaling.** The registration and result subscriptions
  aren't in a NATS queue group — running multiple server replicas today
  means every replica processes every registration and every result. Add
  queue groups before scaling the server beyond one instance.
- **SSE at scale.** Both the agent-list and query-result SSE feeds
  broadcast full snapshots. Fine now; needs pagination and/or delta updates
  before tens of thousands of agents make a full-snapshot-per-heartbeat
  approach expensive.
- Predicate language beyond exact-match OS/site (range/regex/multi-value
  filters) for finer-grained query targeting.
- Console/server process split (`cmd/console` and `cmd/server` start the
  same server package, though their configuration has diverged — see ARCHITECTURE.md's tradeoff #6) once the console
  needs a different scaling profile than the API/NATS-consuming server.

### Audit & history
- Persist query history (who ran what, when, against how many agents).
  **Done** for Interact questions (question history) and endpoint actions
  (audit events). Original note: queries lived only in server memory and
  expired after 5 minutes.
- Heartbeat/facts history beyond "current state" (the time-series item
  above, called out as its own audit-trail use case).
