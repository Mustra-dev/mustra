# Working in mustra

mustra is a fleet-management and endpoint-operations platform: Go agents on
Linux, macOS, and Windows communicate outbound over NATS with a Go control
plane. The control plane stores data in Postgres and serves an embedded web
console. Changes can affect commands running with administrative rights on
managed endpoints; preserve targeting, authorization, and outcome semantics.

## Start here

- Read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements.
  Commits require DCO sign-off (`git commit -s`); comments explain why.
- For product behavior, read the relevant section of
  [docs/CONCEPTS.md](docs/CONCEPTS.md); the README is now a feature summary
  that links into it. For architectural rationale, consult
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- For major features, significant behavior changes, breaking changes, and
  operator-visible fixes, update [CHANGELOG.md](CHANGELOG.md) in the same change.
  Add unreleased work under `Unreleased`; describe the user-visible behavior and
  any required server/agent upgrade or migration. Preserve published release
  entries and move unreleased notes into a versioned section when releasing.
- For deferred work or follow-up planning, read [ToDo.md](ToDo.md). Update its
  checkboxes when completing an item or record deliberately deferred work there.
- For feature scope or proposed work, consult
  [docs/ROADMAP.md](docs/ROADMAP.md), then verify against implementation.
  Older “Slice 1” descriptions and deferred lists are historical: several
  capabilities they call unimplemented now exist. This also affects source
  comments. Current code, configuration, and tests establish actual behavior.

## Find the change surface

| Area | Entry points and responsibilities |
| --- | --- |
| Executables/configuration | `cmd/server/main.go` is the deployed control-plane entrypoint; `cmd/agent/` owns agent flags and service integration. `cmd/console/` calls the same server package but its configuration has diverged; compare both when changing shared startup behavior. |
| Shared protocol | `internal/proto/types.go` contains JSON message shapes; keep it independent of transport and persistence. |
| Messaging | `internal/nats/` owns subject builders, connections, and JetStream streams. `deploy/nats/nats.conf` owns broker permissions. |
| Endpoint runtime | `internal/agent/agent.go` wires registration and collection; `sensor_loop.go` handles periodic snapshots and commands; `query.go` handles live queries. Feature collectors and OS-specific implementations live alongside them. |
| Agent persistence | `internal/agent/store.go` stores identity and the outbox in bbolt; `publisher.go` handles durable publishing and retry. This is separate from the server store. |
| Server runtime | `internal/server/server.go` wires services, consumers, and background loops. `httpapi.go` registers routes and permission gates; feature `*_api.go` files handle HTTP. `consumers.go`, `hub.go`, and `query.go` handle ingestion and live updates. |
| Server persistence | `internal/store/` uses pgx and handwritten SQL; `schema.sql` is embedded and applied by `store.Open`. Feature files contain records and queries. |
| Targeting | `internal/groups/` defines field vocabulary and rule matching, reused by groups and Interact. Software applicability and dispatch are in `internal/server/software_api.go`. |
| Console | `internal/server/static/` contains HTML with page-local JavaScript, shared `app.js`, and `app.css`. `console.go` embeds and serves these assets. |
| Identity/integrations | `internal/server/auth/`, `scim/`, `vault/`, `osv/`, and `debsec/` own authentication, provisioning, credential encryption, and vulnerability sources. |
| Deployment/releases | `deploy/Dockerfile.server` builds the server and six OS/architecture agent binaries. `internal/version/` carries build identity; root `changelog.go` embeds `CHANGELOG.md` for the console. |

`packaging/npm/` and `packaging/pypi/` reserve package names; they are not
application dependencies or build systems. There is no frontend bundler.

## Change conventions and invariants

### Protocol and delivery

- Use subject builders from `internal/nats/`. The `beacon.*` namespace is a
  deployed wire protocol retained after the rename to mustra. Preserve it;
  any rename needs a compatible transition. Preserve existing `BEACON_*`
  environment fallbacks where the entrypoints support them.
- When adding a message, trace producer → subject → broker ACL → stream or
  request/reply subscription → consumer. Update `deploy/nats/nats.conf`
  alongside subject additions. A denied durable publish can block the
  agent's ordered outbox.
- Keep telemetry and asynchronous action outcomes on the durable publisher
  path. Preserve bounded retries and poison-message handling in the outbox
  and server consumers; acknowledge persisted data after the write succeeds.
- Agents and servers upgrade independently. Keep existing JSON fields and
  defaults compatible, and check behavior when an older peer omits a field.
  A command's immediate “started” reply is not its final outcome: long jobs
  report through `AgentActionResult` with run/action IDs.

### Data and endpoint operations

- Schema edits must work both on a fresh database and on an existing one.
  `CREATE TABLE IF NOT EXISTS` alone does not add columns to existing tables;
  follow the idempotent `ALTER`/guarded migration patterns in `schema.sql`.
  Keep SELECT column order and Scan destinations aligned. Go compilation
  does not validate SQL or prove an upgrade works.
- Reuse shared targeting, parameter resolution, applicability, and dispatch
  paths for interactive and scheduled operations. A deleted target group
  must not turn a policy or playbook into a fleet-wide operation; preserve
  the explicit `GroupDeleted` behavior.
- Distinguish software packages (inventory detection) from action packages
  (commands). Preserve the special agent-version fact detection used by
  update actions. Derive deployment status from device results and retain
  the difference between failure, timeout, and no response.
- Enforce starts in report mode, re-checks after remediation, and bounds
  consecutive failures per endpoint. Unsupported compliance rules produce
  `unknown`, never a pass or a reason to remediate.
- Keep integrity baselines/diffs server-side. Preserve event coalescing,
  resource limits, suppression counts, and separate treatment of matched
  evidence. IOC matching does not automatically kill processes; live-response
  kills retain the expected-name check against PID reuse.

### Permissions and UI

- Register routes in `httpapi.go` with the appropriate server-side auth and
  permission wrapper. Check `auth/permissions.go` and neighboring routes;
  sidebar visibility is presentation, not authorization. Agent-facing and
  SCIM endpoints have distinct authentication paths.
- Declare each new `/api` route in `internal/server/openapi_routes.go`
  (body, query parameters, response and statuses, as Go types); the OpenAPI
  spec and the API reference's request builder read it. The drift test
  checks every declaration against its handler's source, a handler serving
  several routes is declared for all of them, and `undocumentedRoutes`
  only goes down. A route that takes a JSON body also needs an example in
  `openapi_examples.go`: scoped to an explicit endpoint or group, harmless
  if sent as written, a `<placeholder>` for any secret
  (`bodiesWithoutExample` only goes down). A route that replaces one
  server-wide setting cannot have a harmless one; list it in
  `noBodyExample` instead. A route that answers with JSON also needs a
  response example in `openapi_resp_examples.go`, written from its
  handler, with a `<placeholder>` for any token it shows once
  (`respsWithoutExample` only goes down). The spec's descriptions are the
  doc comments of the declared types: after changing one, run
  `go generate ./internal/server`.
- Custom sensor scripts and package commands share `deploy.manage` because
  both execute operator-provided code. Preserve audit attribution on endpoint
  actions and the audit-before-send behavior of Direct Connect.
- Extend the existing vanilla JS/CSS structure. Reuse `app.js` helpers,
  navigation, theme handling, and `escapeHtml` for dynamic HTML content.
  The console CSP refuses `style` attributes: use a class, one of the
  `u-*` utilities at the end of `app.css`, or `sx()` for a value computed
  while building markup. Setting `el.style` from script still works.
  Update route, page handler, and navigation together for new pages.
- Static files are embedded at build time: rebuild/restart the server to see
  edits. Shared CSS/JS links are versioned by content hash in `console.go`;
  preserve that serving path when adding pages.

### Designing the console

- For any UI or design change, requested or needed along the way (a new
  page or panel, a layout, visual or copy change, a review of how something
  looks or reads), use whatever design skills you have to hand for UX rules,
  accessibility, layout, typography and colour, and to review screenshots.
- Their output is advice, adapted to this codebase, never pasted in: the
  console is vanilla HTML/CSS/JS with no bundler, Tailwind, React, shadcn
  or npm packages; it is served under a strict Content Security Policy, so
  no external fonts, images, scripts or CDNs; it must work in both themes
  and keep using `app.css` tokens and `app.js` helpers.
- Do not send repository content, screenshots of a real deployment or
  endpoint data to the skills' third-party services (image downloads, AI
  logo generation). Check the result in a browser in both themes, as the
  validation section says.

### Sensors and platform support

- A new built-in sensor needs protocol types, runtime registration/collection,
  query support where applicable, server consumption/display, and an entry in
  `internal/server/sensors_catalog.go` describing the actual collection
  mechanism and limitations per platform. Update the explicit sensor list in
  `sensors_catalog_test.go` too.
- Follow existing OS file suffixes and build tags, with implementations or
  explicit fallbacks for supported platforms. Use `darwin` in protocol and
  targeting values; `macOS` is the display label. Preserve collection time
  budgets and cancellation rather than assuming every OS command is fast.

## Validation

Use the Go toolchain declared in `go.mod`. From the repository root:

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

Format changed Go files with `gofmt`. Run focused package/tests during work,
then the applicable repository checks before handing off code changes.
Use regression tests for changed behavior; concurrency changes warrant a
focused `go test -race` run. Report baseline failures separately from new ones.

- The default tests do not require a running control plane. The Debian live
  tracker test is opt-in: `MUSTRA_LIVE_DEBSEC=1 go test
  ./internal/server/debsec/ -run Live -v` downloads a substantial external feed.
- macOS caveat observed during this guide's creation: four remediation tests
  in `internal/agent/enforce_test.go` supply only `RemediateLinux` although
  `linuxOnly` skips only Windows. `TestWatchDirsIsBoundedAndReal` also fails
  because it uses `Lstat` on macOS's `/etc` symlink. Verify these assumptions
  against the current checkout rather than treating all agent failures as
  expected or weakening production behavior to satisfy them.
- For agent/platform changes, cross-build the affected targets from the
  Dockerfile's matrix: Linux, Darwin, and Windows, each amd64/arm64. Example:
  `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /tmp/mustra-agent.exe
  ./cmd/agent`. Cross-building checks compilation, not OS behavior.
- Database changes need fresh-schema and repeated-upgrade checks against a
  disposable Postgres database. Browser changes need a rebuilt server and
  checks of the affected interaction, permissions, and both themes; Go tests
  do not execute page JavaScript.
- Endpoint-side UI (the Windows tray and toasts, Self Service, end-user
  notifications and surveys) runs on a real desktop, so check it on one.

## Local stack and release work

For running the stack or changing deployment, read [deploy/README.md](deploy/README.md),
then inspect `deploy/docker-compose.yml`, `deploy/.env.example`, and
`deploy/nats/nats.conf`. The active services are NATS, Postgres, server, and
Cloudflared; old mentions of MinIO/VictoriaMetrics do not describe the current
stack. Package payloads and generated output use named volumes.

Compose requires NATS credentials and certificates. `deploy/nats/gen-certs.sh`
defaults to `nats`, `localhost` and `127.0.0.1` only; pass the broker's real
hostnames/IPs as arguments or set `MUSTRA_NATS_SANS`, or remote agents will
fail TLS verification. Cloudflared needs its own tunnel credentials and
`deploy/cloudflared/config.yml` is a placeholder template, so select the
services needed for local testing. Plain-HTTP development requires disabling
secure cookies in that local configuration. `.gitignore` covers
`deploy/nats/certs/`, `.env*` except `.env.example`, cloudflared credentials,
agent data directories and common key/credential extensions
(`*.key`, `*.pem`, `*.creds`, …); still check `git status` before committing
anything generated, and keep `git ls-files -ci --exclude-standard` empty.
Report vulnerabilities privately per [SECURITY.md](SECURITY.md).

For release changes, use `internal/version/` and the Dockerfile's linker flags
as the source of truth. Server and agent versions are independent: a
server-only change must not advertise an unchanged agent as a new release.
`CHANGELOG.md` ships inside the server binary and appears in Administration → About.
