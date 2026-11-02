# Developing mustra

What you need, the two ways to run it, and where things are. The
[README](../README.md) is the product; this is the workbench.

## Prerequisites

| Tool | Why |
|---|---|
| Go, the version in `go.mod` | Everything is Go. No CGO, no code generation, no front-end toolchain: the console is static HTML/JS embedded in the server binary. |
| Docker with the compose plugin | NATS and Postgres, and the production image. |
| `openssl` | Generating the NATS certificates for the production stack. Not needed for the development loop. |
| `make` | The targets below. Every one is a short shell command you can also run by hand; `make help` lists them. |

## The development loop

The production stack builds the server into a container and cross-compiles
six agent binaries on every `--build`. For iterating on the server that is
the wrong shape, so development runs only the backing services and script tools in Docker
and everything of ours from source.

```sh
make dev-up          # NATS and Postgres, published on 127.0.0.1 only
make dev-server      # go run ./cmd/server, console at http://localhost:8080
sudo make dev-agent  # go run ./cmd/agent, in a second terminal
```

Sign in as `admin` / `admin`. The `dev-server` target turns off the Secure
cookie flag, allows those placeholder credentials, and points `/downloads/`
at `bin/agents/`. Build downloads explicitly with `make agents` when testing
Client Management install scripts, or select just the platform you need:
`make agents AGENT_TARGETS=darwin/arm64`. Server startup does not rebuild
agents. Development stamps versions and commit but omits the changing build
timestamp to avoid unnecessary relinking; `make server` stamps all fields.

The script-tools container supplies port 8091 on localhost. Both server
entrypoints default to that URL; override `MUSTRA_SCRIPT_TOOLS_URL` for a separate
private service. `make dev-up` builds it, and starts the analyzers with resource
limits and no control-plane credentials. See
[script-service](../tools/script-service/README.md) for its tests.

The development NATS has no TLS and no authentication and is bound to
localhost; `deploy/nats/nats.dev.conf` says why that is only acceptable
there. Its Postgres is `mustra` / `mustra` on `localhost:5432`, which is
also the server's built-in default DSN, so a bare `go run ./cmd/server` with
no environment at all finds it.

**The agent needs root** for most of what it does: reading every process,
installed applications, patch state, the integrity set. It runs unprivileged
but many sensors report errors or partial data. `sudo make dev-agent` is the
honest way to test it. Its identity and outbox live in `scratch/agent-data`
(gitignored); delete that directory to enrol as a new endpoint.

To stop: `make dev-down` keeps the data, `make dev-reset` wipes it.

## Checks

```sh
make check    # gofmt, go vet, go build, go test: exactly what CI runs
make test     # just the tests
make lint     # just gofmt + vet
```

CI (`.github/workflows/ci.yml`) runs the checks on Linux, compiles every
package for Windows and macOS there, cross-compiles all six agent targets,
and builds the production image without pushing it. The macOS test job and
the macOS and Windows sensor jobs, the slowest machines to get, run
when a change can affect them: the agent's packages and their test imports,
`*_darwin`/`*_windows`/`*_unix` files, `go.mod`/`go.sum` or the CI
configuration. `.github/scripts/changes.sh` decides; run
`.github/scripts/changes.sh origin/main HEAD` to see what a branch
triggers. A manual run runs everything. The
tests must pass on a Mac as well as on Linux; anything platform-specific
should skip with a reason rather than fail.
`.github/workflows/e2e.yml` runs the end-to-end pass described next.

## End-to-end tests

`test/e2e` is a test of the deployment, not of a package: it needs a stack
built by `deploy/init.sh --start`, Docker for its endpoint containers, and
Node for the browser crawl. It is behind the `e2e` build tag, so `go test
./...` does not run it. `.github/workflows/e2e.yml` runs it on every pull
request and push to main. It is also CI's only `Dockerfile.server` build:
`run.sh` checks that both compose files resolve and that the image carries
all six agents, both tray builds and the Python runtimes. In CI, the
workflow first copies the Go cache CI saved on main into the build's cache
mounts and loads the script-tools layers from CI's layer cache, so the
"stack up" step takes about a minute and a half rather than four; both are
restore-only.

```sh
npm ci --prefix test/e2e/ui                              # once: Playwright
npx --prefix test/e2e/ui playwright install --with-deps chromium
test/e2e/run.sh                                          # 15-25 min, most of it the image build
```

`run.sh` needs a checkout with no `deploy/.env` (use a worktree if you
already run a stack from this one): it bootstraps a fresh stack under the
compose project `mustra-e2e`, runs `go test -tags e2e ./test/e2e/`, then
removes the stack, its volumes, `.env` and the certificates. Logs, the
UI report and screenshots land in `test/e2e/artifacts/`. One ordered pass,
`TestE2E`, covers:

- first-run setup with the token from the server log (wrong token, weak
  password and a second setup refused), sign-in, and the public URL set
  through Settings → Agent identity;
- the unauthenticated install scripts: no secret from `.env`, forged
  `Host`/`X-Forwarded-*` ignored, `?site=` injection refused;
- two Ubuntu systemd endpoints installed with the console's one-liner
  under single-use tokens (file modes, no bus password in the agent's
  environment); a spent, garbage or missing token enrolls nothing;
- with one agent's own NATS credential, publishing or subscribing as the
  other agent, on `_INBOX.>` or on wildcards is refused; the legacy shared
  user cannot connect;
- CSRF (cross-site `Origin`, `Sec-Fetch-Site`, `Referer` → 403), the login's
  open redirect, package-file path traversal, and the security headers and
  nonce CSP on every navigation page;
- a signed agent update (the harness builds an older agent from this
  checkout to have something to update), refused when the pinned key does
  not match; password-gated uninstall, and a reinstall as a new agent;
- software deployment with the fixtures in `test/e2e/testdata`
  (succeeded, failed, timed out, `run`, an uploaded payload) and patching
  from a local apt repository on the endpoint, including a broken package
  reported as failed;
- a Playwright crawl of every page in the console's `NAV_TREE` plus an
  endpoint page, dark and light, 1440 px and 390 px wide: no JavaScript or
  console error, CSP violation, failed request or horizontal overflow.

Against a stack that is already up (it must not have been set up yet),
run the tests directly:

```sh
go test -tags e2e -count=1 -timeout 60m -v ./test/e2e/
go test -tags e2e -count=1 -v ./test/e2e/ -run 'TestE2E/(setup|public-url|install-scripts|enroll|nats-isolation)$'
```

Steps after `enroll` need its endpoints, so a `-run` filter has to keep
`setup`, `public-url` and `enroll`. Reset a stack for another pass with
`cd deploy && docker compose down -v && docker compose up -d --wait`.

The harness reads the stack's address, ports and secrets from
`deploy/.env`. To run beside another stack, or on a host that needs local
changes to the build, set:

| Variable | Default | Use |
|---|---|---|
| `MUSTRA_CONSOLE_PORT`, `MUSTRA_NATS_PORT` | `8080`, `4222` | Host ports init.sh publishes on and records in `.env`. |
| `COMPOSE_PROJECT_NAME` | `mustra-e2e` | Keeps the stack's containers and volumes apart from another one. |
| `COMPOSE_FILE` | `deploy/docker-compose.yml` | Add a local override, colon-separated, without editing the repository (a registry mirror, a proxy CA). |
| `MUSTRA_VERSION` | `1.0.0-e2e` | Version stamped on the build; the update test needs a comparable one. |
| `MUSTRA_E2E_HOST_IP` | docker bridge gateway | The address endpoint containers reach the console and NATS at; init.sh puts it in the certificates. |
| `MUSTRA_E2E_CONSOLE_URL` | `http://localhost:<console port>` | Where the harness and the browser reach the console. |
| `MUSTRA_E2E_ENDPOINT_IMAGE` | built from `test/e2e/endpoint` | A prebuilt endpoint image. The default is Ubuntu 22.04, whose systemd boots on cgroup v1 and v2 hosts. |
| `MUSTRA_E2E_UI` | `1` | `0` skips the browser crawl. |
| `MUSTRA_E2E_KEEP` | unset | `1` leaves the stack and endpoint containers running for a look afterwards. |
| `MUSTRA_E2E_ARTIFACTS` | `test/e2e/artifacts` | Where logs, the UI report and screenshots go. |

### Windows, and drills on real endpoints

CI's `agent tests (windows)` job runs the agent's tests natively on
GitHub's Windows machines whenever agent code changes. Tests that change the
machine (install a service, need a real enrolled agent) are not run in CI;
drill those privileged paths on a disposable endpoint instead:

- **Install**: the console's Windows one-liner on Windows Server 2025.
- **Update**: an older release to the current one through the signed
  updater, canaries first (one Linux, one Windows), then the rest.
- **Recovery job registration**: after ten healthy minutes, the
  known-good copy and the job appeared on Linux (systemd timer), Windows
  (scheduled task as SYSTEM) and macOS (launchd, 600 s).
- **Recovery**: on Windows, stop the service, replace `mustra-agent.exe`
  with another program and age `heartbeat` by an hour, then start the
  `\mustra\agent recovery` task: it waited its 90-second recheck,
  restored the known-good build (hashes equal), kept the broken one as
  `.failed`, started the service, and the heartbeat resumed.
- **Uninstall**: `uninstall.ps1` removed the service, the recovery task and
  both directories; a reinstall with a new token enrolled cleanly.

Run a drill that stops the agent from a one-off SYSTEM scheduled task, not
from the agent's own shell, which ends with the agent.

## Configuration

The server and agent take flags; every flag also reads an environment
variable of the same name under `MUSTRA_`:

```sh
go run ./cmd/server -h
go run ./cmd/agent -h
```

The env var wins over the default, the flag wins over the env var. The
pre-rename `BEACON_*` names are still read as a fallback so existing
deployments keep working; new configuration should use `MUSTRA_*`.

Settings that matter for local work:

| Setting | Development value | Why |
|---|---|---|
| `MUSTRA_COOKIE_SECURE` | `false` | Browsers will not send a Secure cookie over `http://localhost`; with `true` the login silently does not stick. |
| `MUSTRA_ALLOW_PLACEHOLDER_SECRETS` | `true` | The server otherwise refuses to start on `changeme`-style passwords. Never set this on a real deployment. |
| `MUSTRA_AGENT_BUILDS_DIR` | `bin/agents` | Where `/downloads/` serves agent binaries from. The container has them baked in; a `go run` server does not. |
| `MUSTRA_AGENT_NATS_URL` | `nats://127.0.0.1:4222` | What the install scripts tell agents to dial. |

## Building

```sh
make server    # bin/mustra-server for this machine, version-stamped from git
make agents    # bin/agents/mustra-agent-<os>-<arch> for all six targets
make servers   # bin/servers/linux_<arch>/mustra-server for both image targets
make image     # the production image, version-stamped
```

Version, commit and build time are linked into the binaries and shown on
the About page. A build without them says `dev`, which is the honest
answer. The agent has its own version (`main.version`) so a server-only
release does not tell every endpoint it is out of date.

Cross-compiling by hand is one line, since there is no CGO:

```sh
GOOS=windows GOARCH=amd64 go build -o mustra-agent.exe ./cmd/agent
```

## Where things are

```
cmd/server          the control plane: flags, wiring, signal handling
cmd/agent           the endpoint agent, plus Windows service glue
cmd/console         identical to cmd/server today; a seam for a future split
internal/server     HTTP/SSE API, every module's handlers, the embedded console
internal/server/static   the console's HTML, JS and CSS
internal/agent      sensors, patches, enforcement, file/process watching
internal/store      Postgres access; schema.sql is applied on every start
internal/proto      message types shared by agent and server
internal/nats       subject names and connection helpers
deploy/             compose stack, bootstrap, dev services, Dockerfile
```

The schema in `internal/store/schema.sql` is idempotent and applied at
startup, so there is no migration tool: a schema change is `CREATE ... IF
NOT EXISTS` or `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` in that file.
When a backfill must run only on the start that adds a column, add the
column in a guarded `DO $$` block that checks `information_schema.columns`
and backfills in the same branch (`catalog_items.carried_to_packages` is
the example): `ADD COLUMN IF NOT EXISTS` cannot tell you it just added it.

`CHANGELOG.md` is embedded in the server and rendered on the About page.
Add an entry under **Unreleased** with the change; the convention is to say
what changed and why it was wrong before, not just what the diff does.

## Releasing

```sh
git tag v0.38.0 && git push origin v0.38.0
```

`.github/workflows/release.yml` publishes `ghcr.io/mustra-dev/mustra` for
`linux/amd64` and `linux/arm64` and attaches the agent binaries with a
checksum file to a GitHub release. Set the repository variable
`MUSTRA_AGENT_VERSION` to the last tag in which the agent changed when
shipping a server-only release.

## Build caching and deployment efficiency

CI and releases use `.github/actions/build-binaries` to build six agents and
two Linux servers on the native runner, then `deploy/Dockerfile.image`
packages `bin/` without invoking Go or QEMU. Release attachments and both
images use the same agent outputs. Agent builds use `-trimpath` and omit
checkout VCS metadata so server-only commits do not change otherwise identical
agent payloads; the independent agent version remains stamped into them.
Server builds use `-trimpath` too, here and in `Dockerfile.server`: the
checkout directory would otherwise be part of every package's cache key,
and E2E's image build reuses this Go cache from a different directory.
The cross-build Go cache is separate from native test caches and gets a new
snapshot per commit on main. Only main saves it, and only main writes the
BuildKit layer caches: a pull request's entries are readable by that pull
request alone, and saving them pushed main's out of the 10 GB Actions
cache. Other refs restore main's latest snapshot. Restores prefer matching
dependencies, then fall back to the same runner OS, architecture, and Go
version when `go.sum` changes.
Go validates cached inputs and rebuilds affected packages. CI cancels
superseded runs, on main as well as on pull requests.

Local Compose builds still use `deploy/Dockerfile.server`, with native Go
cross-compilation and separate server and agent stages sharing Go caches.
The agent stage copies only its local dependency packages; update that
list if the agent gains another internal dependency. Console edits can
reuse the agent layer when the agent version stays fixed. `make image AGENT_VERSION=vX.Y.Z` passes the independent version through Compose.
Without an explicit Make override, `make image` preserves an agent version
pinned in Compose's `.env` or the environment. Otherwise, an unset agent
version falls back to the server version as before.

For repeatable timing, hold version, commit, and timestamp constant. Measure
an initial build, an identical repeat, then a console-only edit. Do not clear
shared Docker/Go caches on a working machine just to simulate a cold build.
Use a disposable builder or a temporary `GOCACHE` instead.
