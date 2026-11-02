# loadsim — control-plane load simulator

`loadsim` drives a real mustra control plane (server + NATS with the auth
callout + Postgres) with a simulated fleet, through the production broker
path: TLS, one auth-callout decision per connection, a per-agent
credential obtained from a real enrollment token, per-agent subjects and
inboxes. It is behind the `loadsim` build tag, so `go build ./...`,
`go vet ./...` and `go test ./...` do not build it:

```sh
go build -tags loadsim -o loadsim ./tools/loadsim
go vet -tags loadsim ./tools/loadsim
```

## Subcommands

| Command | What it does |
| --- | --- |
| `server` | Runs the control plane (`internal/servercmd`, the same code as `cmd/server`, configured by the same `MUSTRA_*` environment) plus `net/http/pprof` on `LOADSIM_PPROF_ADDR` (default `127.0.0.1:18802`). The production binary carries no profiling endpoint. |
| `capture` | Connects as the server's NATS user and saves the newest payload of every agent subject kind (`register`, `heartbeat`, `facts`, `sensor.<kind>`, `procevents`, `recevents`) to `-out`. Run one real agent (`go run ./cmd/agent`) against the stack while it listens. |
| `enroll` | Enrolls `-n` identities with an enrollment token (`-token`, `max_uses` ≥ n; a token allows at most 1000 uses, so use several): each opens its own `mustra-enroll:<nonce>` connection and requests `beacon.enroll.token`, exactly as `internal/agent/identity.go` does. Credentials are appended to `-out` (JSON lines). About 120 enrollments/s on a 4-core box. |
| `fleet` | Runs the first `-n` identities as agents in one process. Each connects with the real agent's NATS options (including its reconnect backoff; `-fixed-reconnect` restores the old fixed 2 s wait for comparison), registers on `beacon.register.<id>`, subscribes to its query/command/shell subjects, publishes heartbeats (10s), facts (60s), performance (60s), every other sensor (`-sensor`, default 15m, all at start like the agent), event batches (`-events`), polls custom-sensor definitions (5m) and the patch-list scope, answers live queries from the templates (spread over the envelope's `answer_within_ms`, as the agent does), and answers commands (`run_software` after `-cmd-latency`; `deploy_capabilities`/`run_deploy` accepted; settings-style commands acknowledged). `-spread` staggers the start; 0 is a connection storm. Stats are served as JSON on `-ctl` (`/stats`, `/stats?reset=1` to start a new latency window). With the server password it also observes every auth callout (`$SYS.REQ.USER.AUTH` → `$SYS._INBOX` reply) and reports its latency. |
| `api` | Console measurements as the break-glass admin: `-mode latency` (page APIs of Agents, endpoint page, Dashboards, Patches, Deployments with `-c` viewers for `-d`), `-mode query` (a live query to every endpoint, following its SSE stream until all answered), `-mode deploy` (creates the `loadsim-tool` package and installs it on every eligible endpoint, polling the deployment until all actions finish), `-mode token` (prints a new enrollment token). |
| `monitor` | Samples server, Postgres (postmaster and children) and nats-server CPU (% of one core) and RSS, broker connections and JetStream consumer lag (pending + ack-pending) to CSV. `-server-pidfile` and `-nats-container` survive restarts. |
| `msum` | Mean/max of each monitor column over a unix-ms range. |
| `jwtsize` | Builds the legacy shared-credential JWT the callout issues for several enrolled-agent counts and reports its size, signing cost and whether the broker can decode it. Needs no stack. |

## Payloads

The simulator replays a real agent's captured data with its own identity
stamped in, so sizes and shapes are real. Sensors a container cannot
produce (systemd services, pending patches) are synthesized at typical
Ubuntu-server sizes (200 units; ~24 upgrades named after packages in the
captured inventory). Templates contain the capturing host's process list
and certificates; keep them out of the repository.

## A run

The environment the server needs is the usual one (see `deploy/README.md`):
`MUSTRA_NATS_URL`, `MUSTRA_NATS_CA`, `MUSTRA_NATS_USER/PASSWORD`,
`MUSTRA_NATS_CALLOUT_SEED`, `MUSTRA_POSTGRES_DSN`, `MUSTRA_HTTP_ADDR`,
`MUSTRA_PUBLIC_URL` (+ `MUSTRA_ALLOW_INSECURE_PUBLIC_URL=true` for http),
`MUSTRA_COOKIE_SECURE=false`, `MUSTRA_BREAKGLASS_USERNAME/PASSWORD` (skips
first-run setup) and, with development secrets,
`MUSTRA_ALLOW_PLACEHOLDER_SECRETS=true`. The broker is the production
`deploy/nats/nats.conf` with certificates from `deploy/nats/gen-certs.sh`
and the issuer from `deploy/nats/gen-callout-key.sh`; port flags
(`-p`, `-m`) on the nats-server command line override the file's ports
without editing it. The simulator reads `LOADSIM_NATS_URL`,
`LOADSIM_NATS_CA` and `LOADSIM_NATS_SERVER_PASSWORD`.

```sh
loadsim server &                                  # control plane + pprof
loadsim capture -out templates -for 3m &          # then run one real agent
loadsim api -mode token -uses 1000                # x N/1000
loadsim enroll -n 1000 -start 0 -token <tok> -out creds.jsonl
loadsim monitor -server-pidfile server.pid -nats-container nats -out m.csv &
loadsim fleet -n 2000 -creds creds.jsonl -templates templates &
curl -s localhost:18803/stats                      # time to all-registered, callout p50/p99 ...
loadsim api -mode latency -c 4 -d 60s
loadsim api -mode query -kind processes
loadsim api -mode deploy
go tool pprof -top http://127.0.0.1:18802/debug/pprof/profile?seconds=30
```

A connection storm after a broker restart is `docker restart <nats>` with
the fleet running; the re-auth wave of JWT expiry has the same shape,
spread over the last fifth of the lifetime by the callout's jitter.

One process simulates thousands of agents: on the test box (4 cores)
5,000 simulated agents used about 2.7 GB and averaged under one core,
with bursts to two during a connection storm or a fleet-wide query. It
shares the CPU with the system under test, so on one box latencies
include its cost; run it on another machine for cleaner numbers.

Experiment flags: `-fixed-reconnect` (the agent's old fixed 2 s
reconnect wait) and `-answer-spread D` (answer fleet-wide queries within D
instead of the window the server's envelope asks for).
