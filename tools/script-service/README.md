# Script analysis and completion

This service supplies custom sensor diagnostics and completion suggestions. The Go
server exposes only authenticated, `deploy.manage`-gated validation/completion
routes. It also repeats validation before saving. No endpoint execution or NATS
protocol changes are involved.

Pinned engines:

| Role | Tool |
| --- | --- |
| Shell diagnostics | ShellCheck 0.11.0, explicitly `--shell=sh --norc`, no external sources |
| PowerShell diagnostics | PSScriptAnalyzer 1.25.0, with `PSUseCompatibleSyntax` targeting 5.1 |
| Shell completion | Bash Language Server 5.6.0 |
| PowerShell completion | PowerShell Editor Services 4.7.0 on PowerShell 7.4.17 |
| LSP framing | `vscode-jsonrpc` 8.2.1 |

`deploy/Dockerfile.script-tools` pins upstream binary checksums and supports Linux
amd64 and arm64. npm versions are locked; an override updates editorconfig's
minimatch dependency to the compatible 10.2.4 security release. There are no
runtime downloads. Upgrade pins, checksums, lockfiles, and real-engine tests
together. Upstream references are in `docs/research/script-editor-packages.md`.

## Deployment

Production Compose starts a separate tools image on an internal network connected
only to the Go server. It has no published port, no credentials, no host mounts,
a read-only filesystem, writable bounded temporary space, and CPU/memory/process
limits. Development Compose uses a small forwarding container to publish port 8091
on localhost for `go run`, while engines retain their internal-only network.
`MUSTRA_SCRIPT_TOOLS_URL` defaults to `http://127.0.0.1:8091` in both server
entrypoints; production Compose supplies `http://script-tools:8091`.

Keep this service private. Its HTTP interface is trusted by network placement;
it is not an independently authenticated public API. Do not attach it to the
NATS/Postgres network or provide the service with control-plane credentials.
PowerShell completion uses a live runspace and upstream argument completers,
which is why isolation applies even though analysis never invokes submitted
scripts. The adapter constructs only initialization, document-update, and
completion requests. Clients cannot choose LSP methods, paths, configuration,
profiles, modules, or shell commands. Child environments are explicitly limited.

## Behavior

The API accepts a maximum 256 KiB per script and 1 MiB per request. Subprocesses
have time and output bounds. The embedded POSIX parser remains a fast syntax
check; ShellCheck supplies further diagnostics. PSScriptAnalyzer parse errors
and incompatible 5.1 syntax block saving. Other analyzer findings remain
advisory, even when the upstream linter calls them errors. Unavailable analysis
returns 503 and does not silently approve a save.

Completion sessions are scoped to the authenticated user plus an opaque editor
identifier. Each session/platform has a separate language-server process and
scratch directory, with at most four cached processes and two-minute idle
expiry. Only one request runs in each session at a time. Disconnects and timeouts
terminate the affected worker; subsequent requests can start a replacement.
No source is logged by the HTTP service, written to a workspace file, or sent to
third-party services. Upstream process logs live only in ephemeral scratch space.

PSScriptAnalyzer runs on Linux PowerShell 7 with its 5.1 compatibility rule; this
is not a Windows endpoint emulator. Missing Windows-only types remain advisory,
and Windows-only modules may be absent from completion results. Shell completion
is supplied by Bash Language Server; `/bin/sh` validation still controls what is
accepted. Neither tool proves that a suggested command exists on every endpoint.

## Validation

Fast tests:

```sh
npm ci --prefix tools/script-service
npm test --prefix tools/script-service
npm test --prefix tools/script-editor
```

Run the actual engines under the same restrictions used in deployment:

```sh
docker build -f deploy/Dockerfile.script-tools -t mustra-script-tools:test .
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --memory 1536m --pids-limit 192 --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -e MUSTRA_SCRIPT_TOOLS_INTEGRATION=1 \
  mustra-script-tools:test node --test '*.test.js'
```

Tests check syntax/advisory separation, 5.1 compatibility, nonexecution during
analysis, context-sensitive cmdlet/parameter/variable/function completion, and
cross-user document isolation. Go tests use an HTTP test service and require no
installed analyzers. CI builds the tools image and runs the actual-engine suite.

Custom sensor requests now include an execution language per platform. Python
uses the same pinned Python 3.13 runtime as clients, calling `ast.parse` in
isolated mode. Batch and WQL return explicit informational limits; endpoint
preview checks WQL class/property availability. Completion remains limited to
Shell and PowerShell, and switching languages does not send Python/WQL/Batch
source to their language servers.
