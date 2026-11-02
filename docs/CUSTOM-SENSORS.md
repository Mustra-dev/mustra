# Custom sensors

Define a script and execution type for each applicable platform on **Sensors →
Custom sensors**. A blank script skips that platform. Authoring and endpoint
tests require `deploy.manage`; scripts execute with the agent's rights.

| Platform | Execution types |
| --- | --- |
| Linux, macOS | Shell (`/bin/sh`), Python 3 |
| Windows | Windows PowerShell 5.1, CMD/Batch, Python 3, WMI query (WQL) |

Agents advertise support before the server sends new execution types. Older
agents continue receiving legacy shell/PowerShell definitions; other definitions
show unsupported until the agent is upgraded and refreshes its capabilities.
Agents fetch definitions every five minutes. Saves are not instant fleet runs.

## Starting from a built-in sensor

Open **Sensors → Catalog**, search for a built-in, and expand it. **View built-in
Go source** shows the collector and runtime files shipped with the server;
independently upgraded endpoints may run a different version. The source uses
agent internals and dependencies and is reference material, not a standalone Go
custom sensor.

Each entry also includes per-platform standalone examples with their differences
from the built-in explained. **Clone into custom sensor** copies the example,
output format, interval, and timeout into an unsaved, disabled draft. It requires
`deploy.manage`. Review and edit the commands, test on a selected endpoint, then
save and explicitly enable collection when ready. Cloning leaves the built-in
unchanged and creates an independent custom sensor when saved.

These examples use native tools and text-line output (`value` records); they do
not reproduce every built-in field or integration. Tool availability varies by
endpoint. Certificate examples require choosing a certificate path on Unix;
integrity examples hash one file; performance examples take one sample instead
of keeping a reporting-window buffer. Custom output bounds still apply, so large
inventories may need filtering or a narrower query. The existing editor can turn
an adapted script's structured output into typed fields.

## Python installation

Client install and update scripts install a private Python 3.13.16 runtime beside
the agent. It is invoked by absolute path with isolated mode and site loading
disabled (`-I -S -X utf8`); system Python, `PATH`, user packages, and `PYTHONPATH`
do not choose its interpreter or default imports. The supported authoring
contract is the standard library. This is not a sandbox for operator code.

Builds package pinned [python-build-standalone distributions](https://github.com/astral-sh/python-build-standalone/releases/tag/20261013)
for both architectures of all three OSes, including separate Linux glibc/musl
builds. The upstream URLs and SHA-256 pins live in
`tools/python-runtime/manifest.json`. `make agents` includes runtime packaging;
Docker source builds package the same files. The control plane serves the
runtime, so endpoints need no connection to Python's upstream download sites.
Installers verify checksums and test the staged interpreter before replacing it.
A standalone agent binary installed by hand must have the matching `python/`
directory beside it; otherwise Python sensors report a runtime error.

Update the pins and agent release together for Python security updates. Retain
upstream license files in redistributed archives. Runtime compatibility still
follows the upstream distribution's supported OS versions and system libraries;
cross-compilation alone does not validate execution on an OS.

## Output formats and fields

All execution types normalize into rows containing declared scalar fields.
Fields and types are shared across platforms; format, row selection, and field
paths can differ by platform. Field names use letters, digits, and underscores,
start with a letter, and are unique. `count` and names starting with `_` are
reserved. At most 64 fields, with names up to 64 bytes, are supported. Types
are `string`, `number`, and `bool`.

- **Text lines:** each output line becomes a row with one `value` field. This is
  the default for existing sensors. CRLF and LF are accepted.
- **JSON:** one complete document; select its row object or array with a row
  path. A top-level array needs no path.
- **JSON Lines:** one complete JSON document per nonblank line, using the same
  row/field mapping for each document.
- **Delimited rows:** newline separates records, and the configured character
  separates columns. Optional headers supply source names; otherwise column
  order follows declared fields. Double quotes protect separators/newlines;
  doubled quotes escape a literal quote.
- **Delimited list:** the configured character separates values, each becoming
  a `value` row. The same quoting rules apply.

Comma, pipe, tilde, and tab (`\t` in the editor) are supported delimiters. A
separator is one Unicode character, excluding newline and double quote.

For `{"services":[{"name":"example","memory":{"mb":128}}]}`, choose row path
`services`, declare `name` (string) and `memory_mb` (number), and map
`memory_mb` to `memory.mb`. Dotted paths support numeric array indexes. JSON
Pointer paths such as `/memory/mb` handle literal dots in property names;
`~1` escapes slash and `~0` escapes tilde. `$` selects the row itself. An array
of scalar values maps to a single `value` field. Multiple nested arrays are not
expanded automatically; select one row collection or reshape them in the script.

Missing properties become null, additional properties are ignored, and objects
or arrays cannot silently become scalar strings. JSON must carry declared
native scalar types. Delimited/text numeric fields parse finite numbers;
booleans use `true` or `false`. Any malformed record or type mismatch invalidates
the whole collection for targeting. Empty successful output is distinct from
failure and from never reporting. Use **Parse sample** before fleet collection.

New agents separate stdout (sensor data) and stderr (diagnostics). Collection
captures at most 64 KiB stdout, 16 KiB stderr, and 500 normalized rows. Exceeding
a bound invalidates the result. Each execution has its own temporary directory,
removed afterward, and a timeout. Interval minimum is 60 seconds; timeout is
1–600 seconds, no longer than the interval. Endpoint previews cap timeout at 60
seconds and do not replace scheduled cached results.

## WQL

Paste a local finite inventory query, for example:

```sql
SELECT Name, ProcessId FROM Win32_Process
```

The namespace defaults to `root\cimv2` and is editable. Queries are passed as data
to the endpoint's CIM provider, never evaluated as PowerShell source. Remote
namespaces and intrinsic event queries are outside this feature's scope.

WQL uses the same JSON mapping and declared fields as script output. **Run on
selected endpoint** suggests scalar fields/types from returned rows, including
for `SELECT *`; **Use suggested WQL fields** puts them in the editor for review.
Empty query results cannot establish a schema: define it manually or test an
endpoint with representative data. Array/object properties require explicit
nested mapping; they are not guessed as scalar fields.

ShellCheck and PSScriptAnalyzer continue their existing checks/completion.
Python syntax is parsed without executing it. Batch receives an informational
validation limitation; WQL class/property availability is verified by endpoint
testing. Autocomplete is currently limited to Shell and PowerShell.

## Targeting, questions, and reports

Custom fields appear in the shared field catalog under stable sensor IDs such
as `custom_csn-….name`. Groups, Interact, and saved-question reports consume the
same normalized cache. `count` counts records from a successful current result.

Ordinary conditions retain existing endpoint-wide semantics. Give group
conditions the same **record group** name to require them to match one record
from the same sensor. Each named group combines its conditions with AND. In
Interact, the same-record checkbox groups conditions by sensor. A record view
keeps columns from one sensor together; endpoint summary remains available.
Saved queries retain their record view when exported or included in reports.

A failed, timed-out, unsupported, disabled, or expired sensor is unknown for
value targeting, including negative conditions such as “does not contain.”
Null-only fields likewise do not prove a negative. Maximum age defaults to two
collection intervals plus timeout and can be configured per sensor. The last
successful result is retained separately for inspection. Custom record views
can show that historical result but automatically include status, collection
time, last-attempt time, a historical marker, and the error; historical values
never enter the targeting input.

Schema changes are checked against groups and saved queries (and thus reports
using those questions). Removing/retyping referenced fields or deleting a
referenced sensor is blocked with reference names. Additive fields and script
edits are permitted. Results from a superseded definition are not reused as
current evidence.

Deferred work is tracked in the issue tracker.

## Go programs

Choose **Go (compiled)** on Linux, macOS, or Windows and provide a single
`package main` source file. Use standard-library imports only; external modules,
CGO, additional source files, and `//go:` compiler directives are rejected.
For example, with text output:

```go
package main

import (
    "fmt"
    "runtime"
)

func main() {
    fmt.Println(runtime.GOOS + "/" + runtime.GOARCH)
}
```

Saving compiles both amd64 and arm64 for each configured Go platform before
updating the sensor. Compiler errors appear in the editor; a failed build keeps
the saved definition and its artifacts intact. Syntax highlighting is local;
compiler diagnostics run on save or endpoint test. Go autocomplete is not
provided. Endpoint tests build before dispatch and use the selected endpoint's
OS and architecture. Text, JSON, JSON Lines, and delimited output use the same
schema, parser, freshness rules, and durable scheduled outcomes as other
execution types.

The isolated script-tools container pins Go 1.27.2 and uses `CGO_ENABLED=0`,
`GOTOOLCHAIN=local`, modules disabled, and no network dependency resolution.
There is one concurrent build, a 45-second compiler deadline (50-second process
group deadline), 256 KiB source limit, 16 KiB compiler diagnostics limit, and
16 MiB executable limit. Compose gives tools 1.5 GiB memory, two CPUs, 192 PIDs,
and a 1 GiB noexec scratch filesystem. It has no endpoint or control-plane
credentials. Builds never run the resulting program in the service.

Builds are cached by compiler version, exact source, OS, and architecture under
`$MUSTRA_PACKAGE_FILE_DIR/go-sensors` (default
`/var/lib/mustra/package-files/go-sensors`). Back up that directory together
with the database. Active artifacts are retained; superseded and preview
artifacts are eligible for cleanup 30 days after their last use. Successful
saves retain the previous revision for another 30 days. Cleanup runs during
sensor saves and the server cache is capped at 1 GiB; saves fail without
replacing the sensor when that budget is exhausted. Restore prior source and
save to roll back; retained artifacts are reused, otherwise they are rebuilt.
No automatic rollback changes a sensor's revision or output schema.

Agents advertise custom-sensor capability version 2 before Go dispatch is
allowed. Upgrade agents and wait for their five-minute capability refresh;
older agents report `unsupported`. Configure the endpoint-reachable console
URL in Client Management, as for package-file downloads. Downloads use scoped,
two-hour tokens sent over authenticated NATS and are size-checked and
SHA-256-verified before execution. The agent caches verified executables in its
OS user cache under `mustra/go-sensors`, retaining recent artifacts up to
128 MiB. Every cache hit is verified and copied into a private execution
directory. Deleting the cache while the agent is stopped is safe; the next run
needs a valid download URL. Collection timeouts include download/staging time.
Temporary control-plane outages retain the last fetched definitions; explicitly
empty successful replies remove them.

CI compiles sensor programs for all six targets and tests execution, timeout,
and verified caching on Linux, macOS, and Windows. To run native tests locally
with the pinned toolchain:

```sh
GOTOOLCHAIN=go1.27.2 MUSTRA_GO_BUILD_TEST=1 go test ./internal/sensorbuild ./internal/agent -run 'TestBuildAndRun|TestGoSensor'
GOTOOLCHAIN=go1.27.2 MUSTRA_GO_CROSS_TEST=1 go test ./internal/sensorbuild -run TestSixTargets -timeout 10m
```
