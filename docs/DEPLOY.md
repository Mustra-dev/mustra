# Software deployment

**Deploy & Patch → Deploy → Software Catalog** is the authoring surface for
software releases. **Action Packages** uses the same versioned engine for Run-only
commands with optional sensor verification; see [the action guide](ACTION-PACKAGES.md).
Existing software and action packages remain available under
**Legacy Packages**. A maintained library of vendor application recipes
is future work; the catalog currently contains operator-authored packages.

## Releases and platforms

Save drafts, test them on one explicitly selected endpoint, then publish. A
published revision is immutable. Subsequent saves create a new draft. Runs keep
their exact revision, scripts, sensor definitions, parameters and dependency
order. Package metadata and targeting remain operator-managed controls.

Each release has variants for Linux, macOS (`darwin` on the wire), and Windows.
Variants can restrict architecture (`amd64`/`arm64`), Linux distribution, and OS
version. Selection must produce exactly one variant. Missing or ambiguous
configurations never fall back to another platform's commands. Each variant can
have its own application version and Install, Update, and Uninstall actions.
Uninstall retains the compatible protocol operation name `remove`.

Secret inputs must be supplied at invocation and cannot have stored defaults.
Shared parameters can be overridden or extended by platform and action.
Supported inputs are text, numeric, select and checkbox values. Scripts read
`MUSTRA_PARAM_name` environment variables; values are not interpolated into
executable source. Python uses the agent's private runtime. Go source uses the
existing isolated builder and checksum-verified platform executables. Windows
also supports Batch and PowerShell; Linux/macOS support Shell.

Schedules pin a revision unless explicitly configured to follow the latest
publication. Self Service has a separate pinned revision and follow-latest
setting. Parameterized software remains excluded from Self Service, preserving
its existing authorization contract. Interactive, scheduled, Self Service and
playbook operations use the same planner and endpoint runner for published
Deploy revisions.

## Checks and dependencies

Requirements decide whether an action is applicable. Detection identifies the
software state; action validation verifies the desired result. Command exit
success alone does not establish deployment success. A validation retry window
supports installers whose observable state settles after the process exits.

Checks support files/directories, file hashes and versions, registry values,
applications, services, processes, OS/architecture, RAM, volume-specific free
space, custom scripts and existing sensors. Compose AND/OR/NOT expressions and
bounded nested if/then/else steps. Script checks return 0 for true, 1 for false;
execution errors and other exit codes are errors. An unavailable, timed-out,
truncated or unparseable sensor never satisfies a check or chooses an else branch.
Platform-specific checks report an error when their mechanism is unavailable.

Sensor row filters evaluate all fields against the same row. Quantifiers are
any, none, all, and matching-row count. Empty successful output can satisfy none;
all requires at least one row unless explicitly configured otherwise. Custom
sensor source, typed output schema and input definitions are pinned when the
package is published. Built-ins execute the installed agent implementation;
agent capability negotiation prevents new jobs being flattened for older agents.

Reusable sensor inputs are defined in the sensor editor and bound to constants
or package parameters in Deploy. Deployment observations are evidence for that
run and do not overwrite scheduled inventory. Historical event checks require a
lookback and complete collection coverage; suppression, polling gaps, agent
restarts and unavailable history cannot establish an absence. History is locally
bounded to 24 hours and 16 MB per source. File history requires an exact path
filter so its monitored-directory coverage can be checked.

Dependencies reference another library package and a published revision. The
planner checks version constraints, targeting, platform support, cycles and
conflicting revisions before dispatch. Missing prerequisites are installed and
validated before the parent. Dependencies can bind their own inputs. Uninstall
does not remove prerequisites. Removing a package required by another recorded
installation is blocked unless an operator explicitly overrides that protection.
Version constraints accept comma-separated bounds such as `>=8, <9`.

## Files

Upload files or import an HTTPS URL into the server library. Imports can use a
vault password credential for HTTP Basic authentication, or a credential with no
username for Bearer authentication. Credentials remain server-side. Direct
endpoint HTTPS downloads require a pinned SHA-256. Authenticated sources should
be imported through the server.

Each action has a **Require software files** checkbox and a file selection;
steps reference only the files they need. An unchecked action downloads no
software payloads. Untaken branches do not fetch their files. Only the selected
OS/architecture's files are sent, and all downloads are verified before use.
Required check/script runtime artifacts are separate from software payloads.
The endpoint cache is bounded and checksum-verified. Waiting downloads retry
within deployment expiry; commands never proceed without required files.
Files referenced by retained revisions cannot be deleted underneath a run.

## Execution and recovery

The agent persists jobs before acknowledging them and serializes software
changes per endpoint. A duplicate dispatch preserves its checkpoints. Completed
steps and branch decisions are retained across restarts. An agent restart during
an uncertain command reports interrupted; it never blindly repeats the installer.
Already accepted local work can continue while the server is unavailable.

Commands default to administrator/system identity. Logged-in-user execution
requires an unambiguous matching session; an absent session waits. It never
silently falls back to elevated execution. Ordinary cancellation prevents later
steps. Force termination is an explicit separate action and may leave partial
installation state. Only steps explicitly marked safe to retry can repeat.
Automatic rollback and loops are outside this design.

Reboot-required exit codes and post-reboot validation have explicit checkpoints.
The default is to wait for a reboot. An operator can allow a required reboot in
the deployment request. Validation that requires reboot runs after the endpoint
reports a different boot time. Expiry bounds waiting work.

## Progress and retention

**Deployment Progress** shows per-endpoint stages, selected branches, downloads,
command stdout/stderr, validation and final outcomes. Installer log paths can be
specified on command steps. Output and attachment truncation is visible. Declared
secret values are redacted before logging. Progress uses the durable action-result
subject and endpoint outbox, independent of the request that started the run.

**Deploy → Settings** configures endpoint and server log limits independently.
Defaults for each endpoint's local log and its server copy are:

- No age-based deletion (`retention_days: 0`).
- 100 MB total ZIP archives, evicting the oldest archives first.
- Rotate at 10 MB of uncompressed log data, preserving event boundaries.
- Compress five completed segments together, verify the ZIP, then remove originals.

MB means 1,000,000 bytes. The active segment and up to four pending segments are
additional uncompressed storage. Deployment outcome summaries are retained
independently of detailed logs. The server provides downloadable endpoint log
archives; the live viewer bounds the displayed event list.

Endpoint logs live in `deploy/logs` beside the agent's bbolt data file. The server
stores its copies under `deploy-logs/<agent-id>` in the package-files directory.
Both directories use restricted filesystem permissions. Server and agent updates
are required for the new protocol; legacy packages preserve their existing path.
