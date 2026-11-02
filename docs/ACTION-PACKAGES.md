# Action Packages

Open **Deploy → Action Packages** to author a versioned command package. One
package covers Windows, macOS, and Linux, optionally with architecture-specific
variants. Unlike software packages, actions have no requirements, installed-state
detection, dependencies, or Install/Update/Uninstall workflows. Every new Run
invocation executes its command, even if a previous invocation succeeded.

## Authoring and versions

Define shared parameters and explicitly shared files, then one command or script
for each platform variant. Variants may add parameters or override defaults;
parameter names and types must stay consistent. Scripts read `MUSTRA_PARAM_name`
environment variables. Inputs are data, not substituted executable source.
Supported languages reuse Deploy: Shell on Linux/macOS, PowerShell or Batch on
Windows, and bundled Python or compiled Go on all supported platforms.

Upload files, import HTTPS sources through the server (optionally using a vault
credential), or specify a direct HTTPS download with a pinned SHA-256. Each
endpoint receives only the selected variant's commands, shared files, and matching
platform/architecture files. Unsupported platforms are skipped; ambiguous variants
are rejected. Files run from the private package directory, also available through
`MUSTRA_PACKAGE_DIR`. Hash verification and a bounded cache apply before execution.

Save an editable draft and test it on one explicitly selected endpoint. Publishing
freezes the complete package version, including all variants, file hashes,
parameters, commands, and custom verification sensor definitions. Changing just
one platform requires a new package version. Published version labels cannot be
reused for that package; older versions remain selectable until retired.

Manual runs default to the published version selected in the editor. Schedules
and playbook steps pin a version by default, with an explicit follow-latest option.
A playbook resolves follow-latest once when launched and retains those IDs in its
run history. Invalid or missing inputs stop the invocation before dispatch.
Targeting and deleted-group protections remain those of the existing deployment
and playbook paths.

## Success and timeouts

- **Exit code:** zero is the default; optionally specify accepted exit codes.
- **Sensor only:** a fresh sensor condition determines success after the command
  completes, even if its exit code is nonzero. The actual exit code is retained.
- **Both:** an accepted exit code and a passing sensor condition are required.

Choose a built-in or custom sensor, bind inputs, and define same-row conditions.
Any, none, all, and matching-count quantifiers retain their existing semantics.
An empty successful collection is evaluated against its condition; collection,
parsing, timeout, or truncation errors cannot pass. A failure to start, download
failure, interruption, or execution timeout cannot be overridden by verification.

Verification starts immediately. An optional 0–3600-second window repeats false
checks every three seconds; it does not repeat the command. Zero means one check,
still bounded by the sensor's collection limit and a 10-minute outer limit.
Custom verification runs under the command's execution identity. Machine sensors
retain agent context. User execution waits for the selected logged-in user and
never silently elevates or switches to a different user for verification.

Download and execution timeouts are independent per variant. Download defaults
to **1800 seconds** for the entire staging phase, including retries; its deadline
survives agent restarts. Execution defaults to **900 seconds**. Zero selects these
bounded defaults, never unlimited execution. Limits cannot exceed 86400 seconds.
Run expiry also bounds waiting for an endpoint/user; actions without an explicit
expiry use 24 hours. Timeout evidence identifies the phase that exceeded its limit.

Actions share the existing per-endpoint deployment queue. Duplicate delivery of
one invocation does not repeat completed work. A new invocation has its own ID
and executes again. Commands do not automatically retry after errors or uncertain
execution. An agent restart during a command reports interruption. Cancel stops
an active action process; it does not undo work already performed.

## Console output and troubleshooting

Every endpoint execution has a unique job ID within its fleet deployment run.
**Deployment Progress → Console output** opens that endpoint's output with
revision, variant/identity evidence, timestamps, stdout/stderr, actual exit code,
verification observations, and final outcome. The view refreshes while active,
supports search through retained history and older-event paging, and provides a
link directly to the run. Download exports only that run's retained JSON events.

Output is written locally and delivered through the durable action-result outbox.
The server persists its own transcript before acknowledging. Server logs remain
readable when an endpoint is offline. Execution and verification outcomes stay
separate from log text; text matching in the log viewer never changes success.

**View endpoint log sensor** invokes the built-in **Action run logs** sensor for
that job. It requires an online upgraded endpoint and returns at most 500 events
and 256 KB from locally retained files/archives. It does not overwrite inventory
or create another action run. The sensor catalog documents the mechanism and
provides source plus a bounded, editable Python example with explicit directory
and job inputs. Native retrieval and server log access require `deploy.manage`.

Retention and rotation are configured in **Deploy → Settings**, separately for
endpoint and server archives. Defaults retain up to 100 MB of compressed history
per endpoint, plus active/pending files. Console streams have a roughly 10 MB
budget including event overhead. A line exceeding 64 KB is omitted with a notice;
subsequent output is retained. Search/display is bounded to 2000 events / 4 MB,
and archive scans are bounded to 512 MB. Explicit notices identify limits; logs
already removed by retention or omitted by output limits cannot be recovered.
Declared secrets are redacted before durable event delivery.

## Retirement and updating consumers

Open a published version's **Used by / retire version** panel to see schedules
and playbook steps that reference it. Select another active version to preview
parameter and operation compatibility. Select compatible references and choose
**Update selected references**. Updates pin them to the chosen version, commit
atomically, and reject a stale preview if an owner changed concurrently. Repair
links open the affected schedule or playbook editor for incompatible inputs.

Retirement preserves definitions, files, and history, but blocks new invocations
of that version. Remaining pinned consumers stay visible in Used by. Existing
dispatched jobs continue. Retiring the current version selects the most recently
created active published revision as the default if one exists. Retiring the
whole package retires every published version and disables the package; inspect
each version's references before doing so. Published versions are not deleted.

## Legacy conversion and compatibility

Legacy actions appear with **Convert to reviewed drafts**. Conversion preserves
the original package and consumers, creates a new action draft, and copies its
file library without implicitly assigning files to every platform. A legacy
Cancel command becomes a separate compensating action draft. Review script
language, replace legacy `$(name)` parameters with environment bindings, review
legacy regex constraints, and explicitly assign files before clearing the review
requirement and publishing. Legacy Update commands remain in the original.
The managed agent-update action retains its special version targeting and is
not converted into an unconditional Run action.

New actions require Deploy protocol capability 2. The server checks capability
before dispatch and reports unsupported agents instead of flattening an action
into a legacy command. Existing version-1 software jobs remain supported by
version-1 agents; the deployed `beacon.*` subjects and broker ACLs are unchanged.

## Example packages

[examples/actions](examples/actions) holds the source of the Linux maintenance
actions, each a Python step run as administrator:
**Fix broken apt repositories** (`fix_apt_repos.py`) and **Hold packages apt
can't upgrade** (`hold_unupgradable.py`). Both take `mode=report` to preview
and have an undo mode. **Upgrade OS release** (`upgrade_os_release.py`) moves
Ubuntu, Debian, or Alpine to the next release, the remedy for a release
flagged **OS end of life** on Risk → Levels. It defaults to `mode=check`, which
changes nothing. It backs up repository files first and refuses Proxmox VE
hosts. Give it an execution timeout of several hours. Publish edits as a new
package version.
