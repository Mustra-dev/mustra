# Core concepts

What each part of mustra actually does, and why it does it that way. The
[README](../README.md) is the tour; this is the long version, worth the
time because everything in the console is built out of these ideas.

For how it is *assembled* — processes, transport, storage, and the
tradeoffs made along the way — see [ARCHITECTURE.md](ARCHITECTURE.md).

## Sensors — the cached answer

A **sensor** is one thing every agent measures about its own machine, on a
timer. The agent collects it, publishes a snapshot, and the server caches
the most recent one per (endpoint, sensor).

That means the console answers "how many machines are missing patches?"
instantly, from cache, without waking a single endpoint. The trade is that the
answer is *as fresh as the last collection* rather than live — which is
why the Sensors module shows you the age of the data next to the data.

There are thirteen sensors: processes, services, installed applications,
patches, disks, network interfaces, logged-in users, hardware, privileges,
network neighbours, certificates, performance and file integrity.

**Every sensor documents how it collects, per platform.** In **Sensors → Catalog**,
inspect the shipped Go collector source or clone an editable standalone example
into a disabled custom-sensor draft. Examples explain their differences from the
built-in and can be reviewed and tested before enabling. This matters more
than it sounds. "5 patches available" means something different depending on
where it came from:

| Platform | How the patches sensor actually reads it |
|---|---|
| Windows | The Windows Update Agent COM API directly (`Microsoft.Update.Session`), *not* the PSWindowsUpdate module — which isn't installed by default, so this works on a stock box |
| Linux | `apt-get update` then a simulated upgrade, or `dnf check-update` |
| macOS | `softwareupdate -l` |

Two sensor properties are worth knowing:

- **Interval** — how often it is collected. 15 minutes by default, adjustable
  at runtime per sensor without restarting the agent.
- **Time budget** — how long one collection may take before it is killed.
  30 seconds for most sensors; **10 minutes for patches**, because a cold
  Windows Update search routinely exceeds half a minute. (It shared the
  30-second budget until 2026-09-09 and was being killed on nearly every
  tick, so Windows machines showed no patch list at all.)

If you need a genuinely live answer rather than a cached one, that's
**Interact** — it asks every matching endpoint right now, once.

**Custom sensors** are the ones you write. The shipped thirteen answer the
questions everybody has; a custom sensor answers the ones only you have —
"which machines still have that vendor agent", "what is in this config
file". You give it a command per platform, an interval and a timeout:

```
Name:     Pending reboot
Linux:    if [ -f /var/run/reboot-required ]; then echo "reboot pending"; else echo none; fi
Windows:  $cbs = Test-Path 'HKLM:\...\RebootPending'; if ($cbs) { "reboot pending" } else { "none" }
Every:    300s     Timeout: 30s
```

Leave a platform blank to skip it. Each platform has an execution dropdown:
Shell on Linux/macOS, PowerShell or CMD/Batch on Windows, bundled Python 3 on
all platforms, compiled Go programs on all platforms, and local WQL queries on Windows.

Define output as text lines, JSON, JSON Lines, delimited rows, or a delimited
list. Shared field definitions and per-platform mappings turn every execution
type into the same records for groups, Interact, and saved-question reports.
Nested JSON paths, configurable separators, sample parsing, and endpoint tests
are available in the editor. Failed or stale results remain unknown for
targeting; historical results remain inspectable.

See [Custom sensors](CUSTOM-SENSORS.md) for runtime packaging, output
examples, WQL schema discovery, freshness, and same-record conditions.

> **On trust:** a custom sensor runs operator-written code on every endpoint
> with the agent's rights. That is the same boundary a package command
> already crosses deliberately, so it needs the same permission
> (`deploy.manage`) rather than a new one — inventing a separate permission
> would imply a distinction that does not exist. The interval has a 60-second
> floor and the timeout is capped and clamped to the interval, because a
> sensor running every five seconds across a fleet is a self-inflicted denial
> of service.

## Software catalog and deployment workflows

**Deploy → Software Catalog** adds immutable published releases, platform variants,
Install/Update/Uninstall workflows, requirements, reusable sensor checks,
dependencies, selective file downloads, and durable endpoint progress logs.
Configure rotation and retention under **Deploy → Settings**. See the
[Deploy guide](DEPLOY.md) for authoring, recovery, and migration behavior.
Versioned Run-only commands live under **Action Packages**; existing command
packages remain under **Legacy Packages**. See the [Action Packages guide](ACTION-PACKAGES.md).

## The Self Service window — and branding it

The window a person opens on their own machine is laid out in five sections:
**Catalog** (what they may install or request), **Updates** (the agent
update and recent update runs), **History** (finished work, filterable by
Install/Remove/Update), **Activity** (what is running now, plus any notice or
survey waiting on them) and **This Computer**. A pending notice or survey
opens the window on Activity once, and every other section carries a line
pointing at it, because a restart prompt nobody navigates to is not a prompt.

What Catalog offers is the software packages published to Self Service, and
publishing is a setting on the package. Open it under **Deploy → Software
Catalog** and, in its Catalog settings, tick **Offer in Self Service**, pick
the computer groups it is offered to (none means every machine), whether a
machine outside them may request it, and which published version Self
Service installs. A machine is offered a package only on a platform it can
install on, and never one whose install needs parameters. **Deploy → Self
Service** lists what is offered, each row linking to its package, beside the
requests waiting on you: approving one grants that machine that package
without moving it into a group. The catalog items of releases before the
package model were copied into packages once, on upgrade; nothing edits
them any more.

**Deploy → Self Service → Appearance** brands it: organization name, window
title, welcome text, logo, a help link (http, https or mailto only; anything
else would run in the agent's loopback origin), theme, five colours, font,
corner radius, background (waves, contours, dots, grid, an uploaded image or
plain) and its intensity, each section's name, order and visibility, the
section it opens on, the empty-activity message, whether the check-in button
and count badges show, and custom CSS. The editor frames the endpoint's own
page in preview mode, so what it shows is what endpoints render.

Branding reaches agents on the window's state request, and only when it has
changed: the agent sends the version it holds, and the server replies with
the full branding (images included) only when that version is stale.
Agents keep the last copy, so the window stays branded offline. An error
reply never clears it; only a real reply saying "default" does. Images are
shrunk in the browser before upload and capped server-side (logo 256 KB,
background 1 MB). Custom CSS is inserted as text into a `<style>`, so it
cannot carry script.

## Packages — software vs actions

Action Packages publish immutable versions containing shared inputs/files and
per-platform commands. Each endpoint receives only its selected variant and
shared files. Run results retain per-endpoint console output; versions can be
retired with a Used by view to update schedules and playbooks. Legacy packages
retain their older command and parameter syntax until explicitly converted.

A **package** is something mustra knows how to run on an endpoint. There are
two kinds, and the distinction is not cosmetic:

| | **Software package** | **Action package** |
|---|---|---|
| Purpose | Install, update or remove software | Run a command |
| Operations | Install / Update / Remove | Run (cancel stops an active run) |
| Verified by | Software detection and post-action validation | Exit code (default 0), a fresh sensor condition, or both |
| Applicability | installed / update eligible / install eligible / not applicable | Applies wherever it has a command for that OS |
| Named | "Install Visual Studio Code" | "Reboot Computer" |

Using a software package for an action produces nonsense: a reboot has
nothing to detect, and it deploys under the label *"Install Reboot
Computer"*. That is why the kinds are separate.

A software package with a **target version** is *update eligible* wherever
a different version is installed. Typed in by hand, that version only moves
when someone edits it. **Follow latest release** names a GitHub project
(`cloudflare/cloudflared`) instead: the server reads its latest release
(not drafts or pre-releases) on save and every six hours, makes it the
target version, and notifies when it moves, so every endpoint still on the
old one shows Update. A distribution's own revision of that release
(`1.8.2-1`, `1.8.2+ds-3`) counts as the release.

Both kinds support:

- **Per-OS commands** — one package covers Linux, macOS and Windows, and is
  simply not applicable where it has no command.
- **Files** — payloads staged to the endpoint *before* the command runs. The
  command runs **in** the staging directory, so `msiexec /i setup.msi /qn`
  means the file you uploaded; `$MUSTRA_PACKAGE_DIR` holds the absolute path.
  Each file's SHA-256 is checked on the endpoint after download, and a
  staging failure stops the command rather than letting it run against a
  payload that never arrived.
- **Command timeout** — how long the command may run on the endpoint. The
  right answer differs enormously between flushing a DNS cache and
  installing an office suite, so it belongs on the package.
- **Expiry** — after this long, stop trying. Without it, a deployment aimed
  at a machine that is switched off fires at a wildly inappropriate time
  three weeks later.
- **Parameters** — typed inputs substituted into the command as `$(name)`,
  so "restart in N seconds" is *one* package instead of one package per N.

A parameter can be `text`, `numeric` (with min/max), `select` (a fixed list)
or `checkbox`, and can carry a regular expression the value must match.
Values are resolved *before any endpoint is targeted*, so a bad value stops
the deployment rather than reaching half the fleet as a half-substituted
command.

```
Command:  shutdown.exe /r /t $(delay) /c "$(reason)"
Deployed: shutdown.exe /r /t 60 /c "Restart scheduled by mustra"
```

> **On trust:** supplying a parameter is exactly as privileged as writing the
> command it lands in, so it needs the same permission (`deploy.manage`), and
> a package with parameters is deliberately **not** offerable through Self
> Service. The validation is there to stop a typo reaching a thousand
> endpoints — it is a correctness boundary, not a security one.

### The package library

**Add from library** on Software Packages offers ready-made definitions
for widely used applications. Each installs through the platform's own
package manager: winget on Windows (found even though it is not on the
SYSTEM account's path), Homebrew casks on macOS (run as the account that
owns Homebrew, which refuses root) and apt on Debian and Ubuntu. Endpoints
therefore always get the vendor's current signed release, and no binary
passes through mustra. Every entry checks that its package manager exists
(an endpoint without it is "not applicable", not failed), detects and
validates the application by a name pattern over the installed-apps
inventory, and counts "already installed" and "nothing newer" as success.

Adding an entry creates a catalog package with an unpublished draft whose
version is the date it was added. Nothing deploys until someone tests the
draft and publishes it, and it can be edited like any other package. The
library is maintained in mustra's source, through code review; a test
holds every entry to the publish rules.

## Software inventory and usage

**Deploy → Inventory & Usage** is the installed-apps sensor turned into
products. A product is one name across platforms and versions: a Windows
display name loses its trailing version, architecture and per-user markers
("Python 3.12.1 (64-bit)" is *Python*), a publisher loses its corporate
suffix, and a dpkg package loses its `:amd64` qualifier. Two rows only merge
when the cleaned names agree exactly; over-merging would count usage and
cost against the wrong thing.

**Usage** is graded per endpoint from two sources, neither of which runs
anything new on the endpoint: the process starts the fleet already reports
(the Hunt timeline, rolled up per UTC day so a 30-day history survives the
48-hour retention of the raw events) and the endpoint's own record of a
last launch (Windows Prefetch, Spotlight's last-used date on macOS). The
grade counts *days with a launch* inside the window, not launches: *heavy*
is half the days or more, *moderate* more than one a week, *light* at least
once, *unused* none — and *unknown* when mustra cannot tell what would run:
a library, runtime, driver or data package (a *component*), or a product on
Windows/macOS with no known executable. Components are inventoried but
never called unused, and neither is a package whose name has never appeared
as a running process anywhere in the fleet. Add executables on a tracked
product when the built-in table does not know a product. Levels are graded
against the usage history that exists until it reaches the window, so they
settle over the first weeks rather than reading *light* for a month.

**Tracked products** carry a cost per seat per year, extra executables and
the catalog package that removes them. Cost × installed is the estimated
annual cost; cost × unused is the estimated waste. **Remove unused** hands
the endpoints where a product has sat unused for the window to that
package's remove command as an ordinary software deployment — applicability,
maintenance windows, the override permission and per-endpoint results all
apply — after a preview. Endpoints first seen inside the window are skipped:
mustra has not watched them long enough to call anything unused.

The rollup runs a minute after the server starts and every 15 minutes; the
Refresh button runs it now. The table exports as CSV.

## Patch lists, block lists, and what a patch run reports

macOS itself on Apple Silicon installs only through an MDM; everything else needs
only the agent. See [macOS updates](MACOS-UPDATES.md).

A **patch list** says what may be applied; a **block list** says what may
not. Both are rules rather than hand-picked patches — severity, operating
system, name patterns, and a minimum age in days since the fleet first saw
the patch pending — because a policy that has to be edited every Patch
Tuesday is not a policy. The resolution is small enough to state in full:

```
allowed = pending ∩ (union of patch lists covering the endpoint)
          − (union of block lists covering the endpoint)
```

with one deliberate asymmetry: an endpoint no patch list covers is
unrestricted, while block lists always subtract. A fleet with no lists
behaves exactly as it did before lists existed. Every patch deployment —
Deploy now, a schedule firing, a single-device apply — is narrowed this way
before it is sent, and the agent is told the names, not the rules. An agent
older than 0.44.0 cannot apply a subset, so a run the lists would narrow is
refused for it with the reason on the action rather than sent unfiltered.

A patch is **superseded** the moment any endpoint reports a newer version
of it pending. That is a display flag: on Linux the older version is still
what that endpoint's repository offers, so superseded patches are not
excluded from applying, only hidden by default.

A patch action reports its **status** plainly: *waiting*
(held until the endpoint's maintenance window opens, for up to a day),
*downloading*, *installing* (with *– retry N* when the agent waited out a
package manager lock), *pending restart* (installed but not in effect),
*succeeded*, *skipped* (the lists permitted nothing), *failed*, *timed out*
and *expired*. Deployments group devices under those headings. "Awaiting
user acceptance" is not modelled: mustra does not prompt users before
installing patches.

A device whose **check for pending updates fails** keeps its last list, so
the Patch page flags it as **Patch check failing**, with the error and since
when, rather than counting it as up to date. Agents from 0.58.0 report the
outcome of every check; for older agents only Rescan now records a failure.

## Maintenance windows and deployment templates

A **maintenance window** says when the endpoints in a computer group may be
touched: which days, from what time, for how long, in which time zone. The
rule the dispatchers apply is small enough to state in full:

- a window restricts only the endpoints in its groups (a window with no
  groups covers every endpoint), and only while it is in effect: a
  recurring window from the start of its effective date on, a one-time
  window from when it is saved until it closes; an endpoint no enabled
  window in effect covers is unrestricted;
- an endpoint covered by several windows may be touched while *any* of
  them is open;
- a window applies to software deployments, patching, or both.

A queued software deployment outside its window stays queued, and the job's
detail says which window it is waiting for and when that next opens; the
job's expiry still applies, so a window that never opens in time produces
an expired job, not a silently dropped one. Patching is fire-and-forget, so
a patch run skips a covered endpoint with the reason on its action and the
next firing inside the window picks it up. Legacy command packages behave
like patching. A window that crosses midnight belongs to the day it started
on: "Friday 22:00 for four hours" is open at 01:00 Saturday whether or not
Saturday is ticked.

Overriding a window is its own permission, `deploy.override_windows`,
deliberately separate from `deploy.manage`: the person allowed to deploy is
not always the person allowed to deploy at two in the afternoon. The switch
only appears in the console for an account that holds it, and the server
refuses the flag from anyone else.

A **deployment template** is a saved deployment form: package, operation,
rollout plan, parameters, reboot, expiry and the override flag. Pick one
from the deployment form to fill it in, or save the form you just filled
as one; the default template pre-fills every new form. A template stores
the override flag but cannot launder the permission: it is honoured only
for a user who holds it at deploy time, and saving a template with the
flag set needs the permission too.

## Deployments — what actually happened

A **deployment** is one identified event that targeted some set of machines.
Everything that touches endpoints creates one: a patch schedule firing, a
bulk push, a one-off apply to a single machine, a Self Service install. So
there is exactly one place that answers *what has mustra done, to what, on
whose say-so, and did it work.*

Status is **derived from the per-device results**, not stored:

| Status | Meaning |
|---|---|
| `running` | At least one device still has work open |
| `succeeded` | Every device reported success |
| `partial` | Some succeeded, some did not |
| `failed` | Reported failures, no successes |
| `timed out` | The agent stopped waiting — the work *may still be running* on the device |
| `no response` | No device ever reported, and enough time has passed that none will |
| `stalled` | Still open long after it should have finished |

`timed out` is deliberately its own status rather than a failure: a machine
that is still installing is a different problem from one that errored, and
collapsing them together hides which you have.

**A long job reports back when it finishes, not when it starts.** Applying
patches is acknowledged in milliseconds and finishes minutes or hours later,
so the agent publishes the real outcome when the work ends. Until then the
deployment stays open and is watchable live in **Patch → Deployments →
Active**, which refreshes itself every five seconds and stops the moment the
run reaches a terminal status.

## Confidence — what this fleet knows about a package

**Deploy → Software → Confidence** answers a narrow question: when this
package has been deployed *here*, how often did it work, on how many
machines, and what happened to their health afterwards.

Some tools compute a confidence score from install outcomes pooled
across every customer it has. mustra has no such corpus, and a number
derived from one fleet dressed up as one derived from thousands is not a
smaller version of that feature — it is a false one. So the score is local
only and says so.

Three things make it honest:

- **It refuses to answer when it cannot.** Under eight attempts a package
  reports *not enough history* and how much it has, rather than a number.
  Three successes out of three is not 100% confidence, it is no evidence,
  and a score shown without its sample size reads as knowledge.
- **The sample size is always on screen**, beside the score, not behind a
  hover.
- **Health change is one-directional.** A fall in the average health score
  across the endpoints in the day after a successful install costs the
  package points, capped at fifteen. A *rise* earns it nothing: machines
  get better for a hundred reasons that have nothing to do with what was
  installed on them, and crediting a package for one is how a score starts
  flattering itself.

Health is sampled every fifteen minutes and kept for 120 days, because the
performance sensor only keeps its latest snapshot — without a history there
is no "the day before" to compare against. The first useful score therefore
arrives a day or two after upgrading, not immediately.

Patching is scored as one number rather than one per KB, because mustra
records a patch run per endpoint, not per update.

## Real-time detection — what ran, not what is running

The processes sensor is a snapshot on a timer. Anything that runs and exits
between two collections never existed as far as the console is concerned —
and "runs and exits" describes most of what somebody who shouldn't be there
does: a `curl | sh`, a base64-decoded one-liner, a scheduled task that fires
and is gone. Threat Response → **Live Activity** is the half that sees those.

An indicator on a process name is matched **at exec**, so it raises its
finding while the thing is still running. A timed hunt structurally cannot
do that.

**How much it sees depends on the mechanism, so the batch says which one:**

| Platform | Mechanism | What an empty feed proves |
|---|---|---|
| Linux | The kernel's process-events connector over netlink — an exec event the moment a process image is replaced | Nothing ran. A process that lives two milliseconds is still seen |
| Windows, macOS | A fast diff of the process table every few seconds | Nothing ran *that lived longer than the interval*. ETW needs a session and a manifest; macOS's EndpointSecurity needs an entitlement Apple grants to a developer account, not to a binary |

The console says how many endpoints are on which, because the difference
decides whether a quiet feed means a quiet machine.

**Identical invocations collapse, twice.** A hypervisor runs
`systemctl status canary.service` several hundred times a minute. The agent
merges identical ones inside its five-second flush — as far as it can go
without delaying detection — and the server merges again into minute buckets
when the batch lands. Measured on one of yours: 2,743 execs a minute became
1,293 rows after the first pass and a fraction of that after the second, and
the surviving rows say more, because "×587" is a fact where 587 identical
rows are noise.

The second merge costs nothing in detection latency — indicator matching
happens in memory when the batch arrives, before any of it — and it applies
only to rows that matched nothing. A start that matched an indicator is
evidence: it keeps its own row, its own timestamp and its own PID, and is
never folded into anybody's count.

Two counts appear as rows of their own rather than as silence:

- **Suppressed** — past 150 *distinct* commands in a five-second window the
  rest are counted, not sent. The cap bites on genuine variety, which is the
  thing worth capping, rather than on repetition, which collapsing already
  handled.
- **Too fast to identify** — the kernel reported an exec, but the process was
  gone before `/proc` could say what it was. Counted rather than invented: a
  guessed name is worse than a gap, and a box with hundreds of unidentifiable
  execs is itself the signal.

**A matched process is never killed automatically.** mustra can kill one, and
an operator can do it in a click from the finding — but doing it on a name
match with no human in the loop would mean a mistyped indicator takes out a
domain controller's LSASS at three in the morning, with the blast radius of a
false positive set by whoever typed the indicator rather than by anyone
watching.

Retention is split by what a row is worth: a start that **matched an
indicator** is evidence and is kept a month, the rest are a timeline and are
kept 48 hours. Deleting evidence on the same schedule as noise is how an
investigation starting a week later finds nothing. File events are kept a
fortnight.

## File integrity — two halves, on purpose

The hash baseline answers **"has this changed since last time"**. It walks a
curated watched set — authentication, authorization, scheduled execution,
service definitions — hashes it, and the server diffs consecutive snapshots.
Detection happens server-side deliberately: an attacker who can rewrite
`/etc/sudoers` can rewrite a baseline sitting beside it. It also cannot miss
a change made while the agent was down, which is exactly when interesting
changes happen.

Real-time events answer **"it changed just now"**. The agent watches the same
set with inotify / ReadDirectoryChangesW / kqueue and reports within seconds.
Both run; neither replaces the other.

What the real-time half buys, in order of how much it matters:

1. **The hash sweep stops waiting.** An event triggers an immediate
   re-collection, so the diff, its notification and its IOC matching all land
   seconds after the write instead of at the next fifteen-minute interval.
   Everything downstream came along for free.
2. **A dropper is caught while it's still there.** File-path indicators are
   matched against the event as it arrives. A hunt runs on a timer, so a file
   that lands and is deleted between two sweeps is invisible to it.
3. **You get the actual time.** A sweep can only say "sometime in the last
   fifteen minutes".

Three bounds keep an event feed from being worse than none:

- **The watch set is the integrity set, not the filesystem.** Watching `/`
  produces a firehose of build artefacts and log rotation in which the one
  interesting write is invisible. Watch descriptors are capped at 512,
  because the kernel's per-user limit is shared with everything else on the
  box.
- **Events are coalesced per path per flush** (5s). Writing a file produces
  several events; reporting the change four times teaches the reader to skim.
- **Past 200 paths in a window the rest are counted, not sent** — and the
  count is published and shown as its own row. A package install touches
  hundreds of files under `/etc` in a second, and the honest report of that is
  "412 more, suppressed". Dropping them silently would make the console claim
  a quiet minute.

**What this does not tell you is who did it.** An event carries the path, the
operation and the time. Naming the process that wrote the file needs kernel
plumbing mustra doesn't have — ETW on Windows, eBPF or the audit subsystem on
Linux, EndpointSecurity on macOS — and a plausible guess would be worse than
the honest gap.

## Integrity Monitor — watchlists, monitors, labels

The mechanism is the two halves described in
[File integrity](#file-integrity--two-halves-on-purpose): hashing on
the endpoint, diffing on the server, and real-time events. The management
objects around it say what to watch where and which changes are ordinary.

A **watchlist** is a named set of paths (files or directories) and, on
Windows, registry keys, in addition to the built-in set every endpoint
watches. Templates aligned to PCI-DSS, CIS Controls, HIPAA, SOX, NERC-CIP
and Microsoft Exchange are starting points, not certifications. One list
can carry Linux, macOS and Windows paths together; an agent skips a path
its OS does not have. Follow-symlinks, per list, hashes what a link points
at while still recording the target it names.

A **monitor** applies a watchlist to computer groups. The union of an
endpoint's monitors is its watch set: pushed to the agent as a `watch`
command, persisted there, and re-applied every five minutes so an endpoint
that joins a group or restarts converges. Registry keys ride along as
pseudo-files — one entry per key whose hash covers its values and subkey
names — so a changed key is reported the way a changed file is. The
Coverage table shows which endpoints run the set their monitors say and
which need the 0.49.0 agent.

**Labels** are rules evaluated as a change or event is recorded: path
prefix, suffix or substring; kind; computer group; weekday and time window
in a timezone; or "during an open maintenance window" — the change-window
rule. Every matching label tags the change; a label marked *expected*
classifies it as change that needs no investigation, the way a deployment
mustra ran already does. What a rule cannot see is *who* made the change:
no agent attributes a file write to a process or user, so those criteria
are accepted but never match.

One label is seeded on first run: Windows rewrites a built-in scheduled
task's definition file every time the task runs, which on a quiet domain
controller is around a thousand modified files a week that nobody
configured, so modifications under the Microsoft task tree are marked
expected and the seed is applied to change already recorded. A task added
outside that tree, or added rather than rewritten, stays unexpected.

The Changes tab carries the investigation metrics: unexpected against
expected change over seven days, changes awaiting investigation, mean time
to investigate (each unexpected change has an *acknowledge* action),
unexpected change by endpoint, and monitor coverage.

## Access — management rights, action groups, content sets, approvals

A permission says what somebody may do. These say what they may do it
*to*, what they may do it *with*, and when somebody else has to agree
first. All four default to "everything", so a console that never
configures them behaves exactly as it did before.

**Management rights** are the computer groups a role may act on. A user's
scope is the union of their roles' groups; a role with no groups means the
whole fleet, so one unscoped role keeps a user unscoped. An operation that
names an endpoint outside the scope is refused and the endpoints are
named. A fleet-wide operation that names no endpoints — "patch every
Debian box" — is narrowed instead, and says how many it dropped.

**Action groups** are a ceiling on a module rather than on a person:
which endpoints Deploy, Patches, Playbooks, Direct Connect, Enforce or
Reveal may act on at all. An administrator is subject to it too. That is
the point: it is how a domain controller stays out of a module's reach
regardless of who is signed in.

**Content sets** are named collections of packages, dashboards and saved
queries, attached to roles. A role holding no content set may use
everything; one holding a set may deploy only the packages, open only
the dashboards and see only the saved queries its sets name. A set can
also list sensors. Those are restricted only once one of a role's sets
lists sensors, so a set made for packages does not cut a role off from
inventory; from then on the role may get, filter on, build groups from, live-query
and view on an endpoint's page only the sensors its sets name (custom
sensors included), and a question or group rule touching another is
refused with the sensor's name. The endpoint's identity fields (hostname,
OS, IP, site and the like) belong to no sensor and stay readable.
Dashboards draw on mustra's own tables, not on sensors, and are not
affected.

**Approvals** park an operation until somebody else decides it. A policy
matches on module, on the computer groups the operation touches, and on
how many endpoints it targets, so "anything that reaches a domain
controller" and "any patch run over fifty machines" are both expressible.
Approving replays the request verbatim under the identity of whoever asked
for it, so targeting, applicability, maintenance windows and the audit
trail are the same code paths and all name the requester rather than the
approver. You cannot approve your own request; two approvers cannot both
run one; a request nobody decides in eight hours expires, because an
approval of yesterday's fleet is not an approval of today's. Only Deploy,
Patches and Playbooks can be gated — those are the operations mustra can
park and resume exactly as asked, and gating one it could not replay would
be a way to lose work quietly.

**Server-wide permissions.** Some settings reach past any one endpoint:
which internal hosts the server may contact (`network.allowlists`), where
agents download from and connect to (`agents.trust`), who can sign in
(`identity.manage`), the outside systems mustra holds credentials for
(`integrations.manage`), and restoring a backup made elsewhere
(`backups.restore`). Each is its own permission, needed on top of
`settings.manage`, so a role or API token can be given exactly one. They
are as strong as they sound: whoever controls sign-in can sign in as
anyone a provider vouches for, and a restore replaces every account.
Administrators hold them all. Four things stay with an administrator's own
session, because a permission for them would be administrator by another
name: making someone an administrator or granting the admin role, editing
an administrator's account, the break-glass account, and approval-exempt
tokens.

**API tokens** act with exactly the permissions they were given, bounded
on every use by their creator's current permissions, and never count as
an administrator. A token holding `tokens.manage` may create and change
tokens, never wider than itself and only those it made; each such token
records its parent and works only while every token up that chain is live
and only with permissions the whole chain still holds, so revoking a
leaked token takes everything it made with it.

## Signing in — sessions and two-step sign-in

People sign in through an identity provider (OIDC) or with a local account.
The break-glass account is a local account that always works, even when the
identity provider is down.

A session lasts at most 12 hours and ends after an hour with no request,
the limits NIST SP 800-63B sets for AAL2 (`MUSTRA_SESSION_MAX_AGE` and
`MUSTRA_SESSION_IDLE_TIMEOUT` change them). An open console polls, so the
idle limit mostly ends sessions whose tab was closed; the per-person "Sign
Out After User Inactivity" preference covers an open, unattended tab.

**Two-step sign-in** applies to local accounts. After the password, sign-in
asks for a six-digit code from an authenticator app (TOTP, RFC 6238), or one
of ten single-use recovery codes. A code is accepted once: the newest step
used is recorded, so a code seen over someone's shoulder cannot be replayed.
Five wrong codes end the attempt and the password has to be entered again,
which also counts against the sign-in rate limit. The secret is encrypted
with the credential encryption key, bound to its account, so the feature
needs `MUSTRA_CREDENTIAL_ENCRYPTION_KEY`.

Anyone with a local account sets it up under **Preferences → Two-step
sign-in**, where they can also make new recovery codes or turn it off (both
need a current code). Under **Administration → Break-glass account** an
administrator, or someone with `identity.manage`, can require it for every
local account; an account without it then sets it up at its next sign-in,
before it has a session. Turning it off is refused while it is required.
An administrator with `users.manage` can reset someone's authenticator from
the Users list after confirming who is asking; that also signs them out.

SSO accounts are left to the identity provider's own MFA, and API tokens
are not people: neither sees the section.

## Jump Gate — just-in-time access to an endpoint

Direct Connect already required a permission, already wrote every command
to the log *before* sending it, and already honoured management rights and
the shell action group. Jump Gate adds the other half of privileged
access: a reason, somebody else agreeing, a clock, and a way for a person
who may *not* open sessions to read what happened in them.

A **jump policy** says what reaching an endpoint costs — whether a reason
is required, whether an approval is, and how long a window may be. The
highest-priority enabled policy covering the endpoint wins, and an
endpoint no policy covers costs nothing extra.

A **grant** is one person's time-boxed permission to reach one endpoint.
Asking records the reason, raises a console notification and posts to
Discord or Slack when a webhook is configured. Approving starts the clock
at the moment of the decision rather than of the request: a window that
began while nobody was looking is not just-in-time. An approver may
shorten a window but never extend it past its policy, cannot approve their
own request, and can revoke one — which closes any session using it
immediately rather than waiting for a clock it has just been taken off. A
session refuses its next command the moment its window passes, decided by
the clock rather than by the sweeper that happens to run once a minute.

**Access → Sessions** is the auditor view: every recorded session with
what was run in it, why it existed, and who agreed. Reading a transcript
takes `sessions.audit` *or* `deploy.manage` — the person who reviews what
was run on an endpoint should not need the ability to run things on it —
and opening one is itself audited.

There are no new ports and no agent change: the gate sits entirely in
front of the session object that already existed.

Remote desktop (RDP, VNC, SSH through a provider) and **shadowing** a
Windows session go through the same gate. Shadowing is for the case RDP
gets wrong: Remote Desktop signs the user out, while a shadow attaches to
their own session and Windows asks them to allow it first. Mustra finds the
session, applies the checks, records the connection and hands the operator
the Remote Desktop client command; see
[REMOTE-ACCESS.md](REMOTE-ACCESS.md).

## Assets — attributes and what happens when an endpoint goes quiet

An endpoint that stops answering is **retired**, not deleted. The row and
everything recorded about it stay, `managed` becomes false, and Last Seen
says when it was last true. What a decommissioned machine was running is
exactly the question somebody asks months later, and deleting it threw away
the only record. An endpoint that registers or heartbeats again is restored
automatically, with its history. A computer group can target the retired
with `managed equals false`. A separate purge, off by default, is the only
thing that removes inventory, and it counts from when something was
retired rather than from when it went quiet.

**Attributes** are what an operator knows that no sensor reports: owner,
cost centre, location, whether a machine may be rebooted during the day.
Each is text, a number, a date, a boolean or a select list, and each
becomes two things at once — a targeting key (`attr.owner` in a
computer-group rule) and an export column (`attr_owner`), so a report or
dashboard panel can be grouped by one. Values are checked against their
kind, so a number stays a number. An attribute's name cannot change once
created: every group targeting it would break silently. Define them under
Client Management → Assets; set them per machine on the endpoint's
Attributes tab.

## Reveal rule sets and pattern pairs

A **rule set** is a compliance regime as an operator works in it: a few
rules aimed at a few computer groups, enabled or disabled as one thing.
Saving one writes its targeting and its enabled state onto the rules it
names, so the Rules tab never disagrees with it and there is still one
answer to where a rule runs. Deleting a set disables the rules it turned
on, because a scan nobody remembers asking for is worse than no scan.

**Pattern pairs** require two of a rule's patterns to match near each other
in the same file before it reports anything. A sixteen-digit number is a
coincidence; a sixteen-digit number a hundred characters from an expiry
date is a card. Distance is measured between the nearest edges of the two
matches, so order does not matter, and two occurrences of one pattern can
pair with each other. A rule with no pairs behaves exactly as before.

mustra does not build an on-endpoint file index. Each scan walks the files
it is pointed at, which is slower on a rescan than an indexed model
and costs nothing on every endpoint in between.

## Dashboards and custom alerts

**Dashboards** are panels over the same sources Reports and Connect read:
a saved query, or a module's export (endpoints, missing patches,
compliance results, Enforce standing, vulnerabilities, deployments,
playbook runs). A panel is drawn as a number, a donut, bars, a stacked
bar with a second grouping, an area over time, a table, or text with
console links, and carries a filter, an optional computer-group
restriction, and a highlight threshold (conditional formatting). The
editor previews any panel before it is saved; every chart has a rows view
one click away. A dashboard is shared unless kept private; anyone can
clone one, and its author or an administrator edits it.

Every panel is sampled every 15 minutes into `panel_samples`; area panels
and the 24 hour / 7 / 30 / 90 day timeframes are drawn from those samples
rather than recomputed. Two starter dashboards, *Fleet overview* and
*Security posture*, are seeded on a fresh install and are ordinary
dashboards afterwards.

**Home** opens with one dashboard at full size and a *Dashboard List* of
up to five micro-chart cards; clicking a card swaps it into the full slot.
The row above filters by computer group and timeframe or shows only
highlighted panels. Which dashboards Home shows is a per-user preference
set from any dashboard's *Show on Home* and *Add to Home list*.

**Custom alerts** (Dashboards → Alerts) are thresholds on a panel: its
count, or one slice's count or share, with a severity. While one holds it
is a Guide notification linking to the dashboard; when it stops holding it
clears itself, like every other Guide item. Alerts are evaluated with the
Guide every two minutes and on demand. Because they write into everyone's
tray, managing them takes `settings.manage`.

## Reports — a page for somebody who isn't here

Everything in mustra is already exportable, which is not the same thing. An
export is a stream of rows for a machine; a report is a page for a person —
sections with titles, counts rolled up, and the date it was true on it.

A **section** picks a source, optionally filters it, and is either a table or
a roll-up:

```
Fleet by platform            endpoints    count by: platform
Endpoints missing patches    patches      count by: hostname
Compliance failures          compliance   where state contains "fail", 20 rows
Settings mustra gave up on   enforce      where state contains "failing"
```

`count by` is most of what makes a report a report: "24 Debian, 12 Windows"
instead of thirty-six rows. A blank value gets its own `(not set)` bucket
rather than being folded away — "how many endpoints have no site" is a real
question and usually an unwelcome answer. Filters are deliberately small: one
column, one substring, `!` to exclude. Anything more expressive belongs in a
saved query, which is a real query language and already exists — and
`question` is one of the sources.

Sources are Connect's, reused whole, with the incremental cursor deliberately
blank: an export sends what's new since last time, and a report doing that
would describe the week as empty because nothing changed since Tuesday.
Nothing wakes an endpoint to build a report — the patches section reads the
cached sensor, like everything else.

**Renderings are kept, not regenerated.** The point of a monthly report is
being able to say what the fleet looked like on the first; re-running today's
query against today's data answers a different question. The last 30 of each
are retained and older ones pruned — a shelf, not an archive.

Delivery reuses Connect's destinations, with one difference that matters: a
**file** destination gets the full standalone HTML document (styles inlined,
so it stays readable when it's forwarded on), an **email** gets that document
and the digest as its plain-text part, while a **webhook** gets the text
digest. Write files to `/var/lib/mustra/output/` — that path is a volume
that survives a redeploy, and anywhere else lives inside the server container
and is lost the next time it's rebuilt. A Discord channel is not a place to paste eight hundred lines of
HTML, and the digest — section names, row counts, the top few buckets of each
roll-up — is what somebody reads on a phone anyway.

A section that can't be built says so *in the document* rather than being
dropped, because a report that looks complete and isn't is the one thing a
report must never be.

## Playbooks — several things in order

Everything else in mustra is one action against many endpoints. A playbook is
several actions against each endpoint, in order, deciding at each step whether
the next one still makes sense:

```
1. Notify        "Updates are being installed"        always,  carry on if it fails
2. Patch         apply pending patches                always,  stop here if it fails
3. Check         is a reboot pending?                 if 2 succeeded
4. Package       Reboot                               if 3 succeeded (i.e. one is pending)
5. Wait          30s, then until it checks in again   if 4 succeeded
6. Check         verify the reboot cleared            if 5 succeeded
```

Nothing new reaches the endpoint — every step is something mustra could
already do. What a playbook adds is the patience to wait for a patch to
*actually finish* before deciding whether to reboot. `apply_patches`
acknowledges in milliseconds and reports what really happened minutes or
hours later, so "patch then verify" by hand means a person watching a page;
here the server does the waiting.

**One run at a time.** A schedule and a person can both start the same
playbook, and two passes at once would mean the same endpoint getting the
same reboot step twice, concurrently — so the second is refused. Two
*different* playbooks running together is fine, and usually the point.

**Each endpoint walks the steps on its own.** A run is not a fleet-wide state
machine: machine seven can be waiting to come back from a reboot while
machine three has already finished. Otherwise the slowest endpoint sets the
pace and one bad endpoint stops the other thirty-eight. Five endpoints walk
at a time — deliberately low, because a step can be "reboot", and rebooting
the fleet in parallel is not orchestration, it's an outage.

Seven step kinds: **patch** (apply and wait for the real outcome),
**package** (any software or action package, with parameters), **check** (a
gate, using the same rule dialect Comply and Enforce use), **wait**,
**enforce** (run one Enforce policy against this endpoint), **notify**, and
**approval** (stop until a second person says yes).

Three details that decide whether it behaves sensibly at 3am:

- **"Wait until it checks in again" means a heartbeat newer than the moment
  the step started** — which is how a reboot is actually detected. A plain
  "is it online" check sails straight past a machine that hasn't rebooted
  yet, and the playbook would verify the old state and call it done.
- **A check that can't be evaluated fails the gate**, rather than passing it.
  A gate that opens because nobody could read it is worse than one that stays
  shut — the same reason `unknown` exists in Comply.
- **A package with no command for an endpoint's platform makes that step
  skipped, not failed**, so a mixed-platform playbook doesn't halt on its
  first step.
- **A step set to "carry on anyway" doesn't fail the endpoint.** It's a red
  cell in the grid, because the step really did fail — but the author has
  declared it survivable, and a run status that ignores that declaration
  makes the setting meaningless. It matters most for gates: "is a reboot
  pending?" is *supposed* to fail on most machines, and counting it would
  paint every run red forever.

Skipped steps are recorded with the reason, never left absent: "why did
nobody get the reboot" is answered by a row saying the check before it
failed, and not at all by a gap in the table. A run shows as a live grid of
endpoints × steps while it's going, and appears in Deployments alongside
patch and software jobs, because it is one.

The editor also draws the steps as a **flow**, with the conditions on the
edges. It is a picture of the form above it, not a second place to author
them — a drag-and-drop canvas would be a second editor for the same nine
fields, and the thing a list of steps actually hides is the branching, which
is what the picture shows.

#### An approval step

A playbook can stop and wait for somebody else. **One decision per run, not
per endpoint** — asking forty people to approve the same change forty times
is not a gate, it's a denial of service. Every endpoint that reaches the step
joins the same pending decision.

The parked run lives in the database, not in a goroutine. An approval that
arrives tomorrow, or after a restart, resumes each endpoint from exactly the
step it stopped at — using the steps the run **froze when it started**, not
whatever the playbook says now, because what was approved is what should run.
A rejected or expired gate closes the run and records every remaining step as
skipped with the reason.

Deciding needs **`approvals.decide`**, never `deploy.manage`, and the person
who started the run cannot approve it. An approval whose only requirement is
being allowed to do the thing yourself is not an approval.

#### What starts a playbook

A schedule, a person, a **Guide event**, or an **outside system posting to a
URL**. Playbooks → Triggers.

An event trigger matches on source, severity and a substring of the title;
every field left empty means *any*, so a trigger with nothing set fires on
everything — which the page says out loud rather than letting you arrive at
it by leaving boxes blank.

Two guards are not optional, because a trigger is the fleet being acted on by
something that is not a person:

- **A Guide item raised by Playbooks never fires a trigger.** A playbook that
  raises a notification that starts a playbook is a loop that runs until
  somebody notices, and the fleet is what it runs on in the meantime.
- **Every trigger has a cooldown**, floored at 60 seconds. A vulnerability
  feed refresh raises hundreds of Guide items in the same second; without a
  cooldown that is hundreds of attempts to launch the same playbook. It is
  claimed with a single conditional `UPDATE`, so two events in the same
  millisecond cannot both pass a read-then-write check.

A webhook trigger's token is the entire credential: generated server-side,
shown once at creation, never returned again. Every answer that is not "it
fired" is byte-for-byte identical — `200 {"accepted": false}` — so a token
that does not exist cannot be told apart from a real one inside its cooldown.
A guesser who can tell those apart has just been told the token is right.

## Enforce — holding a setting in place

Comply tells you the firewall is off. Enforce turns it back on, on a timer,
with nobody watching — which makes it the sharpest thing in here, and most of
its design is about that.

A **policy** targets a computer group and a platform, and contains
**settings**. A setting is two halves:

```
Name:      Host firewall is active
Rules:     c:systemctl is-active ufw -> r:^active
Fix (Linux):   systemctl enable --now ufw
Fix (Windows): Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
```

The rules are the same dialect Comply uses, deliberately: that engine already
reads files, commands, processes and the Windows registry, and a second way
to say "the firewall is on" would be two dialects to learn and two to get
wrong. Leave a platform's fix blank and the setting reports drift there
rather than pretending it was handled.

Four rules make this safe enough to leave running:

- **Report mode is the default.** A new policy checks and records and changes
  nothing until somebody deliberately switches it to enforce. There is also a
  **Dry run** button, which forces one pass into report mode whatever the
  policy says — the way to find out what an enforcing policy *would* do.
- **The endpoint re-checks after fixing.** A remediation exiting zero says
  the command ran, not that the setting took: `systemctl enable ufw` succeeds
  on a machine where ufw isn't installed. Only the second check decides
  whether the state is `remediated` or `failed`. A console that is green
  while the fleet is wrong is worse than one that is visibly red, because
  nobody goes looking.
- **It gives up.** A fix that fails three times in a row on one endpoint
  stops being sent there, and the state becomes `given up`. Without that, a
  broken command runs every thirty minutes on every affected machine forever
  — an engine that generates load in exact proportion to how wrong it is.
  Editing the policy's settings clears the counters, as does **Reset
  history**, so fixing the command is enough to make it try again.
- **Every remediation is audited.** `enforce.remediate`, with the policy, the
  setting, the endpoint and the outcome. This is the answer to "what touched
  my server at 3am", and it's the reason enforcement is tolerable at all.

States are `compliant`, `drifted`, `remediated`, `failed`, `given up` and
`unknown` — because "it was wrong and I fixed it" and "it was wrong and I
couldn't" are the two answers anybody actually wants, and both are invisible
in a boolean. `unknown` is never remediated: acting on an answer you don't
have is how enforcement breaks machines.

Deleting a computer group does **not** widen a policy to the whole fleet.
Anything targeted at it is disabled in the same transaction and marked as
having lost its targeting, so it targets *nothing* until somebody chooses
again — and the console says so rather than showing it as "Every endpoint".
Silently going from "the twelve servers" to "all thirty-nine" because
somebody tidied up a group is exactly the surprise this must never spring.
(It sprang it once: the schema said this was handled and the code didn't
implement it. A deleted group widened a policy from 1 endpoint to 37 in
testing, which is how it was found.)

#### Typed policies, posture, and recovery keys

Four policy types come with their own editor — **Windows Firewall**,
**BitLocker**, **Microsoft Defender** and **AppLocker** — because the
settings that matter on a Windows fleet are the same everywhere and nobody
should have to type `Get-NetFirewallProfile` into a rule box. Each form
compiles into ordinary settings (the editor shows them, read-only), so the
engine above is the only engine: report mode, dry run, the give-up counter
and the audit trail apply unchanged. A BitLocker policy treats *encrypting*
as protected and keeps a separate report-only setting drifted until the
volume is fully encrypted, so a machine that is busy is neither a failure
that burns attempts nor a success claimed early.

The **security posture** sensor reports firewall, disk encryption,
antimalware and application control on every platform — LUKS and FileVault
included — whether or not a policy holds them. It feeds **Enforce →
Coverage** (fleet percentages, per endpoint), the `security_posture.*` fields
for computer groups, and a tab on each endpoint.

On Windows the same sensor carries **BitLocker recovery passwords**. The
server encrypts them with the credential encryption key and strips them
before the snapshot is stored, so the sensor cache never holds one. Reading
a password needs `enforce.recovery_keys`, a permission of its own, and every
read is an audit event (`bitlocker.key_view`) naming who, which machine and
which key. With no credential encryption key configured the passwords are
discarded, loudly. There is no self-service recovery portal: a user who is
locked out asks an operator, which is the trade this fleet wants.

## Client Management — status, health, profiles

The fleet's own agents are a managed thing, not a script somebody runs.
**Client Status** is every client's registration and connectivity — agent
id, addresses, version, when it registered, when it last spoke, the profile
that governs it and the settings it is actually running — exportable as CSV
or JSON, with actions on a selection. **Client Health** is the agent's own
operation as named checks: offline, behind the served version, facts stale,
a core sensor missing or stale, patch scan stale; plus settings drift, all
filterable by computer group.

A **client configuration profile** pushes settings to the agents in a
group: sensor interval, log level, and a random delay that spreads a
thousand agents sharing one interval across it rather than into the same
second. Where profiles overlap the highest priority wins. A profile is a
standing state, not a one-off push: it is re-applied every five minutes,
and every facts message carries the settings the agent runs with, so drift
is measured rather than assumed. Each profile names an **upgrade ring**;
Client Health upgrades the fleet ring by ring, and ring 0 is the deferral
ring a roll never reaches unless you say so.

## Exploitability, levels, and remediation

Findings come from the packages each Debian, Ubuntu and Alpine endpoint
reports. Their distributions file security advisories by **source
package** (`openssl`, not `libssl3t64`; `glibc`, not `libc6`), so the scan
looks each package up by the source package and version it was built from,
and records the finding against every installed package built from it,
under the name its package manager uses, which is what a remediation then
patches. A host's count is of vulnerabilities, not of packages: one
openssl advisory is one finding however many openssl packages are
installed. Alpine and Ubuntu advisories are looked up for the host's own
release (`Alpine:v3.22`, `Ubuntu:25.10`), taken from its version, so an
advisory fixed in that release does not count because another release is
still affected. An Ubuntu endpoint's findings are graded by **Ubuntu's
own priority** for each advisory rather than by CVSS: CVSS rates a flaw in
the abstract, Ubuntu's priority how it bears on Ubuntu as shipped. A
*negligible* one is set aside as not actionable, as Debian's tracker
verdicts set findings aside on Debian endpoints; an advisory without a
priority keeps its CVSS grade. Packages built from the kernel's source that are not a
kernel (headers, `linux-libc-dev`, `bpftool`) are not matched against the
kernel's advisories, which concern the running kernel; the kernel image
itself is.

**OS end of life.** A release its vendor no longer supports shows as
hundreds of findings that will never be fixed for it (Ubuntu marks them
"ignored: end of life"): a patching backlog in appearance, an OS upgrade in
fact. Support dates for Ubuntu, Debian, Alpine and macOS come from
endoflife.date, refreshed daily and kept across restarts; the end is the
end of security support, so a Debian release past its regular support but
covered by Debian LTS is not flagged. Risk → Levels shows each endpoint's
release, and one past its end carries **OS end of life** with the date and
what it means; the Guide raises those endpoints, and those whose support
ends within 90 days. The **Upgrade OS release** action
([docs/examples/actions](examples/actions)) moves an Ubuntu, Debian or
Alpine endpoint to its next release.

A vulnerability list is a backlog; the useful question is which of them
somebody is actually using. Two public feeds answer it: **CISA's Known
Exploited Vulnerabilities** catalogue, downloaded every six hours, and
**EPSS**, FIRST's per-CVE probability of exploitation in the next thirty
days, downloaded daily (FIRST publishes it once a day). Every
finding is joined to them through the CVE aliases OSV publishes, so the
Vulnerabilities table carries a KEV badge (with ransomware use where CISA
records it) and an EPSS figure, and **Exploitability** lists just the
findings that are in KEV or score one percent or more — with CISA's name for
the flaw, the due date, the affected endpoints and the fix. A KEV entry on
the fleet is a Guide item, critical when it is used in ransomware.

**Levels** states one vulnerability level per endpoint the way Comply
defines it, freshness included: the worst actionable severity from a scan
under thirty days old; *no vulnerabilities* for a clean fresh scan; *not
scored* when findings have no severity; *not scanned* for anything older,
never scanned, or on a platform the scanner does not cover (it covers
Debian, Ubuntu and Alpine packages). A level from a stale scan is a guess
wearing a label, so it is not stated.

**Remediation** groups findings by the package that fixes them: the
published fixed versions, which endpoints already have a pending patch for
that package, the catalog package of the same name, and a button that
deploys pending patches to exactly those endpoints — through the same path
as every other patch deployment, so patch lists and maintenance windows
apply.

## The recorder and Signals — what it did, and rules over it

Process and file events say what ran and what changed. The **recorder**
adds what it did: **network connections** (every platform, a diff of the
connection table every five seconds), **logons** (the journal on Linux, the
Security log on Windows, `last` on macOS), **registry changes** to the
persistence keys on Windows, and **DNS resolutions** from the Windows client
cache — with Sysmon's events taken as well wherever Sysmon is installed. On
Windows the Security and Sysmon logs are followed by event log
subscription, so each event arrives as it is written, and the DNS cache is
read in-process every fifteen seconds; nothing starts a process. A lookup
is one event, its answer listing the CNAMEs it passed through and its
addresses. The
same three bounds apply as to the other feeds: identical events collapse
inside a flush, a batch is capped, and what was dropped is counted and
shown. Each batch names the mechanism per kind, and the console repeats it,
because "no DNS events" from a Linux box means the agent cannot see them,
not that there were none.

A **signal** is a rule over those events:

```
process.name contains 'powershell' AND process.command_line contains '-enc'
registry.key contains '\CurrentVersion\Run' AND registry.op != 'delete'
network.direction equals 'connect' AND network.remote_port in [4444, 1337]
logon.outcome equals 'failure' AND logon.reason contains 'no such user'
```

AND, OR, NOT and parentheses; contains, starts with, ends with, equals,
matches (a regular expression), in, and numeric comparisons; strings compare
without case. A rule is checked when saved — a property that does not exist
is refused rather than matching nothing forever — and can be tested against
the last thousand events of each kind before it is enabled. It is then
evaluated on every event as it arrives, from all six objects, on the same
path the indicator match uses. A **finding** is one signal on one endpoint
with a count, and the first hit raises a Guide notification. Nothing fires
that nobody wrote: the thirteen examples are offered, not seeded.

## Live response — one endpoint, mid-incident

Everything above is fleet-shaped: ask thirty-nine machines a question, deploy
to a hundred. Live response is the opposite shape — one machine, right now,
because something on it is wrong.

Open an endpoint and the **Processes** tab is a tree rather than a list. That
is the whole point: a row saying `powershell.exe` tells you nothing, while

```
winword.exe
  └─ cmd.exe
       └─ powershell.exe  -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA…
```

tells you exactly what happened and to whom. The agent reports each process's
parent PID and (truncated) command line for this reason. Filter it and the
matches keep their ancestors, so you never see a hit without its lineage.

The tab opens on the cached snapshot like every other sensor view, and
**Refresh live** asks that one endpoint right now. During an incident the
difference is the whole point: a process that started four minutes ago isn't
in the cache yet, and it's exactly the one you came to find. (It uses the
same fixed query kind Interact does — nothing arbitrary runs on the
endpoint.)

**Kill** ends a process. Two things about it are deliberate:

- **The PID-reuse guard.** A PID is only meaningful at the instant it was
  observed. Between the collection that showed something suspicious and the
  click, that number may have been recycled onto something unrelated —
  possibly something holding the machine up. So the console sends the *name*
  it saw alongside the PID, and the agent refuses if they no longer agree:
  `pid 4812 is now "sqlservr.exe", not "powershell.exe" — the pid was reused,
  so nothing was killed`. The agent also refuses PID 1 and itself.
- **It is a deployment.** A kill records a run and an action exactly like a
  patch job, and is written to the audit log *before* it is sent — "who
  stopped that, and when" is precisely the question asked afterwards, and
  answering it from a different place with a different shape is how one audit
  trail becomes several partial ones. It needs `deploy.manage`; without it
  the tab is read-only.

Right after a kill the agent republishes the processes sensor, so the tab
redraws showing the process actually gone rather than the stale snapshot it
was just in.

What this is *not* is real-time detection. Nothing on the endpoint watches
the kernel, so mustra still learns about a process at the next collection,
not the moment it starts.

## Agents — and updating them

Agents are **not auto-updated**, deliberately. A fleet that silently replaces
its own agent binary is a fleet that can silently break, all at once, with no
one having decided anything. So an update is offered rather than applied.

**Self Service** on the endpoint says when the agent is behind and offers a
one-click update. The command comes from the server, never from the local
window — the same rule that keeps a package name server-resolved.

The updater has to outlive the service it replaces (a service cannot
overwrite its own running binary), so it is deliberately detached, and
differently on each platform:

| Platform | Why the obvious thing fails |
|---|---|
| Linux (systemd) | systemd kills a unit's whole control group on stop, so a plain background child dies the instant the installer stops the agent. `systemd-run` puts the updater in its own transient unit. |
| Linux (OpenRC) | The agent runs under `supervise-daemon` (Alpine and the like). The installer stops and starts it with `rc-service`; the updater survives that in a session of its own (`setsid`). |
| Windows | A service's children can be terminated with the service, so `Start-Process` creates a genuinely independent process. |
| Other | `setsid` — a new session is not in this process's group and survives it. |

It reuses the install script rather than inventing an update path, because
the installer already solves stopping, replacing and restarting *while
preserving the identity database*. Lose that and the endpoint comes back as a
brand-new machine with no history.

To update many at once, run the install one-liner over SSH — the same command
that installs is the one that updates.

### When an update takes the agent down

The updater rolls back a build that does not start within three minutes,
but only while the updater survives. For the rest (a reboot in the middle
of the swap, an updater antivirus kills, a build that crash-loops later),
each agent keeps a **last-known-good** copy of itself beside its binary
(`mustra-agent.lkg`, `mustra-agent.lkg.exe`), taken once a build has run
for ten minutes, and registers a recovery job with the OS: a systemd
timer (`mustra-agent-recover.timer`), a cron entry where there is no
systemd, a launchd job (`com.mustra.agent.recover`) or a scheduled task
(`\mustra\agent recovery`, as SYSTEM). Every ten minutes it runs the
known-good copy, which looks at the heartbeat the agent writes each minute.
If the heartbeat is more than fifteen minutes old, and still is ninety
seconds later, it restarts the service, and if the installed build is not
the known-good one, it puts that back first (keeping the failed binary as
`mustra-agent.failed`). The agent logs what happened at its next start;
the job's own log is `recover.log` in the data directory.

It never restarts a service that has been **disabled**: that is how to keep
an agent down on purpose (`systemctl disable --now mustra-agent`, setting
the Windows service to Disabled, `launchctl disable system/com.mustra.agent`).
Stopping it without disabling it brings it back within about 25 minutes.
Uninstalling removes the job; an agent uninstalled with an older
uninstaller leaves a job that finds nothing to run.

On Windows endpoints under Defender's "advanced protection against
ransomware" ASR rule, add `C:\Program Files\mustra-agent\mustra-agent.lkg.exe`
to the same ASR exclusion as the updater, or the rule may block the copy.

## Notifications — two audiences

mustra tells two different people things, and they are not the same feature.

**Console notifications** (the bell, top right) are for the operator. A
deployment that half-failed at 3am is already in the audit log, but an audit
log answers questions somebody thought to ask — nobody reads one hoping to be
surprised. Failures go looking for you. Successes are deliberately silent: a
tray that fills with things that went fine is a tray people stop opening.

**End-user notifications** are for the person at the endpoint, and come in
two kinds:

| | **Notice** | **Restart** |
|---|---|---|
| Purpose | Tells them something | Asks them to reboot |
| Buttons | Acknowledge | Restart now, plus postponements |
| Extras | — | Countdown, gentle warning, deadline |

Postponement options are a **fixed list**, not a free-text box — "remind me
later" with no bound is how a machine goes unpatched for a month.

They are delivered two ways, and the two are not redundant. The **Self
Service window is reliable**: it is already a local web UI the agent serves,
so it works identically everywhere and the message survives until answered. A
**native toast is best effort** — a service cannot reliably draw in a user's
session, which is what session 0 isolation exists to prevent — so it is fired
and forgotten. A toast that fails to appear never loses the message.

Sending one creates a **deployment**, like pushing a patch, and the action
stays open until the person answers. "Who did we tell and what did they say"
is the same question as "who did we patch and did it work", and it deserves
one answer in one place.

## Engage — asking, rather than telling

A notification tells somebody something. **Engage** asks them something:
ratings of 1–5, a choice from a list, or free text, rendered in the same
Self Service window, with the same toast as a nudge.

The delivery problem is identical, so the machinery is shared. The *answer*
model is not: a notice is answered from a closed vocabulary the agent acts
on, and a survey is answered in the person's own terms.

**The sentiment score is arithmetic you can check.** Ratings map 1–5 onto
0–100. A choice counts only where you have marked which options are the
good ones — deciding on your behalf that "Other" means unhappy would be an
opinion, not a measurement. **Free text is never scored**, because a mood
inferred from prose by counting words is a guess wearing a number's
clothes, and a number nobody can check is the thing a score is meant to
replace. The per-question breakdown is on the page beside the score, so the
single number never has to be taken on faith.

Four things it refuses to do:

- **Score fewer than five answers.** Same rule as Confidence. Too few
  replies is not a low score, it is no score.
- **Hide a thin response rate.** Below 30% the reason says so in words. The
  people who answer an unprompted survey are rarely the indifferent ones,
  and a number carrying no denominator invites being read as the fleet's
  mood when it is five people's.
- **Treat a decline as unhappiness.** "No thanks" is a real button and a
  stored answer. It is counted and never scored — it is the only thing
  separating a question nobody wanted from one nobody was asked, and
  scoring it would invent an opinion somebody deliberately withheld.
- **Flatter either half of the rate.** Only an endpoint that actually
  *accepted* the survey joins the denominator — answers ÷ answers is always
  100%. And the numerator counts machines, not replies: one endpoint asked
  once and answering twice is one reply's worth of coverage, not two. An
  anonymous survey records no endpoint at all, so it cannot compute that
  rate; it reports replies per machine asked and says that is what it is.

**Anonymity is enforced at the endpoint.** When a survey is marked
anonymous, the agent drops the user name and the machine identity before
anything leaves that machine, so the promise made on the screen the person
read is the one kept — the server has nothing to forget to ignore. The
console also rounds an anonymous response's timestamp to the day, because
on a small fleet a precise time is an identity.

Offline endpoints are skipped rather than queued, as with a notice: a
question that surfaces whenever the laptop next wakes asks about something
the person has stopped thinking about.

## Guide — what needs you

A bell in the top bar, and a page behind it. Everything the console wants
an operator to know lands here rather than on the page that produced it:
a job outstanding on an endpoint that stopped answering, a service
certificate about to expire, agents behind the served version, an endpoint
offline for a day, a Mac without Full Disk Access, files with confirmed
sensitive data, a critical Impact finding, a failing directory sync,
endpoints with critical vulnerabilities. Two kinds:
**guidance** links to the fix; an **observation** is something to look at.

The tray is honest by construction. Evaluators run every two minutes and
write one item per condition, keyed so a condition that persists is one
item that refreshes; whatever an evaluator no longer sees is resolved, so
the list empties itself when the world improves rather than accumulating
history nobody clears. A dismissed item stays dismissed while its condition
persists and comes back if the condition goes away and returns — you
dismissed the old occurrence, not the next one.

## Reveal — sensitive data where it lives

Which endpoints hold card numbers, Social Security numbers, private keys,
cloud credentials — and in which files? A **rule** names patterns, roots
per operating system, the endpoints to cover and how often. The agent
walks the files on the endpoint, runs the patterns there, and confirms
matches with **validators**: the Luhn check for payment cards (and, for a
bare run of digits, a word like *card* or *visa* nearby), the Social
Security Administration's structural rules for SSNs, mod-97 for IBANs. A
version string with sixteen digits is not a finding.

What comes back is the path, the size, the modification time and a masked
snippet — `card: **** **** **** 1111` — so an operator can recognise a
file without the number leaving the machine. The file's contents never do.
Office documents are read through their XML; binaries and PDFs are skipped
and counted. Scans are budgeted (200,000 files, fifteen minutes, 5,000
matches) and yield between files, and the default file set is documents,
data and configuration rather than source code, which assigns variables
called `password` all day long.

Ten built-in patterns, custom expressions in RE2 syntax (no lookahead, so
nothing an operator writes can run in exponential time on an endpoint),
four templates to start from — PCI, HIPAA/PII, GDPR, Secrets — a Results
view with CSV export, a Scans view per endpoint, and a **Quick Search**
that sends one string or expression to chosen endpoints now.

## Impact — who can reach what

If this account, group or endpoint were compromised, what else could an
attacker reach? Impact answers it from two things mustra already collects.
The **directory** (Administration → Directory) is Active Directory read over
LDAP: users, groups, computers and nested memberships, on a schedule, with a
read-only bind account. Each endpoint's **local administrators** sensor says
who can administer it — the members of `Administrators` on Windows with
their SIDs, uid 0 and the sudo groups and sudoers grants on Linux, the
admin group on macOS — and the **logged-in users** sensor says who is signed
in. A session exposes that account's credential; the account's groups grant
administration of other endpoints; those endpoints have sessions of their
own. Impact walks that graph.

Users and groups are rated by what they can administer, nested groups
resolved, weighted by criticality — a domain controller in reach is
critical at any share of the fleet. Endpoints are rated by what a compromise
there reaches (outbound) and from how many endpoints it can be reached
(inbound), with hop counts. **Findings** name the shapes worth fixing: a
privileged account signed in outside the domain controllers, an account or
group that administers a large share of the fleet, a disabled account that
still holds grants, a local administrator name repeated across endpoints, a
critical endpoint reachable from much of the fleet. Every object opens to
its direct and inherited control, its sessions and its reach, and **Paths**
finds the shortest route from one object to another, one step at a time —
which is what an attacker would actually do.

Two honest limits. Sessions are the last collection, not a history, so an
account that signed out an hour ago is not on the map. And control is
"administrator of the machine": delegated rights in the directory itself
(GPO links, OU permissions) are not modelled.

## Groups — targeting

A **computer group** is a reusable slice of the fleet, matched *live* against
60+ inventory and sensor fields rather than being a static list. "All Windows
Servers missing more than five patches" stays correct as machines come and go.
Groups scope who may see a Self Service package and who a deployment targets.

Active Directory is a targeting source too, from the Directory sensor:
`directory.ou` (the computer object's container; `ends_with` matches an OU
and everything below it), `directory.computer_groups`, `directory.domain`,
`directory.site`, and the signed-in users' `directory.users`,
`directory.user_groups` and `directory.user_departments`. List-valued fields
match on their items: `equals Finance` is "any of them", `not_equals Finance`
is "none of them".

## Certificate renewal

Cert Manager discovers certificates (files, the Windows store, the macOS
System keychain, what local TLS ports serve) and renews the ones it manages.
A managed certificate names a file on an endpoint (key and certificate in one
file, as Pi-hole keeps them, or apart), its names, the CA, how many days before
expiry to renew, whether each renewal waits for approval, a reload command and
a port to check. When one is due, the agent generates the key — it never
leaves the endpoint — and returns a CSR; the CA signs it (Mustra's private CA,
Let's Encrypt via Cloudflare DNS-01, Cloudflare Origin CA, or your Active
Directory enterprise CA); the agent backs up the old files, writes the new ones
with their owner and mode, reloads, checks the port presents the new
certificate, and restores everything if any step fails. With **Tailscale** the
endpoint instead fetches a publicly trusted certificate for its own tailnet
name (`tailscale cert`), and nothing is signed by Mustra. See also
[Integrations](INTEGRATIONS.md).

**Active Directory Certificate Services.** Mustra does not talk to the CA
itself: a Windows endpoint in the domain, normally the CA server, submits each
CSR with `certreq -submit -config "<host>\<CA name>" -attrib
CertificateTemplate:<template>` and returns the certificate and the CA's own
certificate. Set it up under Certificates → Certificate authorities (the
submitting endpoint, the CA as `host\CA name`, the template; WebServer by
default). The template must take the subject from the request (WebServer
does) and grant **Enroll** to the submitting endpoint's computer account
(e.g. `CA01$`). A template that requires CA manager approval leaves the request
pending: the renewal fails with its request ID; approve it in `certsrv.msc`
and press Renew now. Domain-joined Windows machines trust an enterprise CA
automatically; anything else needs its root installed, as with the private
CA.

**Trusted roots.** Certificates → Trusted roots pushes Mustra's private CA
root and the AD CS root into every endpoint's system trust store
(`update-ca-certificates`, `update-ca-trust` or `trust` on Linux, the
machine's Trusted Root store on Windows), and keeps reaching endpoints enrolled
later; "remove" takes it back out. macOS trusts a new root only from a
configuration profile or a person, so Macs receive a `com.apple.security.root`
profile through Fleet MDM. Home Assistant OS manages its own store and is
reported as unsupported.

## Discover — the network, remembered

Discover is built from endpoints' own ARP and neighbour tables: no scan, no
packets. Every five minutes the server records each device by MAC
(`network_devices`): first and last sighting, which endpoints see it, its
vendor (the embedded IEEE registry) and its name by reverse DNS against the
servers set on the page (the router that hands out DHCP leases knows the
names). An operator can label or ignore a device. The first pass is a silent
baseline; afterwards a device never seen before raises a notification,
except managed endpoints and randomized (private) MACs, which phones rotate.
Container- and VM-internal networks behind a host (Docker, CNI, Podman,
libvirt, LXC, Home Assistant's `hassio`) are not the network and are skipped.

## Containers — what's behind, and nothing changed for you

The Containers sensor reads the host's Docker or Podman API over its local
socket, with GET requests only. It takes each container's name, image, state
and Compose labels. It never reads environment variables, commands or mounts,
because that is where containers keep their secrets.

For each image in use, the endpoint then asks the image's registry two
questions, anonymously, about every six hours:

- **Has this tag moved?** The running image's digest against the tag's current
  one. For `latest` that is the whole question.
- **Is there a newer version?** Asked only of tags that read as versions, and
  only against tags of the same shape: `16.4-alpine` compares with
  `16.5-alpine`, not `17` or `16.5`. A newer major version is shown separately
  from the newest in the current one, since a major upgrade is often a
  migration.

Each container ends up **Update available**, **Up to date**, **Could not check**
(the registry refused or did not answer, or the image is private) or **Not
checked** (built locally, pinned by digest, or checks turned off). Only a check
that succeeded says up to date.

The endpoint asks rather than the server because it can already reach the
registries its images came from. It is the one built-in sensor that contacts a
third party; `--no-container-update-checks` stops that and keeps the inventory.

mustra does not pull images or recreate containers here. Unattended image
updates are how a working service breaks overnight, so this answers what is
outstanding and leaves the decision with whoever reads it. To act on the list,
read `GET /api/containers?update=update_available`.

## Backup status

On a Proxmox VE node the Backups sensor reads, with `pvesh` as root, each
guest's newest backup on every backup storage, how many are kept, whether it
was verified, and whether an enabled vzdump job includes it. The server joins
guests to the Mustra endpoints inside them (MAC, then name) and rates each:
**ok**, **overdue** (newest backup older than the threshold, 36 hours by
default), **never** backed up, or **not covered** by any job (old manual
backups are not protection). Overdue and never notify once per episode and
again on recovery. A pool-based job covers the pool's current members, read
from `/etc/pve/user.cfg` (agent 0.58.0 and later; older agents show those
guests as not covered).

**Backup systems** are read directly as well (Backup Status → Connect a
backup system; `settings.manage`), every 15 minutes: **Proxmox Backup
Server** with a read-only API token (DatastoreAudit on `/datastore`), and
**Rubrik Security Cloud** with a read-only service account. They add what
no Proxmox job made — a host backed up with the PBS client, a server Rubrik
protects — with verification and each datastore's usage, rated like guests
(plus **verification failed**, and Rubrik's own out-of-compliance verdict as
overdue) and alerting the same way. A PBS group for a guest the Proxmox
nodes already list is marked and alerts from the guest's row only. A source
is reached like a webhook: an internal address only when its host is on the
internal destinations allowlist; a PBS server's self-signed certificate is
pinned by its SHA-256 fingerprint. For PBS the page also lists the server's
maintenance jobs (verify, prune, garbage collection, sync): how each last
ended, when, and when it runs next, with what garbage collection freed. A
job run that fails notifies once. A token whose rights do not cover one
kind of job just leaves it out. The secret is sealed, never returned,
and changing the URL, token or fingerprint needs it entered again. The
Rubrik provider follows Rubrik's API documentation and is tested against a
stand-in server, not yet a live account.

## Threat briefings

Reporting → Threat Briefings has a dashboard per vulnerability being
exploited now. Every CISA KEV entry (the catalog of vulnerabilities CISA
has seen exploited in the wild) added in the last 30 days has one, and so
does any older entry found in the fleet; briefings written by hand group
CVEs under one name (PHP2Shell, say) with an overview, mitigation,
references, a detection rule and hunting questions, and take over the KEV
briefings for their CVEs.

The CISA catalog is downloaded every six hours and the vulnerability scan
that finds **vulnerable** endpoints runs every six hours; the page itself is
computed when it is opened. Users with `patches.manage` have a **Refresh
now** button that downloads the feeds and runs the scan straight away, for
the morning a new zero-day is added.

A briefing counts endpoints two ways, kept apart. **Vulnerable**: the
vulnerability scan matched an installed package's version against the
advisory. **Product present**: the product is installed, or the endpoint
runs the operating system, but nothing checked its version against this
CVE. A Linux package on an endpoint whose vulnerability scan ran in the
last week has been checked against the distribution's own security data,
so it counts as cleared, not present; older catalog entries appear only
when the scan confirms them (an installed OpenSSL does not bring back
Heartbleed). KEV names a vendor and product, not a package, so a catalog of
detection rules (internal/server/threats_rules.go) says what each product
looks like on an endpoint: whole-name patterns, not substrings, so "Plex"
is not libmplex and BIND's name server is not its client tools. A product
without a rule is **not checked**, and a network appliance or hosted
service is said to be outside what an endpoint agent sees; neither counts
as zero.

Each dashboard has the CVEs with CISA's required action and due date,
EPSS, references from the catalog, the affected endpoints with their
versions (and the fixed version when the scan knows it), installed
versions by operating system, a 30-day trend, and Interact questions
built from the detection rule.

Users with `patches.manage` can remediate from the briefing: **Patch N
vulnerable endpoints**, and separately **Patch N endpoints with the
product** for the ones whose version was not checked. Both are Patch's
Deploy now with the online affected endpoints named (offline ones are left
to a patch schedule), with the same restart choice, maintenance windows,
patch lists, approval policies, management rights and audit entry. The
dialog offers **Only the affected packages** (the default) or **Everything
pending**. Only the affected packages installs, on each endpoint, just the
pending updates for the packages the vulnerability scan found vulnerable
there, matched by package name (apt/dpkg, dnf/rpm, ignoring architecture
suffixes), and the dialog previews which updates those are. It uses
apply_patches' selective form, which agents have honoured since 0.44.0;
older agents are refused rather than patching everything, and an endpoint
with no pending update for the package is skipped with the reason. Windows
Update and macOS updates do not name applications, so endpoints matched on
their operating system alone can only be patched in full.

Users with `deploy.manage` also see a button for each Software catalog
package whose own detection rule matches the affected product: **Update**
(or **Install**) **<package> on N** deploys it to those online endpoints,
for software the operating system's updater does not manage, such as a
browser installed from its vendor.

A briefing reflects a fix within minutes. When a patch or software run
finishes on an endpoint, the server asks that endpoint for its installed
software and runs the vulnerability scan about 90 seconds later, once for
the whole run, instead of waiting for the six-hourly scan.

**Automatic remediation** (off by default; `patches.manage` turns it on
from the briefings list) patches, every hour, the endpoints a briefing
confirms as vulnerable: only the vulnerable packages, within maintenance
windows and patch lists, optionally a set number of days after the
endpoint is first found vulnerable, and with or without a restart when the
updates need one. Each exposure gets at most three attempts a day apart,
and the third notifies that it is the last. Runs appear under Patch →
Deployments, started by "auto-remediation". As with patch schedules,
approval policies do not hold these runs: turning the rule on is the
decision. **Past-due alerts** (on by
default) notify once per endpoint and briefing still vulnerable after
CISA's due date.

Anyone signed in can read briefings, over
the endpoints they may see; `alerts.triage` writes them. A briefing found
in the fleet (a confirmed match, or an installed product; an operating
system alone does not) notifies once, and again after it clears.

## Hardening scores

Comply → Hardening Scores matches each endpoint to the benchmark written for
its OS family and version among the imported CIS policies (the nearest
version when there is no exact one, marked ≈) and scans it on demand or
daily. The score is the severity-weighted share of evaluated checks that pass
(critical 4, high 3, medium 2, low 1); checks that could not be evaluated are
left out rather than counted either way. A score is kept per day for the
trend, and results export as CSV per endpoint or for the fleet.

**Exceptions** (Comply → Exceptions) take a check out of the score for every
endpoint or one group, with a reason and an optional expiry. They are for
checks a site has decided not to apply — a reinstall for separate
partitions, a default-deny firewall on a hypervisor, audit rules inside a
container — and for checks that are wrong in the published benchmark. The
check still runs and keeps its real result, shown as `excepted`. Exceptions
match by title, so one covers every benchmark version with the check; a
deleted group's exceptions apply to nobody.

**The rule dialect** is Wazuh's SCA dialect, with its semantics: a matcher
holds on one line of a file or command output, and `&&` joins terms that
must all hold on that same line (`r:0 root 0 root && r:644|640`). `!r:x`
holds on a line that does not match, so `not f:/etc/passwd -> !r:^\w+:x:`
reads "every line matches". `d:<dir> -> r:<name> -> <matcher>` looks in the
files under the directory whose names match (three levels, at most 2,000
files); `d:<dir>/*` is the directory. Windows registry values are compared
whole. Anything the engine does not understand is `unknown`, never a pass.

## Compliance by control — NIST and other frameworks

**Comply → Controls** turns the benchmark results around: for a framework,
which controls have evidence from the endpoints, and where it fails. The
mapping is the benchmark's own. Current CIS content from Wazuh lists, for
every check, the controls it supports in NIST SP 800-53 Rev. 5, NIST SP
800-171, CMMC 2.0, FedRAMP, HIPAA, ISO/IEC 27001:2022, GDPR, NIS2, PCI DSS
and SOC 2; mustra reads that block when a policy is imported and adds
nothing of its own, so a control no check maps to is absent rather than
reported as met. A policy imported before this was read carries no
mappings; importing the same file again adds them.

A control **fails** when any of its checks fails on any endpoint, is
**can't tell** when none fails but one could not be evaluated, **passes**
when every result passed, and is **not scanned** when its checks have not
run yet. Exceptions count for neither side. Controls are grouped by family
(AC, AU, CM… for 800-53; 3.1, 3.3… for 800-171) in catalogue order, and
each one opens to its checks and the endpoints they fail on. The CSV export
has one row per control and check, for an assessor's evidence file.

The built-in Linux baseline is mapped too: seven of its ten checks take
the mapping Wazuh gives the same CIS check; automatic security updates
(SI-2, 3.14.1) and legacy NIS entries (AC-2, IA-2; 3.5.1, 3.5.2) are
mustra's own reading. This is evidence for an assessment, not an
assessment: most controls also need policy, process and people that no
endpoint scan can show.

## Lifecycle

The Hardware sensor reports each machine's manufacturer, model, serial
number, firmware date and chassis (laptop, desktop, server, mini PC,
single-board, virtual; containers report none). Agents → Lifecycle joins
that with six asset attributes — purchase date, warranty end, owner,
lifecycle state, location, cost — created in one click, for each machine's
age (from the purchase date, else the firmware date, marked ≈) and warranty
days left. A warranty ending within 30 days notifies once per end date.

## Approving from chat and the API reference

A request waiting on a decision — a Jump Gate access request, a parked
approval, a playbook gate, a certificate renewal — reaches Slack, Teams and
Discord integrations with Approve / Deny buttons and webhooks with an
`actions` array, whatever the channel's severity threshold. The buttons are
links to `/approve`, which shows the request signed in and decides it through
its usual API: same permissions, same rule that nobody approves their own
request. Opening the link decides nothing.

`/api-docs` lists every API route with the permission it needs, generated
from the running server's route table; `/api/openapi.json` is the same as
an OpenAPI 3.2.1 document, and `/api/openapi.yaml` is that document in
YAML (1.2, with any string a YAML 1.1 reader would mistype quoted, so
older parsers read the same values). Both need a signed-in user or an API
token. Every route also declares what it reads and returns (the
request body, query parameters, response, success and error statuses),
reflected from the Go types the handlers use and checked against the
handlers' source by a test, so the spec can type a generated client and
the page's request builder fills in a route's query parameters and body
fields. Types and fields are described by their Go doc comments, and a
route that takes a JSON body has an example body, which the builder
starts from; one that replaces a server-wide setting has none, since an
example sent as written would overwrite it.

## Microsoft Entra ID and Intune

With an app registration (Settings → Integrations), the server reads Entra
ID's devices and Intune's managed devices from Microsoft Graph every hour,
merges them by Entra device ID and matches them to endpoints (the Entra
device ID the endpoint reports, then its hostname). Each endpoint shows its
join type, compliance, Intune check-in and primary user, with Intune Sync and
Restart, which are endpoint actions under the usual gate and audit. Without
Intune the Entra half still works.


## Telemetry — endpoint metrics in Prometheus

Administration → Telemetry turns every agent into a host metrics exporter.
Agents collect CPU, memory, load, filesystems, disks, network interfaces,
boot time, temperatures and open file handles under node_exporter's metric
and label names (`node_cpu_seconds_total{cpu,mode}`,
`node_filesystem_avail_bytes{device,fstype,mountpoint}`, …), so dashboards
and alert rules written for node_exporter work unchanged. On Linux that
includes pressure stall time, OOM kills, network and socket counters, NTP
sync, conntrack, ZFS, CPU frequency, OS release, thermal zones, link state
and every systemd unit's state, and a **health** collector with the names of
the usual textfile scripts: services still running a deleted binary
(`node_service_stale_exe{service}`), packages dpkg left half-installed
(`node_dpkg_broken_packages`), pending and held apt upgrades by origin
(`apt_upgrades_pending{origin,arch}`) and `node_reboot_required`. Health
and systemd shell out, so they refresh in the background (every five
minutes and every minute) and each batch carries the latest. On Linux the values
come from `/proc` and `/sys` the way node_exporter reads them, with its
default filesystem and device exclusions; on Windows and macOS the same
names are filled from the operating system's counters, and Linux-only
families (temperatures, file handles) are absent.

Agents publish each batch on the connection they already hold
(`beacon.telemetry.<agent>.metrics`), never to Prometheus directly, so an
endpoint needs no inbound port and no route to the monitoring network.
Batches are not buffered on the agent: metrics are current or they are
nothing, and a laptop that was offline does not replay an hour of samples.
The server labels each series with `job` (default `mustra`), `instance` and
`instance_name` (the endpoint's hostname), `site`, and any extra labels (an
extra `site` replaces the endpoint's); an agent cannot set those itself. It then delivers them in either or both ways:

- **remote_write** pushes every batch as it arrives to Prometheus (started
  with `--web.enable-remote-write-receiver`), Mimir, VictoriaMetrics or
  Grafana Cloud, with basic or bearer auth. Like a webhook, a receiver on
  an internal address must be on the internal destinations allowlist, and
  only an allowlisted host may use plain http. While the receiver is down,
  batches wait in memory (the newest 2,000) and are retried with backoff; a
  batch the receiver rejects as malformed is dropped and counted.
- **scrape** serves each endpoint's latest batch at `/metrics/endpoints`,
  behind the Prometheus integration's token, with the agents' timestamps
  (the scrape job needs `honor_labels: true` to keep each endpoint's `job`
  and `instance`).

Labels can also be set per computer group, over the extra labels:
`device_class=laptop` on a Laptops group, say, so alert rules can leave
laptops out with `{device_class!="laptop"}` while their metrics still
reach dashboards. Each endpoint in scope also gets an `up` series, 1 while
it heartbeats and 0 once it has gone quiet: pushed metrics have no scrape
of their own, so this is what keeps an `up == 0` alert meaningful. And
`mustra_metrics_last_received_timestamp_seconds` says when its latest batch
arrived, so an endpoint that heartbeats but has stopped sending metrics is
visible: `time() - mustra_metrics_last_received_timestamp_seconds > 120`.
With **Label Proxmox guests** on, an endpoint that is a Proxmox VE guest also
carries `vmid`, `node` and `guest_type` (`lxc` or `qemu`), from the guest
lists its node's agent reports and matched the way backup status matches
them (MAC address, then name).

Collection can be limited to computer groups and to some collectors, and the
interval (default 15 s) applies to every collecting endpoint. Agents ask for
their configuration every five minutes, so a change reaches the fleet within
that. If node_exporter also runs on an endpoint, both report the same series
names under different `job` labels; rules that do not filter on `job` see
the host twice.
