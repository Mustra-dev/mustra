# Changelog

What has actually shipped, newest first. The console renders this file on
Administration → About, so the running build always shows its own history
rather than a page that can drift from it.

## Unreleased

## 1.3.0 — 2026-11-06

Server 1.3.0, agent 1.3.0. Update agents to report containers: upgraded agents on
hosts with containers contact the registries their images came from (see below).
Removes `init.sh --insecure-http`. Install commands copied before the upgrade stop
working: create a new enrollment token.

### Added
- **See which containers have image updates.** The new **Containers** page lists the
  Docker and Podman containers on your Linux endpoints (and Macs with Docker's default
  socket) with which images have an update: the tag has moved, or a newer version tag
  exists, such as `16.5` or `17.1` for `postgres:16.4`. It reports only; nothing is
  pulled or restarted. Images that cannot be checked say why and never count as up to
  date. Also available from `GET /api/containers`, Interact and computer groups. Needs
  an agent upgrade. Upgraded agents on hosts with containers contact the registries
  their images came from, anonymously, about every six hours; start the agent with
  `--no-container-update-checks` to stop that.
- **Ask mustra from an AI agent.** The server now has a read-only MCP endpoint at
  `/api/mcp`, so an agent can ask which containers have updates outstanding and act
  with its own tools. Sign in with an API token that has **See the fleet**.
- **Know when a hunt or sensitive-data scan finishes.** Integrations can opt in to
  completed IOC hunts and sensitive-data scans, alongside the other actions. A hunt
  you start always announces; the one that runs every 15 minutes does only when it
  finds something. The terms of a quick search aren't included.
- **Inventory-and-patching mode from Network Scan & Push and the Home Assistant
  add-on.** Push has a tick box. The add-on takes a verified install command, and
  then runs only that installer, by hash.

### Fixed
- Code scanning findings: an audit line sent to syslog stays valid JSON if its detail
  can't be encoded, an out-of-range user or group ID is refused rather than wrapped
  when a deployment switches user, and a crafted query or page link can't hang or
  misdirect a console page.

### Changed
- **The add-on is checked before it's installed.** The installer now holds the add-on's
  files to a hash like everything else it downloads.

### Removed
- **`init.sh --insecure-http`.** Sign-ins and enrollment tokens would cross the network
  in the clear. Put HTTPS in front with `--public-hostname`, or use an SSH tunnel.
  Existing installs keep working, and the settings in `.env` are unchanged.

## 1.2.3 — 2026-11-05

Server 1.2.3, agent 1.2.3. Update agents to get the corrected macOS update message.
Install commands copied before the upgrade stop working: create a new enrollment
token.

### Fixed
- A Mac whose macOS update couldn't be downloaded is no longer told it's "ready to
  install". macOS can refuse the download without a password, and the patch job and
  the notification now say the update is available and that Software Update fetches it.

### Documentation
- The install guide says how much of a compliance benchmark reads `unknown` in
  inventory-and-patching mode: most of CIS macOS 26, and about a tenth of CIS Windows
  Server 2025.

## 1.2.2 — 2026-11-04

Security patch; server 1.2.2, agent 1.2.2. The fix is in the agent: update agents to
correct their compliance results. Update restricted agents by running the installer
on the machine. Install commands copied before the upgrade stop working: create a
new enrollment token.

### Security
- **A compliance check no longer passes on rules it didn't evaluate.** A check that
  mixed a rule the agent couldn't evaluate with others was judged on the others
  alone, so one that really failed could report `pass`. Endpoints in
  inventory-and-patching mode were the most affected, because they skip every
  command rule. Such a check now reads `unknown`, unless the other rules settle it.
  Some results will change after the update.

### Fixed
- Self Service on a restricted endpoint no longer offers installs or agent updates
  it would refuse. It says apps can't be installed there and to ask IT.

## 1.2.1 — 2026-11-04

Security patch; server 1.2.1, agent 1.2.1. Upgrade the server if any endpoint runs
in inventory-and-patching mode, and update those agents by running the installer
on the machine. Install commands copied before the upgrade stop working: create a
new enrollment token.

### Security
- **Jobs sent to a restricted endpoint no longer wait to run.** Inventory-and-patching
  mode refused them, but a managed deployment stayed open and ran as soon as
  somebody removed the mode, however old it was. Nothing ran while the mode was on.
  A refusal now ends the deployment, and the agent drops any it had stored.
- **A refused shell command no longer reads as a success.** The transcript and audit
  log recorded it with exit code 0 and no output. They now record the refusal, with
  exit code -1. This applies to any command an agent answers with an error.

### Fixed
- A deployment to a restricted endpoint shows as failed, with the reason, instead
  of running forever while the server retried it every 5 seconds.
- Self Service on a restricted endpoint says it can't install, instead of "Deployment
  queued", and no longer records a run.
- A restricted agent no longer logs a warning a minute about deployment settings.
- The macOS installer no longer says Full Disk Access is missing when it can't tell.
  It was checking its own access rather than the agent's.

## 1.2.0 — 2026-11-04

Server 1.2.0; agent 1.2.0. Inventory-and-patching mode needs the new agent, so
push it from **Deploy Agents**. Nothing changes for existing endpoints unless you
ask for it. Install commands copied before the upgrade stop working, and say so:
create a new enrollment token.

### Added
- **Inventory-and-patching mode.** Tick **Inventory and patching only** when
  creating an enrollment token, and those endpoints refuse code from the server:
  Direct Connect, deployments, custom sensors, Enforce, agent updates and anything
  added later. They still report inventory, vulnerabilities and compliance (a
  rule that would run a command reads `unknown`), and take the updates their
  package manager offers from the repositories configured on the machine. It is a file on the endpoint, so a compromised server
  can't turn it off and can't run code there. Update those agents by running the
  installer on the machine.
- **Install commands verify what they run.** A command from the console now checks
  the installer's hash before running it, and the installer checks everything it
  downloads against hashes it carries, including the CA agents trust. A tampered
  download stops the install before anything changes. A command stops working
  when the server changes, such as after an upgrade: create a new token. Commands
  for automation that stores them are still offered, and trust the connection.

## 1.1.1 — 2026-11-04

Server 1.1.1; agent 1.0.0, unchanged: there is nothing to push to endpoints.

### Added
- **More completed-action events.** Compliance scans, Enforce runs and manual
  backups can now be announced too. A compliance scan counts as failed only when
  an endpoint did not answer, and drift in report mode is not an Enforce failure.

### Fixed
- A deployment or patch run that ended without a result coming in (timed out,
  expired while held for a maintenance window, or finished through an MDM) was
  not announced to integrations taking completed actions. Finished runs are now
  checked every minute. Runs already finished when upgrading are not announced.
- An endpoint a patch run could not start on, because it was already patching or
  had no affected package, is now recorded on the run as failed with the reason.
  It used to be left out, so the run's counts did not add up.

## 1.1.0 — 2026-11-04

Server 1.1.0; agent 1.0.0, unchanged: there is nothing to push to endpoints.
Upgrading adds what it needs on startup, and sends no email until you set up an
SMTP account and an integration or report that uses it.

### Added
- **Email.** Administration → Email holds an SMTP account, with a test send.
  Certificates are always verified, a password only travels over TLS, and a
  server on an internal address needs the internal destinations allowlist.
- **Reports can be emailed.** The Email destination sends the full report,
  with the text digest as the plain-text part.
- **Email integrations.** Anything an integration can take can now go to
  email, including certificate and credential expiry, which the guide already
  promised.
- **New-vulnerability alerts.** Integrations can take a new **vulnerability**
  event. After each scan, findings not yet announced arrive as one digest per
  severity level, and the integration's minimum severity chooses between
  everything and only the big ones: `error` is critical findings and anything
  in CISA's KEV catalogue. Threat briefings' actively exploited findings are
  sent too. The first scan after upgrading only takes stock, so nothing is sent
  for findings you already have. Each finding is announced once per endpoint,
  and again only if it becomes more severe.
- **Customizable emails.** Every email's subject, text and HTML can be rewritten
  under Administration → Email, with variables, conditions, functions and shared
  macros, a preview, and a test send. A report or Email integration can have its
  own. HTML values are escaped. A template that fails when sending costs its
  wording, not the email: the default goes out, with a note saying why.
- **Completed-action events.** Integrations can opt in to hear when deployments,
  patch runs, playbooks, nightly backups, certificate renewals, vulnerability
  scans or reports finish, each chosen separately. Off by default. A minimum
  severity of `warning` keeps it to the ones that failed.
- The Vulnerabilities source of reports, dashboards and Connect exports has
  `kev`, `ransomware` and `epss` columns, and lists the worst first. A report's
  default table for it now shows host, vulnerability, package, severity, KEV
  and EPSS.

### Fixed
- The Vulnerabilities source of reports, dashboards and Connect exports
  included findings the distribution says need no action, so its counts were
  higher than the Vulnerabilities page's. They are now left out, as the source
  always claimed. A finding with no rating now reads `unknown` instead of blank.

## 1.0.0 — 2026-11-02

The first public release. Server 1.0.0; agent 1.0.0. Upgrading from
0.105.x: the schema migrates on startup (read permissions, below), and the
agent fixes need the 1.0.0 agent pushed from **Deploy Agents**.

### Changed
- **Seeing the fleet needs a role.** Until now every signed-in account
  could read everything (endpoints, process command lines, logons, the
  network map, the audit log) and ask endpoints questions, whether or not
  it held a role. Reading is now the **See the fleet** permission
  (`fleet.read`) and the audit log is **Read the audit log**
  (`audit.read`); the built-in **user** role holds both. An account with
  neither sees only its own preferences, two-step sign-in and Help, and a
  page telling it to ask for a role. **On upgrade nobody loses access:**
  every existing role and API token is given both permissions, and every
  account that had no role is given the built-in **user** role, once. New
  API tokens need `fleet.read` ticked to read anything.
- A page you may not open now says which permission it needs, inside the
  console, instead of a line of plain text.

### Security
- **Dependency security updates.** go-jose 4.1.6, used when signing in
  with OIDC, caps the RSA key size it accepts in an identity provider's
  key set, so a hostile or compromised provider can no longer stall the
  server with an oversized key (GHSA-mgcc-cww5-fp2q). The script editor's
  Bash language engine now uses zod 4.6.6 and minimatch 11.0.4, which fix
  memory exhaustion and pattern-amplification denial-of-service issues.
- **An approved request runs only with the authority its requester still
  has.** A request parked for approval used to run when approved even if,
  while it waited, the requester's account had been disabled or had lost
  the permission the action needs (for example `deploy.manage` for an
  agent update, a playbook run or a deployment). The approver needs only
  `approvals.decide`, so the action could run when nobody involved held
  the permission. It now fails with the reason recorded on the request.
  Server.
- **An agent cut off from the server is no longer rolled back.** The
  recovery job's heartbeat started only once the agent reached the server,
  so an agent that was running but could not reach NATS looked dead. In
  the first ten minutes after an update, a restart followed by an outage
  of 15 minutes or more, or by someone blocking its traffic, put back the
  previous build without any downgrade authorization. The agent now writes
  the heartbeat from start-up. A build that keeps crashing is still
  restored. Agent.
- **Home Assistant: the add-on installs only signed updates.** The agent
  add-on used to reinstall the agent from the server's `install.sh` every
  time it started, checking the binary only against a checksum from the
  same server. So whatever answered at the add-on's `server_url`, not the
  update signing key, decided what ran there. The agent now downloads an
  update and verifies it against the signed manifest, as on every other
  platform. The add-on installs that verified build when the agent
  restarts, and puts the previous one back if the new build fails within
  two minutes. `install.sh` runs only for a first install, or once after
  the add-on itself is installed, updated or rebuilt. **To get this,
  update the add-on** (version 1.1.0): run the console's install command
  again in the Home Assistant SSH add-on. Agent and add-on.
- Built with Go 1.27.3, which fixes GO-2026-6809 (certificate verification
  could accept compromised intermediate certificates). mustra reached it
  when verifying a directory (LDAP) server's certificate. Server and agent.

### Fixed
- **First run.** After creating the first administrator, sign-in says the
  account was created and fills in its name; a server with no identity
  provider shows the local sign-in form instead of a greyed-out SSO button;
  Home on a server with no endpoints says how to add the first one; and a
  stack built with `init.sh` reports its version instead of "dev".
- Deploying a package with no published version says to publish its draft,
  instead of "no endpoint is eligible".
- The package editor can again let endpoints outside a package's groups
  **request** it from Self Service.
- Readable red badges and buttons in both themes (Threat Briefings,
  Certificate Manager), and readable active filters in the dark theme.
- **winget on Windows Server.** Library packages and package commands that
  use winget failed to start as SYSTEM on Windows Server (exit
  `0xC0000135`): its framework libraries are now found from its own
  manifest. Needs agent 1.0.0 for package commands; library
  packages are fixed by the server.
- Compliance and Enforce `p:` rules match a Windows process with or
  without `.exe` (`p:lsass` finds `lsass.exe`). Needs agent
  1.0.0.
- Go custom sensors build again after the Go 1.27.3 update.
- A server built from source between releases (versions like
  `0.105.1-24-gc9cd30b`) offers its agents an update when it carries a
  newer build, and the agent accepts it, instead of both calling it
  current or a downgrade. The agent side needs agent 1.0.0.
- Home's Patch Status and Risk cards fill their row.
- Windows **Installed Apps** shows the agent's running version after a
  self-update, instead of the version first installed. Needs agent 1.0.0.
- Software sections show current data when you switch to them: a package,
  deployment or maintenance window added since the page opened appears
  without reloading.
- Vulnerabilities from Debian's advisories have a summary (the first
  sentence of the advisory) instead of an empty Summary column; existing
  ones fill in at the next scan.
- Client Management lists endpoints that need re-enrollment only when there
  are some.

### Added
- **Terms of Use and Privacy notice** ([TERMS.md](https://github.com/mustra-dev/mustra/blob/main/TERMS.md),
  [PRIVACY.md](https://github.com/mustra-dev/mustra/blob/main/PRIVACY.md)). First-run setup asks the person creating the
  first administrator to accept the Terms of Use, and the audit log records
  it; Administration → About links the license, terms and privacy notice.
- **Help.** Step-by-step guides for every part of the console, built into
  the server: the **?** at the foot of the left rail, or **Guide** in a
  page's header for the guide to that page.

## 0.105.1 — 2026-10-31

Server 0.105.1; agent 0.64.1. No schema change. The PowerShell exit-code
fix needs agent 0.64.1; the uninstaller change reaches endpoints with the
next install script served by this server.

### Fixed
- **PowerShell sensors and checks keep their exit code**. A
  PowerShell custom sensor or deploy check script ending in `exit N` was
  reported as exiting 1, so a check meaning "error" (2) read as "false" (1)
  and could choose an else branch. Found by the new Windows CI job, which
  runs the agent's tests on a real Windows runner.
- **Quiet Windows uninstall.** The uninstaller no longer prints a red
  PowerShell error when the tray helper is not running. New installs pick
  this up.

## 0.105.0 — 2026-10-31

Server 0.105.0; agent 0.64.0. The schema adds columns to `users` and two
tables (`user_recovery_codes`, `login_challenges`) on startup. Two changes
need agent 0.64.0: the Self Service window's stricter policy and recovery
after a failed update; everything else is the server. **Before upgrading:**
an agent that never enrolled (Settings → Agent identity shows how many) can
no longer connect and must be reinstalled with an enrollment token; sessions
now end after 12 hours, or 1 hour idle; and CIS policies must be imported
again for the new Controls report to map them.

### Added
- **Two-step sign-in for local accounts**. After the password,
  sign-in asks for a code from an authenticator app (TOTP) or a single-use
  recovery code. Set it up under Preferences; administrators can require it
  for every local account (Administration → Break-glass account), which
  makes each one set it up at its next sign-in, and can reset a lost
  authenticator from the Users list. A code is accepted once, five wrong
  codes send you back to the password, and every enrollment, reset and use
  of a recovery code is in the audit log. Needs the credential encryption
  key (`MUSTRA_CREDENTIAL_ENCRYPTION_KEY`). SSO accounts keep using their
  identity provider's MFA.
- **Compliance by control: NIST SP 800-53, 800-171 and more**.
  Comply → Controls shows, for a framework, which controls the benchmark
  results give evidence for and where they fail, grouped by family in
  catalogue order, each opening to its checks and the endpoints that fail
  them; Export CSV writes the same for an assessor. The mappings come from
  the benchmark itself (the `compliance:` block of CIS content), which now
  covers NIST SP 800-53 and 800-171, CMMC, FedRAMP, HIPAA, ISO 27001,
  GDPR, NIS2, PCI DSS and SOC 2; the built-in Linux baseline is mapped to
  both NIST catalogues. **Import your CIS policies again** to pick up
  their mappings: policies imported earlier carry none, and the page lists
  them. Server only.
- **Agents recover from an update that took them down**. Each
  agent keeps a last-known-good copy of itself once a build has run for ten
  minutes, and registers a recovery job with the OS (systemd timer, cron,
  launchd or a scheduled task). If the agent stops running for fifteen
  minutes, the job restarts it, and if the installed build is not the
  known-good one, restores that build first. A service an administrator
  disabled is left alone; uninstalling removes the job. **Agent release**:
  endpoints get it with the agent update, after which their first ten
  healthy minutes set it up. Windows endpoints under Defender's ransomware
  ASR rule need `mustra-agent.lkg.exe` in the same exclusion as the updater.
- **Package library**. Software Packages → **Add from library**
  lists 18 widely used applications (browsers, 7-Zip, VS Code, Git,
  PowerShell 7, KeePassXC, Wireshark, PuTTY, Slack, Zoom, Acrobat Reader,
  Python, Node.js LTS and more), each installed through the platform's own
  package manager (winget on Windows, Homebrew on macOS, apt on Debian and
  Ubuntu) so endpoints always get the vendor's current release. Adding one
  creates an unpublished draft with detection, validation and an
  applicability check already written: test it on one endpoint, then
  publish. Nothing from the library deploys by itself. Server only.

### Changed
- **Choose a package's platforms**. New software and action
  packages no longer start with a Windows platform already added. The
  Platforms section offers Windows, macOS and Linux as toggles: turn on
  one or more, and turning one off removes it (asking first if it already
  has commands). The tab strip for switching between variants appears
  only when there is more than one, and each variant offers "Add another
  … variant" for, say, a second Linux distribution. Server only.
- **Shorter sessions by default**. A console session now lasts at
  most 12 hours (was 7 days) and ends after 1 hour with no request (was 12
  hours), per NIST SP 800-63B AAL2. Everyone is asked to sign in again
  sooner; set `MUSTRA_SESSION_MAX_AGE` and `MUSTRA_SESSION_IDLE_TIMEOUT` to
  keep the old limits.
- **Content sets restrict sensors**. A role whose content sets list
  sensors may now query, filter on, build groups from, live-query and view
  only those sensors; anything else is refused naming the sensor. Sets that
  list no sensors leave sensors open as before, so existing roles are
  unaffected until someone lists sensors. Custom sensors can now be picked
  in a content set. Hostname, OS, IP and the other identity fields are
  always readable. Server only.
- **The console feels more physical**. Buttons press
  in the moment they are pressed; Save in the package editor and in
  Preferences turns into a spinner and then a drawn check where you
  clicked; ten reversible deletes (maintenance windows, deployment
  templates, schedules, package files, compliance exceptions, dashboard
  alerts, integrity labels, end-user messages, Connect exports, playbook
  triggers) happen at once with **Undo** (or Ctrl/Cmd+Z) for 8 seconds
  instead of asking "Are you sure?"; live numbers on Home and the module
  stat tiles roll to their new value and are marked once; "loading…" lines
  became skeleton rows that keep the table still; switching light/dark
  cross-fades; drawer scrims fade with their drawer; headings tighten by
  size and the "MUSTRA" label above page titles is gone. Everything keeps
  its content and drops its motion under reduced motion. Deletes that take
  data or access with them still ask first. Server only.

### Security
- **Self Service refuses inline styles**. The Self Service window
  and the console's preview of it no longer allow `style-src
  'unsafe-inline'`: the page's own style elements carry the response's
  nonce and style attributes are refused, so injected markup cannot
  restyle the window (for example to disguise a button). Branding and
  custom CSS work as before. The preview changes with the server; each
  endpoint's window changes when its agent is upgraded.
- **The legacy shared agent credential is retired**. With agent
  identity enforced (the auth callout configured, the default since 0.80),
  the server refuses the password all agents once shared, and refuses
  trading it for a credential, whatever Settings said; the switch that
  re-opened it is gone. Nothing changes for enrolled agents. An agent that
  never enrolled can no longer connect and has to be reinstalled with an
  enrollment token: Settings → Agent identity says how many there are. An
  install still on a pre-0.80 fleet must finish migrating on 0.104.x
  first (deploy/README.md). `MUSTRA_NATS_AGENT_PASSWORD` is now unused and
  can be removed from `.env`. `legacy_allowed` stays in `GET
  /api/agent-trust`, always false; asking `PUT` to set it true answers 409.

## Earlier releases

mustra was developed privately up to 0.105. This repository starts from
that release; its features are described in the README and
[docs/CONCEPTS.md](docs/CONCEPTS.md).
