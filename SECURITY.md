# Security policy

mustra runs commands as root or SYSTEM on every managed endpoint. A flaw in
the server, the agent or the message bus between them can become remote code
execution across a fleet. Please report anything that might be one
privately, as described below.

## Supported versions

mustra is released from `main`. Security fixes go into the
next release; older lines are not patched.

| Version                         | Supported |
| ------------------------------- | --------- |
| Latest release (`1.x`, newest)  | Yes       |
| Any earlier release             | No: upgrade to the latest |
| Unreleased `main`               | Best effort |

Servers and agents are versioned independently. A fix may need a server
upgrade, an agent upgrade (pushed from **Deploy Agents**), or both. The
release notes and `CHANGELOG.md` say which.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a
vulnerability.**

Email **security@mustra.dev**, or
[open a private report](https://github.com/mustra-dev/mustra/security/advisories/new) (the repository's **Security** tab →
**Report a vulnerability**). Only the maintainers see either, and we work
on the fix privately with you.

A useful report includes:

- the affected component (server, agent and OS, console, NATS
  configuration, deployment files, release artifacts) and version or commit;
- what an attacker needs beforehand (network position, console role, an
  agent credential, a compromised endpoint);
- steps to reproduce, or a proof of concept against a test deployment;
- the impact as you understand it.

Test only against deployments you own. Do not run destructive tests, access
other people's data or degrade a service you do not operate.

## What to expect

mustra is maintained by a small team, so these are targets, not contractual
guarantees:

- **Acknowledgement** within 7 days.
- **Initial assessment** (whether it is in scope, and how severe) within
  14 days.
- **Fix:** we aim to ship critical and high-severity fixes within 30 days
  and others in a later regular release. We will keep you updated if it
  takes longer.
- **Disclosure:** we describe the issue and the fix in the release notes
  and `CHANGELOG.md` when the fixed release is out (with a CVE where
  appropriate), and credit you unless you ask us not to. We ask that you wait for that release, or 90 days from your
  report, whichever comes first, before publishing details.

## Scope

In scope:

- the server (`cmd/server`, `internal/server`, `internal/store`) and the
  web console it serves;
- the agent (`cmd/agent`, `cmd/mustra-tray`, `internal/agent`) and its
  update and install paths;
- the NATS broker configuration and subject permissions in `deploy/nats/`;
- the deployment files in `deploy/` as shipped, and the published release
  artifacts (images, agent binaries, checksums, signatures, attestations);
- the script-analysis tools in `tools/`.

Out of scope:

- vulnerabilities that need administrative access the attack would grant
  anyway: an operator with `deploy.manage` running code on endpoints is the
  product working as designed;
- misconfigurations that contradict the shipped defaults and documentation,
  such as a console served over plain HTTP to the internet, or a NATS port
  exposed without the shipped TLS and credentials;
- vulnerabilities in third-party dependencies with no demonstrated impact on
  mustra (report those upstream; Dependabot tracks them here);
- denial of service by volume alone, social engineering, and findings from
  automated scanners without a demonstrated issue;
- the placeholder packages under `packaging/`.

## Security model

This describes the intended design. If the code does not behave this way,
that is a vulnerability: please report it.

### Components and trust

- **Server.** Trusted. It holds the database, the credential vault key and
  the only NATS identity allowed to publish commands. Compromise of the server
  is compromise of the fleet.
- **Operators.** Authenticated to the console with OIDC (restricted to an
  allowlist of permitted domains, addresses or groups; with none configured,
  SSO sign-in is refused), local accounts or API tokens (which act within
  their creator's permissions), and
  authorized per action by role permissions checked on the server. The
  sidebar only hides what a role cannot use; it is not the access control.
  Endpoint actions are attributed to the operator in the audit log, and
  Direct Connect sessions are audited before the command is sent.
- **Agents.** Trusted to report about their own endpoint, and nothing more.
  Each agent enrolls with an enrollment token (limited uses, with an expiry)
  and receives its own NATS credential; the broker's auth callout scopes each
  connection to that agent's own subjects. An agent can
  publish its own telemetry and results and receive work addressed to it.
  It cannot publish commands, read other agents' traffic or report as
  another agent.
- **NATS.** Agents connect outbound only. The broker requires TLS and a
  credential for every connection, and its permissions separate the server
  role from the agent role. Agents accept no inbound connections. The
  broker's HTTP monitoring port is unauthenticated and must not be exposed
  beyond the host.

### Attackers considered

**A network attacker** (on the path between agents, server and operators)
should not be able to read or change traffic, or impersonate any party:

- NATS traffic uses TLS, and agents verify the broker against the CA the
  deployment generated.
- The console is meant to sit behind TLS. The server is configured with its
  explicit public console URL (`MUSTRA_PUBLIC_URL`, or the setting an
  administrator enters), and uses that URL, never request headers, to build
  agent install commands, download links and update URLs. The OIDC redirect
  URL is configured explicitly as well.
- Session cookies are `HttpOnly` and `SameSite=Strict`, and `Secure` (with a
  `__Host-` name) unless secure cookies are explicitly disabled for plain-HTTP
  development. There are no CSRF tokens: a state-changing request from a
  browser is refused unless its `Origin` (or, without one, `Sec-Fetch-Site`,
  then `Referer`) shows it came from the console's own origin
  (`MUSTRA_TRUSTED_ORIGINS` adds others). Bearer-token API calls and the playbook
  webhook are exempt: each carries its own secret, which a browser does not
  attach on its own. Every console page is served with a nonce-based
  Content Security Policy that allows no third-party or inline scripts.
- Agent updates are signed. An enrolled agent installs a new binary only if
  its manifest verifies against the deployment key it pinned at enrollment
  (and the binary matches the manifest's size and SHA-256), so control of the
  download path is not enough to replace it. Agents that predate signed
  updates still update by running the install script from the configured
  public URL; see Known limits. Release artifacts also carry
  SHA256SUMS, keyless cosign image signatures and, while the repository
  is public, Sigstore build-provenance attestations (see `.github/workflows/release.yml` for how to verify
  them).

**A compromised or malicious agent** (root on one endpoint) controls that
endpoint and can lie about it. It should not be able to:

- run commands on any other endpoint;
- read other agents' data or commands, or submit data as another agent;
- escalate into the server or the console, for example through stored
  content that renders as script for an operator (dynamic console content is
  escaped before it is written into markup, which a static test enforces,
  and the CSP blocks injected scripts), or through oversized messages (the
  broker caps message size and the server caps request bodies).

Revoking that agent's credential cuts it off without touching the others.
Its current connection lasts until its broker token expires (at most an
hour); after that the broker refuses it until it is enrolled again.

**An unauthenticated or low-privileged web user** should not be able to:

- complete first-run setup: creating the first administrator needs the
  one-time setup token printed in the server log (or set with
  `MUSTRA_SETUP_TOKEN`), so a freshly started but unconfigured server cannot
  be claimed by whoever reaches it first;
- sign in with an identity outside the OIDC allowlist, or guess a local
  password quickly (sign-in attempts are rate-limited per address and
  account);
- perform any action their role does not grant, through the console or the
  API;
- learn internal details from failures: a 500 response carries only a
  request ID, and the details go to the server log.

### Known limits

- Anyone with `deploy.manage` (packages, custom sensors) or Direct Connect
  can run arbitrary code as root/SYSTEM on targeted endpoints. Grant those
  permissions accordingly.
- The break-glass local account bypasses OIDC by design. Keep its password
  in a vault and its use audited.
- Agents installed before per-agent enrollment keep using the shared legacy
  credential until they re-enroll, and only while an administrator allows it
  (it is off on fresh installs). While it is allowed, a holder of that
  credential has the old, fleet-wide agent permissions.
- Agents that predate signed updates update by running the install script
  fetched from the public URL; their update is only as trustworthy as that
  URL's TLS.
- Agent-reported values are stored and displayed as reported; the server
  escapes them for display and bounds their size, but does not check them
  against a schema.
- macOS agents are ad-hoc signed; Full Disk Access grants are tied to the
  binary, as described in the README.
- The vulnerability feed (OSV, the Debian security tracker) is trusted for
  what it says about packages; it cannot cause execution on endpoints.
