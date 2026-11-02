# mustra

[mustra.dev](https://mustra.dev) — an open-source fleet management and
endpoint operations platform. A lightweight Go agent on every device, NATS
as the outbound-only message backbone, and a web console for live
visibility and control. Ask every machine a question, deploy to the ones
that answer, and keep the record of what happened.

Every module below is in daily use on a real fleet rather than sketched.
The console starts empty and fills as your agents check in — mustra ships
no sample data.

**Run it:** [Quick start](#-quick-start) is three steps.
**Change it:** [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) is a `go run`
loop that never rebuilds a container.
**Understand it:** [docs/CONCEPTS.md](docs/CONCEPTS.md) is what each part
does and why.

## ✨ Features

- 🔍 **Interact**: Query the whole fleet in one line — `get os from all machines with online equals true`. Identical answers collapse into counted rows, so one query stays readable at any size.
- 📡 **Sensors**: Thirteen built-in measurements, each documenting *exactly* how it gets its answer per platform, plus live coverage of who is reporting and how stale it is. [Write your own.](docs/CUSTOM-SENSORS.md)
- 🎯 **Computer Groups**: Reusable slices of the fleet matched *live* against 60+ inventory and sensor fields, so "all Windows Servers missing more than five patches" stays correct as machines come and go.
- 📦 **Deploy**: Software packages (install/update/remove, verified by finding it installed) and action packages (run a command). Every endpoint is classified before anything runs, and rollouts go out in rings that halt when a ring fails.
- 🗃️ **Software Inventory & Usage**: Installed apps turned into products — one name across platforms and versions — with how much each is actually used, what it costs, and what nobody has opened in months.
- 🩹 **Patch**: Fleet-wide missing-patch visibility, one-off or scheduled, narrowed by patch and block lists scoped per host, site or platform. Runs are watchable live, down to the machines behind each count.
- ⏱️ **Schedules & Maintenance Windows**: Run any package nightly, weekly or once, through the same code path an interactive deploy uses — and say when a group of endpoints may be touched at all.
- 🎭 **Playbooks**: Several actions in order, per endpoint — patch, wait for the reboot, verify, tell the person. Each machine walks the steps at its own pace, so one slow box doesn't hold up the rest.
- 🛡️ **Comply**: CIS benchmarks read straight from Wazuh's published SCA policies, so real CIS content runs without running Wazuh. A rule the engine can't evaluate reports `unknown`, never `pass`.
- 🔒 **Enforce**: Desired state rather than a finding — a setting says what must be true and carries the command that makes it true again. Starts in report mode, re-checks after fixing, and stops retrying an endpoint that fails three times.
- 🧪 **Vulnerabilities & Exploitability**: Findings from OSV joined to CISA's Known Exploited catalogue (pulled every six hours) and EPSS (daily), so the list is ordered by what somebody is actually using rather than by CVSS alone.
- 🚨 **Threat Response**: IOCs matched against cached sensor data on a timer *and* as things happen, so a watched file being written raises its finding at the moment it does.
- 🎬 **The recorder & Signals**: What a machine did, not just what it has — network connections, logons, registry persistence keys and DNS lookups, with a rule language over the stream.
- 🧬 **Integrity Monitor**: Hash baselines diffed server-side (an attacker who can rewrite the file can rewrite a baseline beside it) plus real-time change events. Change mustra itself caused is labelled as such.
- 🕵️ **Reveal**: Which endpoints hold card numbers, SSNs, private keys or cloud credentials, and in which files — patterns run on the endpoint, confirmed by validators, and never shipped back as content.
- 🧯 **Live Response**: One endpoint, mid-incident: a filterable process tree with full command lines and an audited kill that refuses if the PID no longer matches the name it was told.
- 🖲️ **Direct Connect & Jump Gate**: Run commands on an endpoint interactively, every one logged *before* it is sent — with just-in-time access behind a reason, an approver, and a clock that starts at approval.
- 🧭 **Impact**: If this account, group or endpoint were compromised, what else could it reach? Built from Active Directory over LDAP and what each endpoint reports about its own logons.
- 📜 **Certificate Manager**: Every X.509 certificate across the fleet, soonest to expire first. One certificate on five hosts is one row with five locations, and OS trust stores stay separate from service certificates.
- 📊 **Dashboards & Reports**: Panels over the same sources everything else exports, and a rendered page for the person who never opens the console — on a schedule, kept as history, delivered as HTML or a digest.
- 🔌 **Connect**: Standing exports to a webhook (Discord and Slack shapes built in), a file, or syslog — JSON, NDJSON, CSV, CEF, RFC 5424.
- 🔔 **Notify & Engage**: Tell people something (a notice, or a restart prompt that negotiates with a deadline and bounded postponements), or ask them something — surveys with a sentiment score that declines to lie when the sample is thin.
- 🪟 **Self Service**: An installed app on macOS and Windows showing what mustra has done to that machine, what software it may install, and whether its own agent is behind. Authorization stays server-side.
- 🖥️ **Client Management**: The agents are a managed thing, not a script somebody ran — install by one-liner or SSH scan-and-push, a credential vault, client health and profiles, upgrade rings, and version-rollout visibility.
- 🩺 **Performance**: Endpoint health scored from locally-sampled metrics, plus a risk score weighted by how much each endpoint actually matters.
- 🔐 **Access control**: Management rights, per-module action groups, content sets, and approvals that replay the parked request as the requester. All four default to "everything", so nothing changes until you configure them.
- 🗄️ **Backup & Restore**: The whole control plane, nightly or on demand, to a retention you set — restored in a single transaction, with what it deliberately leaves out stated on the page.
- 🖧 **Discover**: What's on the network that mustra doesn't manage, built from endpoints' own ARP tables — zero packets, nothing for an IDS to flag.
- ⚙️ **Administration**: OIDC SSO, SCIM 2.0 provisioning, RBAC, API tokens, runtime log level, and one audit log that streams live to syslog, Splunk, Loki or any SIEM.

Every action lands in that audit log, written *before* it is sent.
[docs/CONCEPTS.md](docs/CONCEPTS.md) covers each of these properly;
[docs/ROADMAP.md](docs/ROADMAP.md) has what's shipped versus deliberately
deferred.

## 🚀 Quick start

One Linux or macOS host with Docker and `openssl`. Postgres 18 ships inside
the stack, so there is nothing else to install — and
[why it isn't swappable](docs/ARCHITECTURE.md#postgres-is-required-not-merely-the-default)
is written down rather than left as an unfinished abstraction.

**1. Bootstrap the control plane.**

```sh
git clone https://github.com/mustra-dev/mustra.git && cd mustra
make quickstart               # or: ./deploy/init.sh --start
```

That is the whole install: it checks the machine can do the job, writes
`.env` with generated secrets, issues NATS certificates carrying this
host's LAN address, builds the images, and waits until the console answers
before telling you it is up. The first build takes a few minutes — it
cross-compiles the agent for six OS/architecture pairs and packages a
private Python runtime for each, so endpoints can install without reaching
the internet. Re-running never overwrites an existing `.env` or
certificates; `--ip` and `--public-hostname` cover a wrong guess and a
console behind HTTPS.

**2. Create the administrator.** Open `http://<host>:8080/`. There is no
default credential; the setup page closes for good once the first account
exists, so do this when you start it rather than leaving a fresh console
open to the network.

**3. Install an agent.** **Client Management → Manual Install** has the
one-liner for each platform, with this server's address and NATS
credentials already in it:

```sh
curl -fsSL http://<host>:8080/install.sh | sudo bash          # Linux, macOS
irm http://<host>:8080/install.ps1 | iex                       # Windows, elevated
```

The agent needs administrative rights and refuses to run without them
rather than half-installing. The endpoint appears within seconds. To reach
many hosts at once, use **Network Scan & Push**.

> **On macOS, root is not enough.** TCC guards Desktop, Documents,
> Downloads, Mail and Photos regardless of privilege, so without **Full
> Disk Access** an inventory or compliance rule covering those paths
> reports nothing rather than reporting a refusal. Add
> `/opt/mustra-agent/mustra-agent` under **System Settings → Privacy &
> Security → Full Disk Access** (the picker hides `/opt` — press
> **Cmd-Shift-G** and paste the path). Expect to re-grant after an upgrade:
> a grant is tied to the binary's identity and this agent is ad-hoc signed.
> To avoid that, push the PPPC profile from **Deploy Agents → Manual
> Install** through an MDM the Mac is enrolled in: it matches the path and
> the identifier the installer pins, so it keeps matching after an upgrade.
> Set **Settings → macOS MDM enrollment** and unenrolled Macs are sent to
> your MDM's enrollment page instead of being asked for a hand grant.

**4. Then, optionally:** import a real CIS policy from
[Wazuh's SCA ruleset](https://github.com/wazuh/wazuh/tree/main/ruleset/sca)
under **Comply → Policies**; read **Sensors → Catalog** to see exactly what
is being collected and how; build a package in **Deploy** (the
[Deploy guide](docs/DEPLOY.md) and
[Action Packages](docs/ACTION-PACKAGES.md) cover authoring, version pins
and retiring a version); and point **Administration → Logging** at your
SIEM.

**Public access.** Put any TLS-terminating reverse proxy in front of port
8080 and set `MUSTRA_COOKIE_SECURE=true` in `deploy/.env`. A Cloudflare
Tunnel is wired up as an optional compose profile — see
[deploy/README.md](deploy/README.md).

**What leaves your network:** only two things, and only from the server.
Vulnerability matching sends package **names, ecosystems and versions** to
[OSV](https://osv.dev) — never hostnames or anything else about your fleet
— and the Debian security tracker's feed is downloaded. Agents accept no
inbound connections at all.

## 🗂️ Layout

```
/cmd/agent          endpoint agent binary
/cmd/server         control-plane API + NATS consumers
/cmd/console        web console entrypoint (merged into cmd/server for now)
/internal/agent     agent internals (sensors, patches, query handling)
/internal/server    server internals (HTTP/SSE API, deploy tooling, patch
                     scheduler, vulnerability scanner, sensor catalog)
/internal/nats      subject builders + connect/JetStream helpers
/internal/proto     shared message types (agent ⇄ server, one source of truth)
/internal/store     Postgres access
/deploy             docker compose control plane, bootstrap script, dev services
/docs               CONCEPTS, ARCHITECTURE, DEVELOPMENT, DEPLOY, ROADMAP
```

## 🔧 Development

```sh
make dev-up       # NATS and Postgres in containers, published on localhost
make dev-server   # the server from source, console at http://localhost:8080 (admin / admin)
sudo make dev-agent   # an agent from source, in another terminal
make check        # gofmt, go vet, go build, go test: what CI runs
```

[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) covers every setting,
cross-compiling the agent, what runs where, and how to reset. `make help`
lists every target.

## 🔒 Security

mustra runs commands as root/SYSTEM on every endpoint it manages, so
please report vulnerabilities **privately**, never in a public issue:
[open a private report](https://github.com/mustra-dev/mustra/security/advisories/new).
[SECURITY.md](SECURITY.md) covers supported versions, what to expect, and
the security model. Release images are signed with cosign (keyless) and
every release carries SHA256SUMS and an SBOM (plus build-provenance
attestations while the repository is public); `.github/workflows/release.yml` shows how to verify them.

## 💙 Supporting mustra

mustra is free and always will be. If it's useful to you, sponsorship helps
it keep getting built — see the Sponsor button on the repository.

## 📄 License

**GNU Affero General Public License v3.0** ([LICENSE](LICENSE)) — the same
license Grafana and Mattermost use, chosen for the same reason: it closes
the "service loophole" the GPL leaves open. Self-hosting it, modifying it
for your own fleet and using it commercially are all fine; the obligation
attaches when you offer it to others as a service.

Contributions welcome under the same license — see
[CONTRIBUTING.md](CONTRIBUTING.md), which asks for a one-line
`Signed-off-by` on each commit.
