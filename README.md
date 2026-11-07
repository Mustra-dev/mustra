# mustra

Open-source, self-hosted fleet management and endpoint operations for
Linux, macOS and Windows. Put a lightweight Go agent on every device, ask
the whole fleet a question in one line, act on the machines that answer,
and keep a record of what was done.

![Interact: one query across the fleet, answered from inventory](docs/images/interact.png)

- **Self-hosted, and nothing phones home.** One Docker Compose stack
  (Postgres and NATS) on your own hardware. Agents only connect outbound
  to your server and accept no inbound connections. No telemetry, no
  licence check.
- **Free, under the AGPL-3.0.** Every feature, with no paid tier.

## ✨ What it does

- 🔍 **Interact:** `get os from all machines with online equals true`.
  Identical answers collapse into counted rows, so a query stays readable
  at any fleet size.
- 📦 **Deploy and Patch:** install, update and remove software, or run
  commands, in rollout rings that halt when a ring fails. Schedules,
  maintenance windows, and playbooks that patch, wait for the reboot,
  verify, then tell the user.
- 🛡️ **Comply and Enforce:** CIS benchmarks from Wazuh's published SCA
  policies (Wazuh itself isn't needed). Desired-state settings start in
  report mode, and a check mustra can't evaluate reports `unknown`, never
  `pass`.
- 🧪 **Vulnerabilities:** OSV matches, ranked by CISA's Known Exploited
  Vulnerabilities catalog and EPSS rather than by CVSS alone.
- 🚨 **Threat response:** IOC matching, an activity recorder with rules,
  file integrity monitoring, sensitive-data discovery, and a live process
  tree.
- 🖲️ **Direct Connect and Jump Gate:** interactive commands on an
  endpoint, each one logged before it's sent, with just-in-time access
  behind an approver.
- 📜 **Inventory:** software usage and cost, certificates fleet-wide,
  hardware, users, and devices on the network that mustra doesn't manage.
- 🐳 **Containers:** every Docker and Podman container across the fleet,
  and which images have an update. It only reports, so nothing is pulled
  or restarted.
- 🔐 **Access control and audit:** OIDC SSO, SCIM, RBAC, two-person
  approvals, and one audit log you can stream to your SIEM.
- 🪟 **For the people at the keyboard:** a Self Service app, notices,
  restart prompts they can postpone a limited number of times, and
  surveys.

[docs/CONCEPTS.md](docs/CONCEPTS.md) explains each module and why it works
the way it does.

| | |
| --- | --- |
| ![Home](docs/images/home.png) | ![Vulnerabilities](docs/images/vulnerabilities.png) |
| ![Deploy](docs/images/deploy.png) | ![Patch](docs/images/patch.png) |

## 🚀 Quick start

You need one Linux or macOS host with Docker and `openssl`.

```sh
git clone https://github.com/mustra-dev/mustra.git && cd mustra
make quickstart
```

This generates secrets and certificates, builds the images, and waits
until the console answers. The first build takes a few minutes.

1. Open the one-time setup link it prints and create the administrator
   account. There is no default password, and the link stops working once the
   account exists.
2. Give the console its HTTPS address, which agents install and update from.
   Follow [deploy/README.md](deploy/README.md#public-access), or enter it under
   **Administration → Agent Identity**.
3. Go to **Client Management → Manual Install**, create an enrollment token, and
   copy the install command for each platform. The command checks everything it
   runs before running it.

   The endpoint appears within seconds. To reach many hosts at once, use
   **Network Scan & Push**.

On macOS, give the agent **Full Disk Access**
([why, and how to do it with an MDM](docs/guides/install-agents.md)).

**What leaves your network:** nothing goes to the mustra maintainers. By
default, the server sends package names and versions to
[OSV](https://osv.dev) (never hostnames or anything else about your fleet)
and downloads public vulnerability feeds. [PRIVACY.md](PRIVACY.md) lists
every connection.

## 📚 Docs

- [Concepts](docs/CONCEPTS.md): what each module does
- [Architecture](docs/ARCHITECTURE.md): how it's built, and why
- [Development](docs/DEVELOPMENT.md): run it from source, with no container rebuilds (`make help` lists every target)
- [Roadmap](docs/ROADMAP.md): what has shipped and what is planned
- Step-by-step guides: under **Help** in the console, and in [docs/guides](docs/guides)

## 💬 Getting help

- **A bug or an idea:** [open an issue](https://github.com/mustra-dev/mustra/issues/new/choose).
  Issues are public, so leave out hostnames, IP addresses and usernames.
- **A question, or something you'd rather not post publicly:** email
  **support@mustra.dev**.

## 🔒 Security

mustra runs commands as root or SYSTEM on every endpoint it manages, so here
is exactly what you are trusting.

- **How an agent enrolls:** with a token that has limited uses and an expiry.
  It receives its own credential, and its permissions cover only its own
  messages, so a compromised endpoint can't command, read or impersonate
  another one. Revoking it takes effect within an hour.
- **Is the connection authenticated both ways?** Yes, though not with client
  certificates. The agent verifies the broker over TLS against your
  deployment's own CA, and the broker requires the agent's credential.
- **How do you know the install is genuine?** The command you copy from the
  console checks the installer's hash before running it, and the installer checks
  everything it downloads, including that CA, so a tampered download stops before
  anything changes.
- **Can the console run arbitrary commands?** By default, yes: that's the point of
  deployments, custom sensors and Direct Connect. Only people whose role allows it
  can run code, each action is in the audit log, and you can require a second
  person's approval.
- **Can I turn that off?** Yes, per endpoint. Choose **Inventory and patching
  only** when you create the enrollment token. Those endpoints keep reporting
  inventory, vulnerabilities and compliance, and take the updates their package
  manager offers from the repositories configured on the machine, but refuse
  everything else from the server. It's a file on the endpoint, so the server can't
  turn it off: only an administrator on that machine can. The trade-off is that you
  update those agents by running the installer on the machine.
- **What if the server is compromised?** So is every endpoint not in that mode. Only
  the server may send commands, and commands aren't individually signed, so protect
  it like you would your SSH keys. Agent updates are signed, against a key each
  agent pins at enrollment.
- **Compared with Ansible:** Ansible needs no agent, but it needs inbound SSH or
  WinRM on every machine. mustra's agents open no ports and connect out, which
  suits a mix of Macs that change networks, Windows, and Home Assistant OS,
  where there's no host shell to SSH into.

The full threat model and known limits are in [SECURITY.md](SECURITY.md).
Release images are signed with cosign and ship with SHA256SUMS and an SBOM.

**Found a vulnerability?** Report it privately: email **security@mustra.dev**,
or [open a private report](https://github.com/mustra-dev/mustra/security/advisories/new).

## 📄 License

[AGPL-3.0](LICENSE). Self-hosting, modifying and commercial use are all
allowed. The AGPL's obligations apply if you offer mustra to others as a
service. mustra comes with **no warranty**, and you may use it only on
devices you're authorized to manage. See the [Terms of Use](TERMS.md) and
[Privacy](PRIVACY.md).

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) asks for a
`Signed-off-by` line on each commit.
