# Administration
<!-- group: Run mustra; order: 60; pages: /settings -->

Configure the server: integrations, how agents behave, network allowlists, branding, telemetry, API tokens and the break-glass account.

## Before you start

- You need **Manage settings** (`settings.manage`). Some sections also need a permission of their own, named on the section: **Change network allowlists**, **Change agent trust**, **Manage sign-in**, **Manage integrations**.
- Every change here is written to the audit log.

## What is where

| Section | What it does |
| --- | --- |
| **Integrations** | Connect outside systems: email, Slack and Teams, event streaming, Microsoft Entra ID and Intune, certificate authorities |
| **Telemetry** | Send endpoint metrics to Prometheus (remote write), or let Prometheus scrape them |
| **Single Sign-On** | Identity providers and the SSO allowlist. See [Accounts, roles and sign-in](users-and-access.md) |
| **SCIM** | Let your identity provider create and disable accounts automatically |
| **Break-glass Account** | The local administrator that still works when SSO is down, and the two-step sign-in requirement |
| **Agent Behavior** | How often agents report, and default sensor settings |
| **Agent Identity** | The addresses agents connect to and download from |
| **Uninstall Password** | A password the agent uninstaller asks for, so users cannot remove it |
| **macOS MDM** | Enrol Macs in your MDM, and run macOS updates through it |
| **Email** | The SMTP account reports and Email integrations send through, and a test send |
| **Network Allowlists** | Which internal hosts the server may reach (webhooks, syslog, LDAP) and import from |
| **Message Buffer** | How long agent messages are kept when the server cannot process them |
| **Directory** | Read Active Directory over LDAP, for targeting and Impact |
| **Branding** | Your logo in the console |
| **API Tokens** | Tokens for scripts and other systems. See [Automate with the API](api.md) |
| **About** | This build's version, the agent versions in the fleet, updates and the changelog |

## The break-glass account

Keep at least one local administrator with a strong password and two-step sign-in, stored somewhere safe offline. When your identity provider is down, it is the only way in.

## Upgrades

**Administration → About** shows the running version and the changelog. Upgrading the server is done where it runs; see [Install the server](install-server.md). After an upgrade, update agents from **Client Management**.

## Customize your emails

Everything mustra emails can be rewritten under **Administration → Email → Templates**: the subject, the plain text and the HTML. Pick the kind of email, edit it, and use **Preview** to see it with invented data, or **Send test** to see it in your inbox. A blank field uses the default.

A **report** or an **Email integration** can have its own wording, which comes first. Each field stands alone, so you can change only a subject.

Templates use [Go template](https://pkg.go.dev/text/template) syntax:

```
[{{.Vars.company}}] {{upper .Severity}}: {{.Title}}

{{if .Detail.items}}{{range .Detail.items}}- {{.id}} on {{join ", " .hosts}}{{if .kev}} (actively exploited){{end}}
{{end}}{{else}}{{.Body}}{{end}}
{{if .Link}}Open in mustra: {{.Link}}{{end}}

{{template "signature" .}}
```

- **Variables** come from the email itself (`{{.Title}}`, `{{.Severity}}`, `{{.Detail.endpoints}}`), and the page lists what each kind of email has. A variable an email doesn't have prints as nothing.
- **Your own variables**, set under **Variables and macros**, work everywhere as `{{.Vars.company}}`. Don't put passwords in them.
- **Macros** are reusable blocks. Define `{{define "signature"}}The {{.Vars.company}} IT team{{end}}` under **Variables and macros**, and use it anywhere as `{{template "signature" .}}`.
- **Functions** such as `upper`, `join`, `date` and `percent` are listed on the page. `if`, `range`, `eq`, `lt`, `gt`, `and`, `or` and `not` are built in. To compare a count, use `int`: `{{if gt (int .Detail.kev) 0}}`.

In HTML, values are escaped for you, so a strange hostname can't change your layout. For a report, `{{.Report.Document}}` is the whole page and `{{.Report.Content}}` is just its sections, to place inside your own layout.

**If a template fails** when an email is being sent, mustra sends its default wording instead, with a note at the top saying what went wrong. An alert is never lost to a typo. Saving also checks a template, and refuses one that calls itself.

## Get an email when something finishes

This is off until you ask for it. Under **Integrations**, tick **Completed actions** on an integration, then choose which: deployments and patch runs, playbooks, backups, compliance scans, Enforce runs, IOC hunts, sensitive-data scans, certificate renewals, vulnerability scans or reports. Choosing none means all of them.

**Minimum severity** decides how many you get: **info** tells you about every one, and **warning** only about those that failed or partly failed. IOC hunts run every 15 minutes, so a scheduled one announces only when it finds something, and one you start always does. A hunt or sensitive-data scan that finds something still counts as succeeded: findings have their own alerts. A compliance scan counts as failed only when an endpoint didn't answer: failing checks are what it's there to find, and they have their own alert. Likewise, drift in report mode isn't an Enforce failure. Vulnerability scans run every six hours, and Enforce runs on each policy's timer, so choose what you'd really read. A daily compliance scan sends one email per benchmark. This works with any integration, not only email.
