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
