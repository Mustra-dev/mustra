# Threat response
<!-- group: Secure; order: 45; pages: /hunt -->

Look for signs of an attack: known-bad files, processes and addresses (indicators), suspicious behaviour (signals), and a live feed of what endpoints are doing.

## Before you start

- Reading findings and activity needs **See the fleet**. Creating indicators and signals, and acknowledging findings, needs **Manage settings** (`settings.manage`).

## Add an indicator

An indicator is one thing known to be bad: a file hash, a file name, a process name, an IP address or a domain.

1. Open **Threat Response → Indicators**, then **New indicator**.
2. Choose its kind, paste the value, give it a name, a severity and where it came from (for example an incident number).
3. Choose **Save indicator**.
4. Choose **Hunt now** to check every endpoint. Process names are also matched the moment a process starts.

Matches appear under **Findings**. mustra never kills a matching process by itself; that is your decision, from the endpoint's page.

## Write a signal

A signal is a rule over what endpoints do, for example:

```
process.name contains 'powershell' AND process.command_line contains '-enc'
```

1. **Signals → New signal**, write the rule, set a severity.
2. Choose **Test against recent events** to see what it would have caught.
3. Choose **Save signal**. Matches appear under **Signal findings**.

## Watch live activity

**Live Activity** shows what ran and what connected, across the fleet, as it happens. Switch between **Processes**, **Network**, **DNS**, **Registry** and **Logons**.

How much is seen depends on the platform, and the page says which mechanism each endpoint uses: on Linux every process start is seen; on Windows and macOS, processes that live longer than a few seconds. A quiet feed from a Linux endpoint means nothing ran.

## Respond

From a finding, open the endpoint and:

- **Kill** the process (mustra checks the process name again first).
- Open **Direct Connect** to investigate. See [Direct Connect and remote desktop](remote-access.md).
- Revoke the endpoint's credential to cut it off.
