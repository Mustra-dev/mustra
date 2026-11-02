# Connect: exports
<!-- group: Run mustra; order: 66; pages: /connect -->

Send mustra's answers to another system on a schedule: your full inventory to a CMDB, vulnerability findings to a SIEM, deployment results to a log platform.

## Before you start

- You need **Manage settings** (`settings.manage`).
- A destination inside your network (a webhook, a syslog server) must be on the internal destinations allowlist: **Administration → Network Allowlists**.

## Create an export

1. Open **Connect** and fill in **New export**.
2. **Name** it after where it goes.
3. Choose the **Source**:
   - **Endpoints — full inventory**: every endpoint, each run.
   - **Deployments — incremental** and **Query history — incremental**: only what is new since the last run.
   - **Vulnerability findings**.
   - **A saved query's answer**: pick the **Saved query**.
4. Choose the **Format**: **JSON**, **NDJSON** (one object per line, for Loki or Vector), **CSV**, **CEF** (ArcSight and most SIEMs) or **Syslog RFC 5424**.
5. Choose the **Destination**: **HTTP webhook** (plain, Discord or Slack style), **File on the server**, or **Syslog socket**, and enter the **Target** (a URL, a file name or a host and port).
6. Set **Run every (minutes)** and choose **Save export**.

## Check it worked

Choose **run now** on the export. Its row shows when it last ran and whether it succeeded; a failure says why (for example a refused connection or a destination not on the allowlist).
