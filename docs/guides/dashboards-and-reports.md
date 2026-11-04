# Dashboards and reports
<!-- group: See your fleet; order: 24; pages: /dashboards, /reports -->

Build dashboards to watch what matters to you, raise alerts when a number crosses a line, and send scheduled reports to people who never sign in.

## Before you start

- Reading and building your own dashboards needs **See the fleet**. Shared dashboards you did not create can be edited by their owner or someone with **Manage settings**. Custom alerts need **Manage settings**.

## Build a dashboard

1. Open **Dashboards** and choose **New dashboard**. Give it a name and description.
2. Choose **Add a panel** for each chart. A panel has:
   - a **source**: endpoints, vulnerabilities, patches, compliance results, software, a saved question, and others;
   - what to **group by** (for example operating system), or a **filter** (for example severity equals critical);
   - a **chart**: number, bar, stacked bar, donut or table;
   - optionally, computer groups to limit it to.
3. Choose **Preview** to check a panel, and **↑**/**↓** to order them.
4. Tick **shared** if everyone should see it, and choose **Save dashboard**.

Choose **Show on Home** to put a dashboard on your Home page, or **Add to Home list** to keep it one click away there. **Clone** copies a dashboard to change it.

Ready-made dashboards are included; open them from **All Dashboards**.

## Raise an alert from a number

1. **Dashboards → Alerts → New alert**.
2. Choose a panel and a threshold, for example "critical vulnerabilities greater than 0".
3. Choose **Save alert**. When the number crosses the line, an item appears in **Guide**. **Evaluate now** checks it immediately.

## Send a report

A report is a page of tables and charts, rendered on a schedule and delivered by email, or to Slack, Discord, a webhook, syslog or a file on the server.

1. Open **Reports** and fill in **New report**: a name and description.
2. Choose **Add a section** for each part: its source, what to group by, the columns, a filter and a row limit. **Load the weekly-health example** fills in a typical report.
3. Choose the schedule (**Daily** or **Weekly**, at a time) and where it goes: **Email** (set up under [Administration → Email](administration.md) first), **Slack**, **Discord**, **A webhook**, **Syslog** or **A file on the server**.
4. Choose **Save report**.
5. **Preview** shows it now; **Run & send** sends it now.

**Renderings** keeps every report that was sent, so you can see exactly what someone received.
