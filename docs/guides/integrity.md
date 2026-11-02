# Integrity monitoring
<!-- group: Secure; order: 44; pages: /integrity -->

Know when important files, folders and Windows registry keys change, on which endpoint, and whether the change was expected.

## Before you start

- Reading changes needs **See the fleet**. Creating watchlists, monitors and labels needs **Manage settings** (`settings.manage`). Acknowledging changes needs **Triage alerts** (`alerts.triage`) or **Manage settings**.
- Every endpoint already watches a built-in set of system locations. Watchlists add your own.

## Watch something new

1. Open **Integrity Monitor → Watchlists** and choose **New watchlist**, or **Use template** to start from a ready-made list (PCI-DSS, CIS Controls, HIPAA, SOX, NERC-CIP, Microsoft Exchange, persistence locations).
2. List the paths to watch, one per line: files or folders, on any operating system (`/etc/nginx`, `C:\inetpub\wwwroot\web.config`). On Windows, add registry keys too. An endpoint skips paths its system does not have.
3. Choose **Save watchlist**.
4. **Monitors → New monitor**: pick the watchlist and the computer groups it applies to, then **Save monitor**.
5. Choose **Push to endpoints now**, or wait up to five minutes. **Coverage** shows which endpoints are watching it.

## Read changes

- **Changes** lists every change with the endpoint, the path, what happened (created, modified, deleted, permissions changed) and when.
- **Unexpected change by endpoint, last 7 days** shows where unexplained changes cluster.
- **Live events** streams changes as they arrive.

## Mark ordinary changes as expected

Package updates and log rotation change files all the time. A **label** says which changes are normal, so they stop looking alarming.

1. **Labels → New label**: describe the change (paths, endpoints, the process or time window).
2. Choose **Test against recent changes** to see which past changes it would have matched.
3. Choose **Save label**. Matching changes are shown as expected.

## Acknowledge a change

After investigating an unexpected change, choose **acknowledge** on it. It stays in the history, marked with who acknowledged it.
