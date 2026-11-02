# Reveal sensitive data
<!-- group: Secure; order: 46; pages: /reveal -->

Find which endpoints hold card numbers, national ID numbers, private keys or cloud credentials, and in which files, without the data ever leaving the endpoint.

## Before you start

- Reading results needs **See the fleet**. Creating rules and scanning needs **Deploy software and run actions** (`deploy.manage`).

## How it protects the data

The agent searches files on the endpoint and confirms matches there (a card number must pass the Luhn check, for example). Only the path, size, date and a masked snippet such as `**** **** **** 1111` come back. The file's contents never leave the machine.

## Find something once

1. Open **Reveal → Quick Search**.
2. Type the text to look for, choose the endpoints, the folders to search and the file types.
3. Choose **Search**. Results arrive as each endpoint finishes.

## Scan on a schedule

1. **Reveal → Rules**, then **New rule**.
2. Pick the patterns (card numbers, US Social Security numbers, IBANs, private keys, cloud keys, and others), or **Add custom pattern** with your own expression.
3. Set the folders to search per operating system, the endpoints or groups, and how often.
4. Choose **Save and scan now**, or **Save rule** to wait for the schedule.

**Rule sets** group rules for a purpose; templates for PCI, HIPAA/PII, GDPR and secrets are a starting point.

## Read the results

- **Overview** shows confirmed findings by pattern and the endpoints with the most confirmed files.
- **Results** lists every file, with **Export CSV** for remediation tracking.
- **Scans** shows each scan's progress, and how many files were skipped (binaries, PDFs, files over the size limit).

Scans have limits (200,000 files, 15 minutes, 5,000 matches per endpoint) so they never overwhelm an endpoint.
