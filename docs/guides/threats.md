# Threat briefings
<!-- group: Secure; order: 41; pages: /threats -->

A page per vulnerability attackers are exploiting right now: which endpoints have it, which versions are affected, and how to hunt for signs it was used.

## Before you start

- Reading briefings needs **See the fleet**. Writing briefings, changing settings and patching from here need **Manage patches** (`patches.manage`).

## What is here

mustra downloads CISA's **Known Exploited Vulnerabilities** catalogue several times a day. Every entry from the last 30 days, and any older one found in your fleet, gets a briefing card with:

- **Vulnerable**: endpoints where the vulnerability scan matched an installed version.
- **Product present**: endpoints that have the product installed, whatever the version. Check these by hand when the scan does not cover their platform (for example Windows software).
- **EPSS**, the date CISA added it and CISA's due date for fixing it.

Use the filters at the top: **All**, **In this fleet**, **Vulnerable**, **Written briefings**, **Ransomware**, or search by name, CVE or vendor.

## Act on a briefing

1. Choose a card to open it. **Affected endpoints** lists the machines.
2. Choose **Patch vulnerable endpoint** or **Patch endpoint with the product** to deploy pending patches to them.
3. **Hunting** lists what to look for if you suspect the flaw was used before you patched. Turn those into indicators under [Threat response](hunt.md).

## Write your own briefing

For a threat that is not in CISA's list, or to add your organisation's own guidance:

1. Choose **Write a briefing** (or **Write a briefing from this** on an existing card to start from it).
2. Fill in the summary, affected products, mitigation, references and hunting notes.
3. Choose **Save**. It appears under **Written briefings**.

## Automatic remediation and alerts

At the top of the page, **Automatic remediation** can patch vulnerable endpoints a set number of days after a KEV entry appears, and **Past-due alerts** raise a Guide item when CISA's due date passes with endpoints still vulnerable. Choose **Change** to set them.
