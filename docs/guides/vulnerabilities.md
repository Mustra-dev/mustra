# Vulnerabilities and risk
<!-- group: Secure; order: 40; pages: /risk -->

Find which endpoints have known vulnerabilities, which of those attackers are actually using, and fix them by package.

## Before you start

- Reading findings needs **See the fleet**. Scanning and deploying fixes needs **Manage patches** (`patches.manage`).
- The scanner covers **Debian, Ubuntu and Alpine** packages. Windows and macOS endpoints show as *not scanned* here; use [Threat briefings](threats.md) and [Patch endpoints](patching.md) for them.

## Run a scan

1. Open **Vulnerabilities**.
2. Choose **Scan now**. The server compares every reported package against public advisories (OSV, and Debian's and Ubuntu's own trackers). It takes a minute or two.
3. Scans also run automatically; the page shows when the last one finished.

## Read the results

- **Vulnerabilities** lists each finding: the CVE, the package, the severity, how many endpoints have it, and two signals of real-world risk:
  - **KEV**: the U.S. CISA catalogue of vulnerabilities known to be exploited. A KEV badge means attackers use it now.
  - **EPSS**: the probability it is exploited in the next 30 days.
- **Devices** lists each endpoint with its counts by severity.
- **Exploitability** narrows the list to findings in KEV or with an EPSS of 1% or more. Start here.
- **Levels** gives each endpoint one vulnerability level from its latest scan, and flags operating systems past their vendor's end of security support.

Ubuntu findings are graded by Ubuntu's own priority, which reflects how the flaw affects Ubuntu as shipped; *negligible* ones are set aside.

## Fix them

1. Open **Remediation**. Findings are grouped by the package that fixes them, with the fixed version and the endpoints affected.
2. Choose **Deploy fix to affected endpoints now**, or **Schedule…** to do it in the next maintenance window.
3. Patch lists, block lists and maintenance windows apply, exactly as for any patch deployment.
4. Scan again afterwards; fixed findings drop off.

## An endpoint's operating system is out of support

**Levels** marks it **OS end of life**. Its vulnerabilities will never be fixed by patches; it needs an upgrade to a supported release. The **Upgrade OS release** example action in the repository's `docs/examples/actions` moves Ubuntu, Debian and Alpine to their next release.

## Mark how important an endpoint is

Under **Performance → Risk Score**, set an endpoint's **criticality** (for example a domain controller as critical). It raises the endpoint's risk score so its findings sort higher. Setting it needs **Manage patches**.
