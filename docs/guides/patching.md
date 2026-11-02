# Patch endpoints
<!-- group: Deploy and patch; order: 34; pages: /patches -->

See which operating system and application updates each endpoint is missing, and install them now or on a schedule, with control over what is allowed.

## Before you start

- You need **Manage patches** (`patches.manage`).
- Each endpoint reports its missing updates through its own update system: Windows Update on Windows, `softwareupdate` on macOS, and apt or dnf on Linux. A Windows search can take several minutes the first time.

## See what is missing

1. Open **Patch**. **Endpoint patch readiness** summarises how many endpoints are up to date.
2. **Missing patches** lists each update and how many endpoints need it, with its severity where the vendor gives one.
3. **Devices** lists endpoints and how many updates each is missing.
4. To refresh a list now rather than wait for the next collection, choose **Rescan now**.

## Patch now

1. In **Missing patches** or **Devices**, tick what you want (**Select all shown** for everything filtered).
2. Choose **Apply patches to selected**.
3. Choose whether endpoints may restart, and confirm.
4. Follow progress under **Recent activity**.

## Patch on a schedule

1. **Patch → Deploy & Schedule**, under **Scheduled & recurring deployments**, choose **New schedule**.
2. Pick the computer groups, the days and time, and the restart behaviour.
3. Choose **Create schedule**. Schedules respect maintenance windows.

A common setup is a pilot group on Tuesday night and everyone else on Thursday night, so a bad update shows up on a few machines first.

## Allow, hold back and pin updates

**Patch Lists** control what a patch run may install:

- A **patch list** names the updates allowed; a **block list** names updates that must never be installed (for example a driver that broke laptops).
- **Assignments** apply lists to computer groups.
- **Repository lists** (Linux) choose which package repositories updates may come from.

Choose **Save list**, then **Assign** it. **Export JSON** and **Import JSON** move lists between servers.

## Read the results

Each patch run reports per endpoint which updates installed, which failed, and whether a restart is pending. An endpoint that was offline when the run started reports **no response**, which is different from **failed**.

## If something goes wrong

- **A Windows endpoint shows no patches at all:** the first Windows Update search can take up to ten minutes; check again later. If it stays empty, look under **Client Health**.
- **Linux shows updates that will not install:** the repository may require a newer package manager key; run `apt-get update` on the endpoint through Direct Connect to see the error.
