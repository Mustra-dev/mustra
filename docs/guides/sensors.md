# Sensors and custom sensors
<!-- group: See your fleet; order: 22; pages: /sensors -->

Sensors are what every agent measures about its own machine. Thirteen are built in; write your own custom sensor to answer questions only your organisation has.

## Before you start

- Reading sensors needs **See the fleet**. Writing custom sensors needs **Deploy software and run actions** (`deploy.manage`), because a custom sensor runs your script on endpoints with full rights.

## The built-in sensors

Processes, services, installed applications, patches, disks, network interfaces, signed-in users, hardware, privileges, network neighbours, certificates, performance and file integrity.

Each runs on a timer (every 15 minutes by default) and the server keeps the latest result per endpoint. That is why questions in Interact are instant.

- **Sensors → Catalog** lists every sensor, what it answers and exactly how it collects on each operating system. Choose a sensor to read its source, or **Clone into custom sensor** to start your own from it.
- **Sensors → Fleet Coverage** shows, for each sensor, how many endpoints report it and how old the newest and oldest results are. Start here when an answer looks incomplete.

## Write a custom sensor

1. Open **Sensors** and choose **New custom sensor**.
2. Give it a **Name** and a **Description**.
3. Under **Script per operating system**, choose the **Linux**, **macOS** or **Windows** tab and write the script. Leave a platform empty to skip it. For each, pick an **Execution type**: shell, PowerShell, CMD, bundled Python 3, a compiled Go program, or (Windows) a WQL query.
4. Choose the **Output format** the script prints: text lines, JSON, JSON Lines or delimited rows.
5. Under **Result fields**, choose **Add field** for each value, with its name and type. Paste example output into **Sample output for active platform** and choose **Parse sample** to see how it is read.
6. Pick a **Test endpoint** and choose **Run on selected endpoint**. The result shows exactly what that endpoint returns, before anything is saved.
7. Set **Run every (seconds)** (at least 60) and **Timeout (seconds)**.
8. Tick **Enabled on all endpoints with a configured platform** when you are ready, and choose **Save sensor**.

### An example: is a reboot pending?

Linux, shell, text lines:

```
if [ -f /var/run/reboot-required ]; then echo yes; else echo no; fi
```

Windows, PowerShell, text lines:

```
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { 'yes' } else { 'no' }
```

One field, `pending`, type string. After it has run once everywhere, ask Interact: `get hostname from all machines with <your sensor name>.pending equals yes`.

## Use the results

- **results** next to a custom sensor shows the latest value from each endpoint.
- Its fields appear in Interact questions, computer group rules, dashboards and reports, like any built-in field.

## If something goes wrong

- **A result is "unknown":** the script failed, timed out, or the endpoint has not run it yet. The endpoint test shows the error output.
- **Nothing ever arrives from Windows:** check the script in an elevated PowerShell on that machine; it runs as SYSTEM, which has no mapped drives and no user profile.
