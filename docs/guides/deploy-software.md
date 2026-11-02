# Deploy software
<!-- group: Deploy and patch; order: 30; pages: /software -->

Package an application once for Windows, macOS and Linux, then install, update or remove it on any endpoints, now or on a schedule, and see exactly what happened on each one.

## Before you start

- You need **Deploy software and run actions** (`deploy.manage`).
- Know how the application installs silently on each system: an MSI or EXE switch, a `.pkg`, a Homebrew formula, an apt or dnf package.

## The quickest way: add from the library

The library has ready-made packages for common applications (browsers, 7-Zip, VLC, Zoom and others) that install through winget on Windows, Homebrew on macOS and apt on Linux.

1. Open **Deploy → Software Catalog** and choose **Add from library**.
2. Find the application and choose it. It is added as a **draft**.
3. Open the draft, check its commands, and choose **Publish**. A package cannot be deployed until a version is published.
4. Deploy it as described below.

## Create a package yourself

1. **Deploy → Software Catalog → Create Software Package**.
2. Under **Package details**, enter the **Application name** and **Version number**.
3. Under **Platforms**, select each system the package supports: **Windows**, **macOS**, **Linux**. Select more than one and each endpoint gets the commands for its own system.
4. For each platform:
   - **Requirements:** limit it by architecture, Linux distribution or OS version if you need to.
   - **Detection:** choose **Add check** and describe how to tell it is installed, for example **Installed application** named `jq`, or **File exists** at a path. mustra uses this to know which endpoints need the package, and to confirm an install worked.
   - **Install**, **Update +** and **Uninstall +**: for each action, add **Action steps**. Each step has a **Language** (shell, PowerShell, Python, Go), a **Timeout (seconds)** and a **Script**. Choose **Run as** administrator/system, or the logged-in user.
5. Need an installer file? Upload it under **Files**; the script finds it in the folder named by `MUSTRA_PACKAGE_DIR`.
6. Need a value that changes per deployment, such as a licence key? Add it under **Shared parameters**; scripts read it from `MUSTRA_PARAM_<name>`.
7. Choose **Save**. The package is a draft.

**Example Linux install step (shell):**

```
apt-get update -qq
apt-get install -y jq
```

**Example Windows install step (PowerShell), with an uploaded MSI:**

```
Start-Process msiexec.exe -Wait -ArgumentList '/i', "$env:MUSTRA_PACKAGE_DIR\app.msi", '/qn', '/norestart'
```

## Test, then publish

1. Open the draft and choose **Test draft on endpoint**. Pick one endpoint you can afford to experiment on.
2. Read the result: each step's output and exit code, and whether detection now says installed.
3. When it works, choose **Publish**. The published version is frozen: changing it later means publishing a new version, and older versions stay available until you retire them.

## Deploy

1. In **Software Catalog**, tick one or more packages and choose **Deploy**, or choose **deploy** on a package's row.
2. Choose the operation (**Install**, **Update** or **Uninstall**) and the targets: computer groups or individual endpoints. **Install Eligible** and **Updates Needed** show how many endpoints need it.
3. Choose when: now, or at a time. Deployments respect each endpoint's **maintenance window** unless you have permission to override it.
4. Confirm.

## See what happened

**Deploy → Deployments** lists every deployment. Open one to see each endpoint's result:

| Result | Meaning |
| --- | --- |
| **Succeeded** | The steps ran and detection confirmed the outcome |
| **Failed** | A step failed or detection did not confirm it; open the endpoint's log for the output |
| **Timed out** | A step ran longer than its timeout and was stopped |
| **No response** | The endpoint did not pick up the job before it expired, usually because it was offline |

**Package Confidence** shows, over time, how often each package succeeds across your fleet.

## Repeat it on a schedule

**Deploy → Schedules → New schedule** runs a deployment daily, weekly or once at a set time, for example "update Chrome on all laptops every Tuesday night".

## Maintenance windows and templates

- **Maintenance Windows** say when endpoints in a group may be changed, for example weeknights 22:00–05:00 for servers. Deployments wait for the window.
- **Templates** save deployment options you use often (timing, restart behaviour, retries) so each deployment starts from them.

## Action packages

An **action package** runs a command or script and reports whether it worked, with no install state: clear a cache, restart a service, collect a log. Create one under **Deploy → Action Packages** the same way as a software package, without detection. Every run executes the command again. Success can be judged by exit code, by a sensor check afterwards, or both; `docs/ACTION-PACKAGES.md` in the source repository covers every option.

## If something goes wrong

- **"publish its draft first":** the package has no published version yet. Open it, review the draft, choose **Publish**.
- **No endpoint is eligible:** none of the targets runs a platform the package defines, or detection already says they have it. Check **Install Eligible**.
- **It installed but shows Failed:** detection does not match what the installer actually did. Fix the check (for example the exact application name in **Installed Software**) and publish a new version.
