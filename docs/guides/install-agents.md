# Install agents
<!-- group: Manage endpoints; order: 10; pages: /agents -->

Put the mustra agent on Windows, macOS and Linux endpoints, one at a time or many at once, keep it up to date, and remove it.

## Before you start

- You need **Deploy software and run actions** (`deploy.manage`) to open Client Management.
- Each endpoint must reach the server's console address (for downloads) and its agent address (usually port 4222). Both are shown in the install commands.
- The agent runs with full rights: root on Linux and macOS, LocalSystem on Windows. The installers refuse to run without them.

## Install on a few machines

1. Open **Client Management → Manual Install**.
2. Fill in:
   - **Label**: what the token is for, for example "Finance laptops".
   - **Site**: optional; groups endpoints by location.
   - **Uses**: how many machines may enroll with it.
   - **Expires after (hours)**: how long it is valid.
3. Choose **Create enrollment token**. The token is shown **once**, inside the commands.
4. On each endpoint, run the command for its system:

| System | Where to run it |
| --- | --- |
| Linux, macOS | A terminal, as a user who can `sudo` |
| Alpine Linux | A root shell (the command adds `bash` and `curl` first) |
| Windows | PowerShell, opened with **Run as administrator** |

5. The endpoint appears under **Client Status** within a minute. The token's **Uses** count goes up by one.

Anyone holding the command can enroll machines until the token is used up or expires. Choose **Revoke** next to a token you no longer need.

## Install on many machines over SSH

**Network Scan & Push** finds Linux and macOS hosts on your network and installs the agent over SSH.

1. **Client Management → Credential Vault**, choose **Add credential** and store an SSH username with a password or private key. Secrets are encrypted on the server.
2. **Network Scan & Push**: choose **Scan for SSH hosts**.
3. Choose **Select hosts without an agent**, then **Apply credential to selected**.
4. Choose **Deploy selected**. Progress appears under **Deployments**.

For Windows fleets, push the Windows command with your existing tool (Group Policy, Intune or similar), running it as SYSTEM.

## macOS: grant Full Disk Access

macOS hides parts of the disk even from root. Without Full Disk Access, some inventory and file monitoring is incomplete; each Mac lists what it is missing under the **Privileges** tab of its endpoint page.

- **A few Macs:** System Settings → Privacy & Security → Full Disk Access → **+** → press **Cmd+Shift+G**, enter `/opt/mustra-agent`, and choose `mustra-agent`.
- **Many Macs:** download the **PPPC profile** from **Manual Install** and push it through the MDM the Macs are enrolled in. Double-clicking the profile does not work; macOS accepts it only from an MDM.

## Keep agents up to date

When the server is upgraded it carries the matching agent.

1. **Client Management → Overview** lists **Endpoints behind the current version**.
2. Choose **Update agent** next to one endpoint to try it first, then **Update all online**.
3. An update that fails to start is rolled back on the endpoint automatically: the agent keeps a last-known-good copy and a scheduled job restores it.

## Watch health

- **Client Status** lists every endpoint with when it last checked in.
- **Client Health** shows endpoints whose agent is struggling (slow collection, a full queue, missing privileges).
- **Profiles** change how often endpoints report, for a group of endpoints.

## Remove the agent

| System | How |
| --- | --- |
| Linux, macOS | `sudo /opt/mustra-agent/uninstall.sh` |
| Windows | **Settings → Apps → Installed apps**, find **Mustra Agent & Self Service**, choose **Uninstall**; or run `C:\Program Files\mustra-agent\uninstall.ps1` as administrator |

If **Administration → Uninstall Password** is set, the uninstaller asks for it. Removing the agent does not remove the endpoint from the console; it shows as offline until you delete it.

## If something goes wrong

- **The command fails with a certificate error:** the server's agent certificate does not name the address the endpoint used. Ask the server's administrator to re-run the server setup with that address.
- **The endpoint never appears:** check that port 4222 (or the port in the command) is reachable from the endpoint, and look at the agent's log: `journalctl -u mustra-agent` on Linux, `/var/log/mustra-agent.log` on macOS, `C:\ProgramData\mustra-agent\agent.log` on Windows.
- **"token is not valid":** it has expired, been revoked or used up. Create another.

## Inventory and patching only

For machines you want visibility into, without giving mustra the ability to run code on them. Tick **Inventory and patching only** when you create the enrollment token.

These endpoints still report inventory, vulnerabilities and compliance, and take the updates their package manager offers. They refuse everything else from the server: Direct Connect, deployments and Self Service installs, custom sensors, Enforce, end-user notices, and agent updates. A compliance rule that would run a command reads **unknown**, and updates come only from the repositories configured on the machine, so patch lists that choose repositories don't apply. The endpoint's page shows the mode.

- **Compliance results are thinner, and how much depends on the benchmark.** A check that needs a command reads `unknown`, unless its other rules settle the result. In our testing that was about 60 of 66 checks in CIS macOS 26, and about 42 of 398 in CIS Windows Server 2025. Benchmarks that lean on commands tell you little in this mode, so check yours before relying on it.
- **It can't be turned off from the console.** It's a file beside the agent, `no-remote-code`, that only an administrator on the endpoint can change. To leave the mode, delete that file and restart the agent.
- **Updating the agent:** run a new install command on the machine. It keeps the mode.
- **Network Scan & Push:** tick **Inventory and patching only** beside the scan. It applies to every host you push to while it's ticked.
- **Home Assistant add-on:** use the verified install command, not the plain one. The add-on then runs only that installer, by hash. If the add-on is rebuilt or updated, run a new install command. Its **no_remote_code** option is the switch here, and only a Home Assistant administrator can change it.

## How install commands protect you

A command from the console checks the installer's hash before running it, and the installer checks everything it downloads, so a tampered download stops the install before anything changes.

If a command says it **no longer matches the server**, the server has changed since you copied it, usually because of an upgrade or a new uninstall password. Create a new enrollment token.

For tools that store a command and reuse it, **Commands for automation that stores them** keeps working across upgrades until the token expires. Those commands trust the connection rather than checking the installer, so use them only over HTTPS.

