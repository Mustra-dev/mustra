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
