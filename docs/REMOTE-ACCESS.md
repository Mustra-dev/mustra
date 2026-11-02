# Remote desktop: RDP, VNC and SSH from Mustra

Each endpoint's page has a **Jump** menu with every way into it: **RDP**
(Windows, plus *RDP (local account)* on a domain-joined machine), **VNC**
(macOS Screen Sharing) or **SSH** (Linux), the temporary-admin variants when
those are offered, and the agent's recorded **PowerShell** or **Shell**. Mustra decides who
may connect to what, with the same checks as a shell session: management
rights, the shell action group, and Jump Gate (a reason, an approval, a time
limit, per policy). Every connection is written to the audit log as
`remote.open`. A provider carries the session. It is **off by default**; Access
→ Jump Gate → Remote desktop explains how to turn it on.

## Shadowing a Windows session (the user approves)

Remote Desktop to a Windows workstation takes the console over: whoever is
signed in is signed out the moment you connect. For "show me what you are
seeing", use **Shadow session** instead, under Jump on a Windows
endpoint's page, as *view* or *control*. It needs no provider. Mustra
applies the same checks as RDP (management rights, the shell action group,
Jump Gate), writes `remote.open` with `protocol: shadow` to the audit log,
and shows you a command for your own Windows computer:

```
mstsc.exe /v:<address> /shadow:<session id> /prompt [/control]
```

Copy it or download it as a `.cmd`. The Remote Desktop client asks for your
credentials for the endpoint, then **Windows asks the person in that
session** whether to allow you to view (or control) it. Nothing is shown
until they accept; nobody is signed out; no account is created; they can
end it at any time. The session id comes from the endpoint's logged-in
users sensor (agents from 0.57.42 report each Windows session's id and
state); the active console session is picked, and the other sessions are
listed so you can shadow one of those instead. An older agent does not
report ids: run `quser` on the endpoint to read the ID column, then shadow
from the API with `session_id`.

The endpoint must allow it:

- The policy *Set rules for remote control of Remote Desktop Services user
  sessions* (Computer Configuration → Administrative Templates → Windows
  Components → Remote Desktop Services → Remote Desktop Session Host →
  Connections; registry `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal
  Services\Shadow`) set to *Full Control with user's permission* (1) or *View
  Session with user's permission* (3). Unconfigured, Windows allows full
  control with the user's permission; a value of 0 disables shadowing, and
  2 or 4 would skip the user's permission, which defeats the point.
- The *Remote Desktop - Shadow (TCP-In)* firewall rule, which is in the
  Remote Desktop group, and TCP 3389; Remote Desktop itself need not be
  enabled for incoming connections.
- You hold administrator rights on the endpoint (shadowing is a Remote
  Desktop Services administrative operation).
- Windows Home cannot be shadowed, as it cannot host Remote Desktop.

With agent 0.57.44 or later the endpoint reports these itself (the
security posture sensor's `remote_shadow`: the rule and where it comes
from, the firewall rule, the Remote Desktop service). When one of them
rules shadowing out, the Jump menu shows the two Shadow entries greyed
out with the reason, instead of letting the Remote Desktop client fail;
the endpoint's Security posture tab lists them too. An Enforce policy
that sets `Shadow = 1` and enables the firewall rule fixes both.

What Windows does not do: record the session, or carry it through a
browser. Shadowing is a Windows client to a Windows endpoint.

## Providers

| Provider | What it is | Needs |
| --- | --- | --- |
| **Guacamole** (built in) | Apache Guacamole in the browser: nothing to install on a phone, iPad or Mac. | The `remote` compose profile and a shared secret. |
| **BeyondTrust** | Privileged Remote Access or Remote Support. The button opens a Jump session in the BeyondTrust console, which records it and can inject vaulted credentials. | Your site address; the representative console installed. |
| **Custom** | Any gateway or client, from a URL template. | A template with `{ip}`, `{hostname}`, `{protocol}` (rdp, vnc, ssh), `{port}`. |

## Guacamole

1. `openssl rand -hex 16`, and put the result in `deploy/.env` as
   `MUSTRA_GUACAMOLE_JSON_SECRET`.
2. `docker compose --profile remote up -d guacd guacamole`.
3. Access → Jump Gate → Remote desktop: provider **Guacamole**, address
   `http://guacamole:8080/guacamole` (the default), and the same secret.
   Administrators only; the secret is kept in the credential vault.

How it works: Guacamole runs its JSON auth extension and has no accounts of
its own. When someone clicks RDP, the server checks access, signs a ticket for
that one connection (HMAC-SHA256 then AES-128-CBC with the shared secret,
valid two minutes), trades it for a Guacamole session token and opens
`/guacamole/#/client/…`. The mustra server proxies `/guacamole/` (page, API
and WebSocket tunnel) to signed-in users only, so Guacamole needs no port,
hostname or tunnel of its own.

With **temporary accounts** off, Guacamole asks for a user name and password
when the session opens. Turn them on (below) and it signs in by itself.

### Temporary accounts (JIT)

Access → Jump Gate → Remote desktop → *Sign in with a temporary account*:

- **Off:** Guacamole asks for credentials.
- **Offered:** each endpoint gets a second button, e.g. *RDP (temporary
  admin)*.
- **Always:** every Guacamole session signs in this way.

What happens:

1. The server writes the session down, then asks the endpoint's agent for
   a local administrator: name `mustra-` plus eight random characters, and a
   24-character random password (RDP, VNC) or a fresh RSA key (SSH).
2. Guacamole signs in with it. Nobody sees the password.
3. When the session ends (closed for three minutes, its Jump Gate window
   ends, its grant is revoked, or eight hours pass), the server asks the
   agent to sign the account out and delete it. It retries with backoff,
   and sends a notification after three failures.
4. The agent records the account's deadline and deletes it once that
   passes, even if it can't reach the server. Windows and Linux also enforce
   the expiry at sign-in.

| Platform | The account |
| --- | --- |
| Windows | Local user in Administrators and Remote Desktop Users (found by SID, so localized names work), with an expiry; profile deleted on removal. Created through the NetUser APIs, so the password is never on a command line. Domain controllers are refused. The agent also turns off the privacy-settings page and first sign-in animation (machine policies), which every new account would otherwise see. |
| Linux | `useradd` with an expiry date, a sudoers.d entry (`NOPASSWD`, since nobody knows the password), and the key in `authorized_keys` for SSH. The password goes to `chpasswd` on stdin. |
| macOS | Hidden local user in `admin`, with the Remote Management privilege, so Screen Sharing limited to listed users still lets it in. Created through `dscl` on stdin. |

The agent only creates or deletes names of the `mustra-<random>` shape, so
the server can't use this to remove any other account.

Things that turn the account away:

- **CIS hardening on Windows member servers** denies "log on through
  Remote Desktop Services" to local accounts. A temporary account then
  can't sign in until that policy is relaxed for the machines you reach
  this way.
- **sshd `AllowUsers` / `AllowGroups`.** The agent reports these when it
  creates the account, in the server log.

### Recording

guacd records every Guacamole session: the screen, plus the text of an SSH
session. Recordings go to the `remote-recordings` volume, which the server
mounts read-only. Access → Sessions → Remote desktop lists each session and
downloads its recording, and each download is audited.

- `guacenc` (in the guacd image) turns a screen recording into a video.
- Keystrokes are not recorded, because that would capture every password
  typed.
- Turn recording off under *Record sessions*.
- If the server runs outside compose, point `MUSTRA_REMOTE_RECORDINGS_DIR`
  at guacd's recording directory, and give the server read access to it.
  guacd writes files that only its own group (gid 1000) can read.

The Guacamole containers must reach the endpoints: Mustra connects to the
endpoint's first private IPv4 (then any IPv4, then its hostname).

## BeyondTrust

Enter the site (`https://access.example.com`). Mustra builds a client
scripting link, `/api/client_script?type=rep&operation=generate&action=start_jump_item_session&search_string=<ip>&jump.method=<rdp|shell_jump|vnc>`,
which asks the representative console to start the Jump session. The parameters
differ between Privileged Remote Access and Remote Support versions: check
the link against your site's client scripting API documentation before relying
on it, or use **Custom** with the exact link your site expects.

## The endpoints

- **Windows:** Remote Desktop enabled (Settings → System → Remote Desktop),
  TCP 3389 allowed. Windows Home cannot host RDP.
- **macOS:** Screen Sharing on (System Settings → General → Sharing).
  Guacamole then asks for a Mac account's name and password (Apple's own
  login, which guacd supports); no separate VNC password is needed. Since
  macOS 12.1, turning it on from a script needs MDM: send the
  `EnableRemoteDesktop` MDM command (Fleet: `POST /api/v1/fleet/commands/run`
  with that RequestType), then, as root,
  `/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart
  -activate -configure -allowAccessFor -allUsers -privs -all -restart -agent`.
  Without MDM, kickstart opens the port but screen control stays off.
- **Linux:** an SSH server listening on 22.
