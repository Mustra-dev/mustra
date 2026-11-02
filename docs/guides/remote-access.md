# Direct Connect and remote desktop
<!-- group: Manage endpoints; order: 16; pages: /shell -->

Run commands on an endpoint interactively, or open a remote desktop, SSH or screen-sharing session, with every connection recorded.

## Before you start

- You need **Deploy software and run actions** (`deploy.manage`). Reading other people's session transcripts needs **Audit remote sessions** (`sessions.audit`).
- Jump Gate policies may ask for a reason, an approval or a time limit first. See [Access control](access.md).

## Run commands (Direct Connect)

1. Open **Direct Connect**, or choose **Direct Connect** on an endpoint's page.
2. Choose the endpoint, type the reason (for example a ticket number) and choose **Open session**.
3. Type a command and choose **Run**. It runs as root (Linux, macOS) or SYSTEM (Windows), in PowerShell on Windows and a shell elsewhere, and shows its output and exit code.
4. Choose **Close** when you are done.

Each command is written to the audit log **before** it is sent, with your name and the reason, so even a command that hangs is on record. **Open sessions** lists everyone's sessions that are still open.

## Remote desktop, SSH and screen sharing

Each endpoint's page has a **Jump** menu with the ways into it: **RDP** for Windows, **VNC** (Screen Sharing) for macOS, **SSH** for Linux. These need a remote-desktop provider, which is off until an administrator sets it up under **Access → Jump Gate → Remote desktop**.

### Help someone on their Windows screen

**Shadow session** under **Jump** asks the signed-in person for permission to view or control their session, without signing them out. Copy the command it shows into your own Windows computer:

```
mstsc.exe /v:<address> /shadow:<session id> /prompt
```

Windows asks the person to accept before anything is shown.

## Review what was done

**Access → Jump Gate → Sessions** lists recorded sessions. Choose **Transcript** to read every command and its output.
