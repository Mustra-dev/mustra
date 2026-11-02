# One endpoint, in depth
<!-- group: Manage endpoints; order: 14; pages: /endpoint -->

Every endpoint has a page with everything mustra knows about it, and the actions you can take on just that machine.

## Open it

- Type its hostname, IP address or serial into the search box at the top and select it, or
- select its name anywhere it appears: Home, Client Status, query results, findings.

## What is on it

- **Summary:** operating system, hardware, domain, agent version, when it last reported, and its standing in Comply (hardening), backups and Entra ID where those are connected.
- **Tabs**, one per sensor: processes, services, installed software, patches, disks, network, signed-in users, certificates, privileges and more. Each shows the endpoint's last report and how old it is.
- **Refresh live** asks the endpoint for the current value of the open tab, if it is online.
- **Attributes:** your own fields for this endpoint, such as owner, cost centre or warranty date. Change them and choose **Save attributes**. Define new attribute fields under **Client Management → Assets**.

## Act on this endpoint

Depending on your permissions:

- **Processes → Kill** stops a process. mustra checks the process name again before killing it, so a reused process ID is never hit by mistake.
- **Copy command** gives a shell command you can run on the endpoint for the item you are looking at.
- **Intune sync** and **Restart via Intune** appear when Intune manages the endpoint.
- **Direct Connect** opens an audited command session. See [Direct Connect and remote desktop](remote-access.md).
- **Revoke credential** disconnects the agent and stops it reconnecting, for a machine that is lost or compromised. It must be reinstalled with a new enrollment token to come back.
- **Remove from inventory** deletes the endpoint and its history from the console. If the agent is still installed it reappears at its next report; revoke its credential or uninstall it first.

## Check it worked

Every action you take here is written to the audit log with your name, the endpoint and the reason you gave.
