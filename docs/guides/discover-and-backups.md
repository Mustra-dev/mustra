# Discover and backup status
<!-- group: See your fleet; order: 26; pages: /discover, /backup-status -->

See every device on your networks, including the ones mustra does not manage yet, and whether your virtual machines and servers are backed up.

## Before you start

- Reading needs **See the fleet**. Labelling devices needs **Manage computer groups**; Discover's settings and connecting backup systems need **Manage settings**.

## Discover

Every endpoint reports the devices it sees on its local network (its ARP neighbours). **Discover** combines them into one list: every IP and MAC address, the vendor of its network card, when it was first and last seen, and whether it runs the mustra agent.

1. Open **Discover**. Devices without an agent are the ones to look at: printers and phones are expected, an unknown laptop is not.
2. Choose **Label** on a device to name it, so it stops looking unknown.
3. Turn on new-device alerts to get a Guide item when a device appears for the first time.

To install the agent on Linux and macOS devices found here, use **Client Management → Network Scan & Push**. See [Install agents](install-agents.md).

## Backup status

**Backup Status** shows whether each virtual machine, container and server has a recent, verified backup.

- **Proxmox VE**: install the mustra agent on each Proxmox node. It reads every guest's newest backup and whether a backup job covers it.
- **Proxmox Backup Server** and **Rubrik Security Cloud**: under **Connect a backup system**, enter the address and a read-only API token or service account, and choose **Connect**. They are read every 15 minutes; **Read now** reads them immediately.

Each guest or server is rated **ok**, **overdue** (no backup in the last 36 hours, by default), **never** backed up, or **not covered** by any job. Overdue and never raise a Guide item, once per episode. Change the threshold under the page's settings and choose **Save**.
