package server

import (
	"embed"
	"encoding/json"
	"github.com/mustra-dev/mustra/internal/store"
	"net/http"

	"github.com/mustra-dev/mustra"

	"github.com/mustra-dev/mustra/internal/proto"
)

// What each sensor is, and how it gets its answer.
//
// A sensor is otherwise the most opaque thing in the product: a name in a
// list, a number that may or may not be current, and no way to find out
// where it came from short of reading the agent source. That matters more
// than it sounds, because the right reaction to "patches: 5" depends
// entirely on whether that number was read from the Windows Update COM API
// two minutes ago or from a cached apt index last Tuesday.
//
// So each entry says what the sensor answers, exactly how it is collected
// per platform, what it costs the endpoint, and where it can be wrong. The
// per-OS mechanism is the part people actually ask for: "how is it pulling
// it" is the first question anyone evaluating a fleet tool asks.
//
// This is deliberately a hand-written catalog rather than generated from
// the agent. The mechanism strings are the honest, human answer -- "reads
// the ARP/NDP table, puts zero packets on the wire" -- which no amount of
// reflection over collector functions would produce.

type sensorMechanism struct {
	OS  string `json:"os"`
	How string `json:"how"`
}

//go:embed sensor_templates/*.json
var sensorTemplates embed.FS

// sensorTemplate is a built-in sensor's editable example: a custom sensor
// nobody has saved yet, so it has none of the ID, creator and times the
// server gives a saved one.
type sensorTemplate struct {
	Parameters      []proto.DeployParameter         `json:"parameters,omitempty"`
	Platforms       map[string]proto.SensorPlatform `json:"platforms"`
	Fields          []proto.SensorField             `json:"fields"`
	MaxAgeSeconds   int                             `json:"max_age_seconds"`
	Name            string                          `json:"name"`
	Description     string                          `json:"description"`
	Commands        map[string]string               `json:"commands"`
	IntervalSeconds int                             `json:"interval_seconds"`
	TimeoutSeconds  int                             `json:"timeout_seconds"`
	Enabled         bool                            `json:"enabled"`
	// Notes says what the example does not do that the built-in does.
	Notes string `json:"notes"`
}

type sensorDoc struct {
	Template  *sensorTemplate   `json:"template,omitempty"`
	Sources   []string          `json:"sources"`
	Kind      string            `json:"kind"`
	Name      string            `json:"name"`
	Summary   string            `json:"summary"`
	Answers   string            `json:"answers"`
	Returns   string            `json:"returns"`
	Mechanism []sensorMechanism `json:"mechanism"`
	Interval  string            `json:"interval"`
	Timeout   string            `json:"timeout"`
	Cost      string            `json:"cost"`
	Caveat    string            `json:"caveat,omitempty"`
	// OnDemand sensors answer a specific request and are never collected
	// as inventory, so their absence from coverage is not a gap.
	OnDemand bool `json:"on_demand,omitempty"`
}

func sensorCatalog() []sensorDoc {
	docs := []sensorDoc{
		{Kind: string(proto.SensorActionLogs), Name: "Action run logs", Summary: "Console output and progress from one endpoint action run.", Answers: "What did this particular action write to stdout or stderr, and where did it stop?", Returns: "job_id, run_id, agent_id, timestamp, stage, message, exit_code", Mechanism: []sensorMechanism{{OS: "all", How: "Reads the agent’s retained deployment JSON logs and compressed segments, filtered to an explicit endpoint run ID. No command is executed."}}, OnDemand: true, Interval: "On demand from Deployment progress → View endpoint log sensor; never collected as inventory", Timeout: "15 seconds", Cost: "Bounded local archive read; returns up to 500 events and 256 KB.", Caveat: "Requires an online, upgraded agent and deploy.manage. Retention and command output limits apply; missing history cannot be recovered. Built-in collection runs in agent context. Server-side logs remain available while the endpoint is offline."},
		{
			Kind:    string(proto.SensorProcesses),
			Name:    "Processes",
			Summary: "Every process running right now, with CPU and memory.",
			Answers: "What is running on this machine, and what is using it up. The first thing anyone looks at when a box is behaving badly.",
			Returns: "pid, name, username, cpu_percent, mem_percent, mem_rss_mb",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "gopsutil, which reads the kernel's own process table directly — /proc on Linux, sysctl on macOS, the Windows process APIs. No shelling out, so no shell, no PATH, and nothing to quote wrong."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Cheap. A table read, no child processes.",
			Caveat:   "A snapshot, not a history: a process that started and exited between two collections is invisible here.",
		},
		{
			Kind:    string(proto.SensorServices),
			Name:    "Services",
			Summary: "OS services and whether they are running.",
			Answers: "Is the thing that is supposed to be running actually running — and is it set to come back after a reboot.",
			Returns: "name, display_name, status, start_type",
			Mechanism: []sensorMechanism{
				{OS: "linux", How: "systemctl list-units --type=service, which reports the unit's active state and whether it is enabled at boot."},
				{OS: "darwin", How: "launchctl list, which enumerates loaded launchd jobs along with their last exit status."},
				{OS: "windows", How: "EnumServicesStatusEx on the Service Control Manager, in the agent's own process (no PowerShell), with each service's start type from its Services registry key; the same state and start-type values Get-Service reports."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "One short-lived child process per collection.",
			Caveat:   "start_type is left empty rather than guessed where the platform's service manager does not expose it comparably.",
		},
		{
			Kind:    string(proto.SensorInstalledApps),
			Name:    "Installed applications",
			Summary: "What software is installed, and at what version.",
			Answers: "Who has this application, and who is on an old version of it. Also the backbone of the software catalog — package detection matches against this rather than running a separate check per package per device.",
			Returns: "name, version, publisher, executable, install date, last used (where the platform records one)",
			Mechanism: []sensorMechanism{
				{OS: "linux", How: "dpkg-query -W on Debian/Ubuntu (install date from the package's dpkg file-list mtime), rpm -qa on RHEL-family (INSTALLTIME)"},
				{OS: "darwin", How: "reads each app bundle's Info.plist with plutil (version, CFBundleExecutable), the bundle's mtime as install date, and Spotlight's kMDItemLastUsedDate via mdls as last used"},
				{OS: "windows", How: "reads the Uninstall registry keys (both 32- and 64-bit hives) in the agent's own process (no PowerShell) — the same source Add/Remove Programs uses — taking the executable from DisplayIcon and InstallDate, and last used from that executable's Prefetch file (when prefetch is enabled)"},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Moderate. Enumerating packages on a large machine is the slowest of the cheap sensors.",
			Caveat:   "Only what the platform's own package/registry inventory knows about. Software dropped on disk without an installer will not appear.",
		},
		{
			Kind:    string(proto.SensorPatches),
			Name:    "Available patches",
			Summary: "OS updates that are available but not yet installed.",
			Answers: "How far behind is this machine, and is anything security-relevant outstanding. Drives the Patches module and the compliance view.",
			Returns: "name, current_version, new_version, severity",
			Mechanism: []sensorMechanism{
				{OS: "linux", How: "apt-get update then a simulated upgrade on Debian/Ubuntu; dnf/yum check-update on RHEL-family. A patch list can scope this to specific repos instead of whatever the host has configured."},
				{OS: "darwin", How: "softwareupdate -l, Apple's own update listing tool, which queries the Software Update catalogue the machine is pointed at."},
				{OS: "windows", How: "the Windows Update Agent COM API directly — Microsoft.Update.Session, CreateUpdateSearcher, searching IsInstalled=0 and IsHidden=0. Deliberately not the PSWindowsUpdate module, which is not installed by default, so this works on a stock Windows box with no prerequisites."},
			},
			Interval: "the agent's sensor interval (15 minutes by default), plus an immediate republish after patches are applied",
			Timeout:  "10 minutes — its own budget, not the 30 seconds every other sensor gets",
			Cost:     "The most expensive sensor by a wide margin. It talks to Microsoft Update or your WSUS, or refreshes the apt index.",
			Caveat:   "A cold Windows Update search regularly exceeds thirty seconds, which is why this sensor has a ten-minute budget of its own. It shared the common 30-second budget until 2026-09-09 and was being killed on nearly every tick, so the console showed no patch list for Windows machines at all.",
		},
		{
			Kind:    string(proto.SensorPatchStatus),
			Name:    "Patch check status",
			Summary: "Whether the last check for pending updates worked, and if not, why and since when.",
			Answers: "Is this device's patch list current, or is it the last list from before its checks started failing.",
			Returns: "ok, error, timed_out, checked_at, failing_since",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "Published by the agent after every Available patches check (the sensor tick, the republish after a patch job, Rescan now) with that check's outcome; it runs nothing of its own. The server fills in failing_since from the previous status."},
			},
			Interval: "with every Available patches check",
			Timeout:  "none of its own; a check that hits the Available patches budget is reported as timed out",
			Cost:     "None beyond the patches check it reports on.",
			Caveat:   "Agents from 0.58.0 publish it. For older agents only Rescan now records a failure, from the server's side.",
		},
		{
			Kind:    string(proto.SensorDisks),
			Name:    "Disks",
			Summary: "Mounted filesystems and how full they are.",
			Answers: "What is about to run out of space. The single most common preventable outage.",
			Returns: "mountpoint, fstype, total, used, free, used_percent",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "gopsutil partition and usage calls, which use the platform's native statfs/GetDiskFreeSpaceEx rather than parsing df output."},
				{OS: "linux", How: "Home Assistant OS add-on: the Supervisor's /host/info disk_total/disk_used: the add-on container mounts none of the host's filesystems, so the data partition is reported as one disk."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Cheap.",
		},
		{
			Kind:    string(proto.SensorNetwork),
			Name:    "Network interfaces",
			Summary: "Interfaces, addresses and MACs on this machine.",
			Answers: "Where is this machine on the network, and what is it called there. Also how a device is matched to an inventory record when its name or IP has changed.",
			Returns: "name, mac, addresses, flags",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "gopsutil interface enumeration over the OS network stack."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Cheap.",
		},
		{
			Kind:    string(proto.SensorUsers),
			Name:    "Logged-in users",
			Summary: "Who is signed in, from where, and since when.",
			Answers: "Is anyone actually using this machine — which is the question you want answered before rebooting it.",
			Returns: "user, terminal, host, started; on Windows also session_id and state (Active or Disc), which shadowing a session needs",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "gopsutil's logged-in user list (utmp on Unix); quser on Windows, which also gives each session's id and state."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Cheap.",
		},
		{
			Kind:    string(proto.SensorDirectory),
			Name:    "Directory",
			Summary: "Domain membership (Active Directory, Entra ID) and the signed-in users' accounts and groups.",
			Answers: "Is this machine in the domain, where (OU, site, domain controller), and who is signed in: their groups, whether the account is enabled or locked, how old the password is, when they last logged on.",
			Returns: "joined, kind (ad, entra, hybrid, workgroup), domain, site, dc, computer_dn, computer_ou, entra_tenant, users[] (name, upn, display_name, email, title, department, manager, groups, enabled, locked, password_last_set, last_logon)",
			Mechanism: []sensorMechanism{
				{OS: "windows", How: "Win32_ComputerSystem for domain membership and dsregcmd /status for Entra ID; then an LDAP search of Active Directory as the computer account (any domain member may read it, so no credentials are configured) for the computer's DN and each signed-in user's attributes and direct group memberships. Signed-in users come from quser. A local account is described from Get-LocalUser and its local groups."},
				{OS: "linux", How: "realm list for the joined domain (realmd/SSSD); each signed-in user's groups from id -Gn and name from getent passwd. Account policy (lockout, password age) stays in the directory and is not read."},
				{OS: "darwin", How: "dsconfigad -show for an Active Directory binding; each signed-in user (and the console user) from id -Gn and dscl."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "60 seconds",
			Cost:     "One PowerShell start and a few LDAP lookups on Windows; a handful of commands elsewhere.",
		},
		{
			Kind:    string(proto.SensorBackups),
			Name:    "Backups",
			Summary: "On a Proxmox VE node: every guest's latest backup, how many are kept, where, and whether a backup job covers it.",
			Answers: "When was this virtual machine or container last backed up, is that backup verified, and is it in a backup job at all — joined to the Mustra endpoint running inside the guest.",
			Returns: "vmid, name, type, status, node, macs, covered, jobs, last_backup, last_storage, last_size_bytes, last_verified, backups, storages, last_job_status, last_job_end",
			Mechanism: []sensorMechanism{
				{OS: "linux", How: "Only where /usr/bin/pvesh exists (a Proxmox VE node), as root: the node's qemu and lxc guests and their network cards, the backup storages' contents (Proxmox Backup Server, directories, NFS…), the node's last vzdump task, and the vzdump jobs in /etc/pve/jobs.cfg. Shared storages list the whole cluster's backups; each node reports only its own guests."},
				{OS: "windows", How: "Not collected (reports nothing)."},
				{OS: "darwin", How: "Not collected (reports nothing)."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "3 minutes",
			Cost:     "A few pvesh calls per guest on Proxmox nodes; nothing elsewhere.",
			Caveat:   "Pool-based backup jobs are not expanded, so their guests show as not covered. Backups made outside Proxmox VE (inside the guest, or another tool) are not seen.",
		},
		{
			Kind:    string(proto.SensorLocalAdmins),
			Name:    "Local administrators",
			Summary: "Every principal that can administer the endpoint.",
			Answers: "Who could take this machine over — the endpoint half of Impact. Paired with the directory, it becomes who can reach what from here.",
			Returns: "name, domain, sid, kind, source, via",
			Mechanism: []sensorMechanism{
				{OS: "windows", How: "NetLocalGroupGetMembers on BUILTIN\\Administrators (found by its SID, since the name is localised), in the agent's own process: each member's SID, whether it is a user or a group, and whether it is builtin, local or from the domain. On a domain controller the same call returns the domain's Administrators group."},
				{OS: "linux", How: "uid 0 accounts in /etc/passwd; members of the sudo, wheel and admin groups (including by primary group); user and %group grants at the start of lines in /etc/sudoers and /etc/sudoers.d. The command list after a grant is not interpreted."},
				{OS: "darwin", How: "dscl's GroupMembership and NestedGroups of /Groups/admin, plus root."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "45 seconds on Windows, 20 on macOS, immediate on Linux (file reads)",
			Cost:     "Cheap. One API call on Windows.",
		},
		{
			Kind:    string(proto.SensorSecurityPosture),
			Name:    "Security posture",
			Summary: "The endpoint's own protective controls: firewall, disk encryption, antimalware, application control, and whether RDS shadowing can work.",
			Answers: "Is this machine protected — and across the fleet, what share is. The coverage numbers on Enforce, the fields behind \"encrypted laptops\" groups, and the source of BitLocker recovery-key escrow.",
			Returns: "firewall_engine, firewall_enabled, firewall_profiles, encryption_engine, os_volume_encrypted, volumes, antivirus_engine, antivirus_enabled, antivirus_realtime, antivirus_signature_age_hours, antivirus_tamper_protected, antivirus_cloud_level, app_control_engine, app_control_mode, app_control_collections, remote_shadow (Windows: mode, source, firewall_rule, service, ready, reason)",
			Mechanism: []sensorMechanism{
				{OS: "windows", How: "One PowerShell pass over the same APIs the typed Enforce policies check: Get-NetFirewallProfile, Get-BitLockerVolume (with the recovery passwords, which the server encrypts and strips before the snapshot is stored), Get-MpComputerStatus and Get-MpPreference, and Get-AppLockerPolicy -Local. Remote shadowing reads the Shadow value from the Terminal Services policy key (or the RDP-Tcp default), whether the Remote Desktop rule for RdpSa.exe is enabled, and whether TermService runs; the Jump menu uses it to say shadowing is off before anyone tries. Each probe is isolated, so a missing module blanks only its own section."},
				{OS: "linux", How: "ufw status, firewall-cmd --state, an nftables ruleset with hooks, or iptables policy — whichever front end is installed; LUKS from the lsblk device tree, walking parents so LVM-over-LUKS roots count. No antimalware or application-control model: reported as none, not off."},
				{OS: "darwin", How: "socketfilterfw --getglobalstate and fdesetup status. XProtect is reported as always-on antimalware; there is no AppLocker equivalent."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "90 seconds on Windows (four modules), 20 seconds elsewhere",
			Cost:     "Moderate on Windows: one PowerShell start that loads four modules. Cheap elsewhere.",
			Caveat:   "BitLocker recovery passwords travel inside the snapshot over the agent's TLS channel and are stored only in the encrypted escrow table; if the server has no credential encryption key configured, they are discarded with a warning rather than stored in the clear.",
		},
		{
			Kind:    string(proto.SensorHardware),
			Name:    "Hardware",
			Summary: "CPU, memory and machine model.",
			Answers: "What is this machine, physically. Drives package requirements — a package needing 4 GB of RAM is reported Not Applicable on a 2 GB box rather than failing halfway through installing.",
			Returns: "cpu model, cores, total memory, vendor/model",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "gopsutil host and cpu information."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Cheap, and near-static — it rarely changes between collections.",
		},
		{
			Kind:    string(proto.SensorPrivileges),
			Name:    "Privileges and platform protections",
			Summary: "What the agent can do here, and which OS protections are on.",
			Answers: "Whether an action will actually succeed on this endpoint before you deploy it, and whether the machine's own defences are enabled.",
			Returns: "elevated, protections and their state",
			Mechanism: []sensorMechanism{
				{OS: "linux", How: "reads /proc/self status and capabilities to determine effective privilege."},
				{OS: "darwin", How: "csrutil status for System Integrity Protection, and profiles status for MDM enrolment."},
				{OS: "windows", How: "inspects the process token's privileges. A LocalSystem token holds SeDebugPrivilege, SeBackupPrivilege and the rest, but they arrive disabled — the agent enables them at startup, because until AdjustTokenPrivileges is called the kernel behaves as though it lacks them."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Cheap.",
		},
		{
			Kind:    string(proto.SensorNeighbors),
			Name:    "Network neighbours",
			Summary: "Hosts this machine has recently talked to, from its ARP/NDP table.",
			Answers: "What is on my network that mustra does not manage. Across a fleet the union of these tables covers a network surprisingly completely, because anything that talks to anything shows up in somebody's table.",
			Returns: "ip, mac, interface",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "reads the kernel's existing ARP/NDP neighbour table. This puts ZERO packets on the wire — no sweep, no SYNs, nothing an IDS will flag."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Effectively free, and invisible to network monitoring.",
			Caveat:   "Only shows hosts this machine has recently communicated with. A device nobody talks to is invisible — which is the trade for not scanning.",
		},
		{
			Kind:    string(proto.SensorCertificates),
			Name:    "Certificates",
			Summary: "X.509 certificates on disk, in the OS certificate store, and served by local TLS services, and when they expire.",
			Answers: "What is going to expire, and which machine and path it lives on. Certificates fail on a date, silently, and almost always on the host nobody remembers owning.",
			Returns: "path, subject, issuer, not_after, days remaining",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "walks only the paths that conventionally hold certificates (including Proxmox's /etc/pve and /etc/proxmox-backup), with depth and count bounds — 'search the filesystem for certificates' on a fileserver is a good way to turn a sensor into an outage. Parses the certificates, which are public by definition; private keys are never read. Then connects to local listening ports that conventionally serve TLS (443, 8443, 8006, 8007, 636, 5986 and a few more), at most 20, and records the certificate each presents as tls://address:port."},
				{OS: "windows", How: "also reads the LocalMachine Personal, Web Hosting and Remote Desktop certificate stores with CertOpenStore/CertEnumCertificatesInStore in the agent's own process, read-only (paths shown as Cert:\\LocalMachine\\…); the Root and intermediate stores are trust stores and are skipped."},
				{OS: "darwin", How: "also reads the System keychain with `security find-certificate`; the bundled system roots are not read."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Bounded filesystem walk over a small set of known directories.",
			Caveat:   "A certificate stored somewhere unconventional will not be found. The bound is deliberate.",
		},
		{
			Kind:    string(proto.SensorPerformance),
			Name:    "Performance",
			Summary: "A counted summary of CPU, memory and load, sampled on the endpoint.",
			Answers: "Is this machine healthy, and how often has it been unhealthy lately.",
			Returns: "sample count, averages, and counts of samples over threshold",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "gopsutil samples into an in-memory ring buffer on the endpoint; only a summary is sent. Shipping a raw sample every 15 seconds would put roughly 5,700 rows per endpoint per day into Postgres to answer a question nobody asks in that form."},
			},
			Interval: "its own reporting interval, independent of the other sensors",
			Timeout:  "30 seconds",
			Cost:     "Continuous light sampling on the endpoint; one small message per report.",
			Caveat:   "The ring buffer is in memory, so it resets when the agent restarts. An agent that just restarted genuinely has no history to report.",
		},
		{
			Kind:    string(proto.SensorIntegrity),
			Name:    "File integrity",
			Summary: "Hashes of a watched set of files, so changes can be diffed.",
			Answers: "Has anything changed in the places that matter since last time.",
			Returns: "path, hash, size, modified time",
			Mechanism: []sensorMechanism{
				{OS: "all", How: "hashes a bounded watched set and reports the current state. The server diffs consecutive snapshots — change detection belongs there, not on the endpoint. This is periodic baselining rather than real-time event monitoring (inotify / ReadDirectoryChangesW), which needs no kernel interface, no watch descriptors, and cannot miss a change that happened while the agent was down — exactly when interesting changes happen."},
			},
			Interval: "the agent's sensor interval (15 minutes by default)",
			Timeout:  "30 seconds",
			Cost:     "Hashing cost scales with the watched set, which is why it is bounded.",
			Caveat:   "Periodic, so it reports that something changed between two collections, not the moment it changed or how many times.",
		},
	}
	for i := range docs {
		docs[i].Sources = sensorSourceFiles(docs[i].Kind)
		data, err := sensorTemplates.ReadFile("sensor_templates/" + docs[i].Kind + ".json")
		if err != nil {
			continue
		}
		var template sensorTemplate
		if json.Unmarshal(data, &template) != nil {
			continue
		}
		template.Name = docs[i].Name + " (custom)"
		template.Description = "Based on built-in " + docs[i].Name + ". " + template.Notes
		docs[i].Template = &template
	}
	return docs
}

func sensorSourceFiles(kind string) []string {
	switch proto.SensorKind(kind) {
	case proto.SensorActionLogs:
		return []string{"action_logs.go"}
	case proto.SensorProcesses, proto.SensorServices, proto.SensorInstalledApps:
		return []string{"sensors.go"}
	case proto.SensorDisks, proto.SensorNetwork, proto.SensorUsers, proto.SensorHardware:
		return []string{"inventory.go"}
	case proto.SensorPatches, proto.SensorPatchStatus:
		return []string{"patches.go", "patchlist.go"}
	case proto.SensorPrivileges:
		return []string{"privileges_linux.go", "privileges_darwin.go", "privileges_windows.go"}
	case proto.SensorNeighbors:
		return []string{"neighbors.go"}
	case proto.SensorCertificates:
		return []string{"certificates.go", "certificates_sources.go"}
	case proto.SensorPerformance:
		return []string{"performance.go"}
	case proto.SensorIntegrity:
		return []string{"integrity.go", "integrity_unix.go", "integrity_windows.go"}
	case proto.SensorLocalAdmins:
		return []string{"localadmins_windows.go", "localadmins_linux.go", "localadmins_darwin.go"}
	case proto.SensorDirectory:
		return []string{"directory.go"}
	case proto.SensorBackups:
		return []string{"backups.go"}
	case proto.SensorSecurityPosture:
		return []string{"posture.go", "posture_windows.go", "posture_linux.go", "posture_darwin.go"}
	}
	return nil
}

// sensorSourceFile is an entry of what GET
// /api/sensors/builtin/{kind}/source answers.
type sensorSourceFile struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

// sensorSourceResponse is what GET /api/sensors/builtin/{kind}/source
// answers.
type sensorSourceResponse struct {
	Sources []sensorSourceFile `json:"sources"`
}

func (s *Server) handleSensorSource(w http.ResponseWriter, r *http.Request) {
	files := sensorSourceFiles(r.PathValue("kind"))
	if len(files) == 0 {
		http.NotFound(w, r)
		return
	}
	sources := []sensorSourceFile{}
	for _, name := range append(files, "sensor_loop.go") {
		data, err := mustra.SensorSources.ReadFile("internal/agent/" + name)
		if err != nil {
			http.Error(w, "collector source unavailable", 500)
			return
		}
		sources = append(sources, sensorSourceFile{Name: "internal/agent/" + name, Code: string(data)})
	}
	writeJSONResponse(w, sensorSourceResponse{Sources: sources})
}

// listSensorsResponse is what GET /api/sensors answers.
type listSensorsResponse struct {
	AgentCount     int                       `json:"agent_count"`
	AgentCountByOS map[string]int            `json:"agent_count_by_os"`
	Coverage       []store.SensorCoverageRow `json:"coverage"`
	Sensors        []sensorDoc               `json:"sensors"`
}

// handleListSensors returns the catalog alongside live fleet coverage, so
// the page answers both "what does this sensor do" and "is it actually
// working right now" -- a sensor whose description is perfect and whose
// last collection was nine days ago is still broken.
func (s *Server) handleListSensors(w http.ResponseWriter, r *http.Request) {
	docs := sensorCatalog()
	coverage, err := s.store.SensorCoverage(r.Context())
	if err != nil {
		s.logger.Warn("sensor coverage lookup failed", "error", err)
		coverage = nil
	}
	agents, aerr := s.store.ListAgents(r.Context(), s.staleAfter())
	total := 0
	if aerr == nil {
		total = len(agents)
	}
	byOS, _ := s.store.AgentCountsByOS(r.Context())
	writeJSONResponse(w, listSensorsResponse{
		Sensors: docs, Coverage: coverage, AgentCount: total, AgentCountByOS: byOS,
	})
}
