// Package proto defines the message shapes shared by the agent and the
// server/console. Nothing here talks to NATS or Postgres directly — it is
// pure data so both sides serialize/deserialize identically.
package proto

import (
	"encoding/json"
	"time"
)

// AgentInfo is the static identity information an agent presents at
// registration and that the server keeps in inventory.
type AgentInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`      // runtime.GOOS: linux, windows, darwin
	Arch     string `json:"arch"`    // runtime.GOARCH: amd64, arm64
	Site     string `json:"site"`    // deployment/site label, e.g. "branch-1"
	Version  string `json:"version"` // agent build version
}

// RegisterRequest is sent by an agent on the register subject (request/reply)
// to obtain or reconfirm an agent_id.
type RegisterRequest struct {
	// AgentID is empty on first-ever registration. If the agent already has
	// a persisted ID (from bbolt) it sends it back so the server can
	// reconfirm the same identity rather than minting a new one.
	AgentID string    `json:"agent_id,omitempty"`
	Info    AgentInfo `json:"info"`
}

// RegisterResponse carries the agent_id the agent should persist and use for
// all subsequent subjects.
type RegisterResponse struct {
	AgentID string `json:"agent_id"`
}

// Heartbeat is published periodically by an agent so the server can detect
// staleness (agent goes offline).
type Heartbeat struct {
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
}

// Facts is a snapshot of gopsutil-derived host facts.
type Facts struct {
	AgentID     string    `json:"agent_id"`
	Timestamp   time.Time `json:"timestamp"`
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Platform    string    `json:"platform"` // e.g. "ubuntu", "windows", "darwin"
	PlatformVer string    `json:"platform_version"`
	KernelVer   string    `json:"kernel_version"`
	CPUCount    int       `json:"cpu_count"`
	MemTotalMB  uint64    `json:"mem_total_mb"`
	IPs         []string  `json:"ips"`
	AgentVer    string    `json:"agent_version"`
	Site        string    `json:"site"`
	UptimeSec   uint64    `json:"uptime_sec"`
	// Timezone is the host's IANA zone ("America/Los_Angeles") when the
	// agent can tell, and UTCOffsetSeconds its current offset from UTC;
	// both feed maintenance windows in endpoint local time. Agents before
	// 0.57.0 send neither.
	Timezone         string `json:"timezone,omitempty"`
	UTCOffsetSeconds *int   `json:"utc_offset_seconds,omitempty"`
	// Settings is what the agent is actually running with, so the server
	// can tell a client that drifted from its profile from one that took it.
	Settings *AgentSettings `json:"settings,omitempty"`
	// WatchRevision identifies the integrity watch set the agent is
	// running (see WatchConfig), so the server can tell an endpoint that
	// took its monitors from one that has not.
	WatchRevision string `json:"watch_revision,omitempty"`
}

// WatchConfig is the integrity watch set the server pushes with the
// "watch" command: what the monitors covering this endpoint add to the
// built-in set. Paths are files or directories; a path this OS does not
// have is skipped. Registry keys are Windows-only ("HKLM\...") and are
// hashed and diffed like files, and polled for real-time change.
type WatchConfig struct {
	Revision       string   `json:"revision"`
	Paths          []string `json:"paths,omitempty"`
	RegistryKeys   []string `json:"registry_keys,omitempty"`
	FollowSymlinks bool     `json:"follow_symlinks,omitempty"`
}

// AgentSettings are the runtime settings a client configuration profile
// pushes. Zero values mean "not set": an agent keeps whatever it has.
type AgentSettings struct {
	SensorIntervalSeconds int    `json:"sensor_interval_seconds,omitempty"`
	LogLevel              string `json:"log_level,omitempty"` // debug | info | warn | error
	// RandomDelaySeconds spreads each sensor publish over a random wait up
	// to this long, so a thousand agents sharing an interval do not all
	// report in the same second.
	RandomDelaySeconds int `json:"random_delay_seconds,omitempty"`
	// Profile names the profile these came from, echoed back so drift is
	// judged against the right one.
	Profile string `json:"profile,omitempty"`
	// NoRemoteCode says this endpoint runs in inventory-and-patching mode.
	// Reported, never applied: only a file on the endpoint sets it.
	NoRemoteCode bool `json:"no_remote_code,omitempty"`
}

// QueryKind enumerates the fixed set of safe, canned queries/sensors
// supported. There is no arbitrary code execution on agents yet — see
// docs/ROADMAP.md for the planned query/command language.
type QueryKind string

const (
	// QueryKindFacts asks an agent to return its current gopsutil-derived
	// fact snapshot (the same shape published on the facts subject).
	QueryKindFacts QueryKind = "facts"
	// QueryKindProcesses asks for the current running-process list.
	QueryKindProcesses QueryKind = "processes"
	// QueryKindServices asks for the current OS service list.
	QueryKindServices QueryKind = "services"
	// QueryKindInstalledApps asks for the current installed-application list.
	QueryKindInstalledApps QueryKind = "installed_apps"
	// QueryKindPatches asks for the current list of available (not yet
	// applied) OS patches/updates.
	QueryKindPatches QueryKind = "patches"
)

// ProcessInfo is one row of a QueryKindProcesses / SensorProcesses result.
type ProcessInfo struct {
	PID  int32  `json:"pid"`
	Name string `json:"name"`
	// PPID is what makes a process list a process *tree*. "powershell.exe
	// is running" is unremarkable; "powershell.exe was spawned by
	// winword.exe" is an incident, and the difference is one field.
	PPID     int32  `json:"ppid,omitempty"`
	Username string `json:"username,omitempty"`
	// Cmdline is truncated by the agent. It is the single most useful field
	// for working out what a process was actually doing, and also the one
	// most likely to be enormous — a Java service can carry kilobytes of
	// classpath that would be paid for by every collection, forever.
	Cmdline    string  `json:"cmdline,omitempty"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float32 `json:"mem_percent"`
	MemRSSMB   uint64  `json:"mem_rss_mb"`
}

// ServiceInfo is one row of a QueryKindServices / SensorServices result.
// StartType is best-effort — not every OS's service manager exposes it the
// same way, so it's left empty rather than guessed when unavailable.
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Status      string `json:"status"` // "running" | "stopped" | other OS-reported state
	StartType   string `json:"start_type,omitempty"`
}

// InstalledApp is one row of a QueryKindInstalledApps / SensorInstalledApps
// result.
type InstalledApp struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	// Executable is the product's main binary when the platform records
	// one (Windows DisplayIcon, the macOS bundle's CFBundleExecutable), so
	// the server can tie the product to process starts without guessing
	// from its display name. Lower-case base name, no path, no ".exe".
	Executable string `json:"executable,omitempty"`
	// InstallDate is YYYY-MM-DD where the platform knows it: the registry's
	// InstallDate on Windows, the dpkg/rpm install record on Linux, the app
	// bundle's modification time on macOS.
	InstallDate string `json:"install_date,omitempty"`
	// LastUsed is RFC 3339, from the endpoint's own record of when the
	// program last ran (Windows Prefetch, Spotlight's kMDItemLastUsedDate).
	// Empty where the platform keeps no such record; the server then relies
	// on process starts alone.
	LastUsed string `json:"last_used,omitempty"`
	// Source and SourceVersion are the source package a Linux package was
	// built from (dpkg's source:Package and source:Version, apk's origin),
	// when it differs from Name or Version or not. Security advisories for
	// Debian, Ubuntu and Alpine are filed by source package: libssl3t64's
	// are openssl's. Empty from older agents and other platforms; the
	// vulnerability scan then uses Name and Version.
	Source        string `json:"source,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// PatchInfo is one available (not yet applied) OS patch/update, one row of
// a QueryKindPatches / SensorPatches result. The field names are
// deliberately package-manager-neutral (Name/CurrentVersion/NewVersion)
// since Linux (apt/dnf), macOS (softwareupdate), and Windows (Windows
// Update) all report this differently — see internal/agent/patches.go for
// how each OS's native listing maps onto it.
type PatchInfo struct {
	Name           string `json:"name"`                      // package name, or the Windows Update KB/title
	CurrentVersion string `json:"current_version,omitempty"` // empty on Windows — Windows Update doesn't expose a comparable "installed version" for a pending update
	NewVersion     string `json:"new_version,omitempty"`
	Severity       string `json:"severity,omitempty"` // best-effort: "security" | "" (unknown/not distinguished on this OS)
	// RestartRequired: installing it restarts the machine, where the OS says
	// so up front (macOS "Action: restart"). Agents before 0.57.8 never set it.
	RestartRequired bool `json:"restart_required,omitempty"`
}

// Predicate is a minimal agent-side filter evaluated locally by each agent
// after it receives a QueryEnvelope. It lets a query narrow beyond what the
// coarse mustra.q.* subjects (all/os/site/agent) can express on their own,
// without the server having to resolve and enumerate a target list.
type Predicate struct {
	OS   string `json:"os,omitempty"`   // exact match against AgentInfo.OS if set
	Site string `json:"site,omitempty"` // exact match against AgentInfo.Site if set
}

// Match reports whether info satisfies the predicate. A nil predicate always
// matches (the coarse subject alone was enough targeting).
func (p *Predicate) Match(info AgentInfo) bool {
	if p == nil {
		return true
	}
	if p.OS != "" && p.OS != info.OS {
		return false
	}
	if p.Site != "" && p.Site != info.Site {
		return false
	}
	return true
}

// QueryEnvelope is published by the server to a mustra.q.* subject to fan a
// query out to a slice of the fleet.
type QueryEnvelope struct {
	QueryID   string     `json:"query_id"`
	Kind      QueryKind  `json:"kind"`
	IssuedAt  time.Time  `json:"issued_at"`
	Predicate *Predicate `json:"predicate,omitempty"`
	// AnswerWithinMs asks each agent to answer after a random delay of up
	// to this many milliseconds instead of at once, so that a fleet's
	// answers reach the control plane spread out rather than in one burst
	// the broker cuts the connection over. Zero (and older servers, which
	// never set it) means answer immediately; older agents ignore it.
	AnswerWithinMs int `json:"answer_within_ms,omitempty"`
}

// QueryResult is published by an agent on the per-query result subject in
// reply to a QueryEnvelope it matched. Exactly one of the sensor fields is
// populated, matching the envelope's Kind.
type QueryResult struct {
	// Pending: the agent is still collecting (a slow Windows Update
	// search) and publishes the result as its sensor when done.
	Pending       bool           `json:"pending,omitempty"`
	QueryID       string         `json:"query_id"`
	AgentID       string         `json:"agent_id"`
	Timestamp     time.Time      `json:"timestamp"`
	Facts         *Facts         `json:"facts,omitempty"`
	Processes     []ProcessInfo  `json:"processes,omitempty"`
	Services      []ServiceInfo  `json:"services,omitempty"`
	InstalledApps []InstalledApp `json:"installed_apps,omitempty"`
	Patches       []PatchInfo    `json:"patches,omitempty"`
	Error         string         `json:"error,omitempty"` // populated if the agent failed to answer
}

// SensorKind identifies a periodically-collected, centrally-cached sensor —
// the model: agents keep publishing their latest snapshot on a
// timer, the server caches the most recent one per (agent, sensor) so the
// console can show current data without a live round-trip, and a live query
// (QueryKind above) can still force an immediate fresh read on demand.
//
// Deliberately a separate concept from QueryKind even though the values
// overlap: QueryKind is "ask every matching agent right now, once"; a
// SensorKind is "keep this agent's cached snapshot fresh." Facts uses
// neither of these — it has its own dedicated subject/table since it
// backs core inventory columns, not a cache. See docs/ARCHITECTURE.md.
type SensorKind string

const (
	SensorActionLogs      SensorKind = "action_logs"
	SensorProcesses       SensorKind = "processes"
	SensorServices        SensorKind = "services"
	SensorInstalledApps   SensorKind = "installed_apps"
	SensorPatches         SensorKind = "patches"
	SensorDisks           SensorKind = "disks"
	SensorNetwork         SensorKind = "network"
	SensorUsers           SensorKind = "users"
	SensorHardware        SensorKind = "hardware"
	SensorPrivileges      SensorKind = "privileges"
	SensorNeighbors       SensorKind = "neighbors"
	SensorCertificates    SensorKind = "certificates"
	SensorPerformance     SensorKind = "performance"
	SensorIntegrity       SensorKind = "integrity"
	SensorLocalAdmins     SensorKind = "local_admins"
	SensorDirectory       SensorKind = "directory"
	SensorBackups         SensorKind = "backups"
	SensorSecurityPosture SensorKind = "security_posture"
	// SensorPatchStatus is the outcome of the last check for pending
	// updates (PatchStatus). A failed check publishes no patches snapshot,
	// so without it "nothing pending" and "could not look" read the same.
	SensorPatchStatus SensorKind = "patch_status"
)

// PatchStatus is published after every check for pending updates. Servers
// before it refuse the unknown kind and drop it, so the patches snapshot
// itself never changes shape.
type PatchStatus struct {
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	TimedOut  bool      `json:"timed_out,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	// FailingSince is when the checks started failing; the server fills
	// it in from the previous status, so it survives agent restarts.
	FailingSince *time.Time `json:"failing_since,omitempty"`
}

// PerformanceInfo summarizes an endpoint's recent health. Samples are kept
// on the endpoint and only this summary travels, because "is this machine
// healthy, and how often has it been unhealthy lately" is the question
// people actually ask — and answering it from counts rather than from
// several thousand shipped rows per endpoint per day keeps the server's
// database the size of an inventory rather than a metrics store.
type PerformanceInfo struct {
	CPUCurrent    float64 `json:"cpu_current"`
	CPUAverage    float64 `json:"cpu_average"`
	CPUPeak       float64 `json:"cpu_peak"`
	CPUEvents     int     `json:"cpu_events"`
	MemoryCurrent float64 `json:"memory_current"`
	MemoryAverage float64 `json:"memory_average"`
	MemoryPeak    float64 `json:"memory_peak"`
	MemoryEvents  int     `json:"memory_events"`
	DiskCurrent   float64 `json:"disk_current"`
	DiskPeak      float64 `json:"disk_peak"`
	DiskEvents    int     `json:"disk_events"`
	// Samples says how much history this summary covers. A machine that
	// restarted ten minutes ago has a short window, not a quiet one, and
	// the difference matters when reading a score built from it.
	Samples     int     `json:"samples"`
	WindowHours float64 `json:"window_hours"`
}

// IntegrityFile is one watched file's current state. The endpoint reports
// state; the server diffs consecutive snapshots to find change. That split
// is deliberate — keeping the baseline on the endpoint would mean an
// attacker who can rewrite the file can rewrite the baseline sitting next
// to it.
type IntegrityFile struct {
	Path          string `json:"path"`
	Hash          string `json:"hash,omitempty"`
	Size          int64  `json:"size"`
	Mode          string `json:"mode"`
	Owner         string `json:"owner,omitempty"`
	Group         string `json:"group,omitempty"`
	Modified      string `json:"modified"`
	SymlinkTarget string `json:"symlink_target,omitempty"`
}

// CertificateInfo is one X.509 certificate found on an endpoint.
//
// DaysLeft is computed on the endpoint at collection time rather than by
// the server, so it reflects that machine's own clock — a host whose clock
// is wrong will present an expired certificate regardless of what the
// server thinks the date is, and the inventory should say so.
type CertificateInfo struct {
	Path         string   `json:"path"`
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SerialNumber string   `json:"serial_number,omitempty"`
	Fingerprint  string   `json:"fingerprint"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	DaysLeft     int      `json:"days_left"`
	DNSNames     []string `json:"dns_names,omitempty"`
	IsCA         bool     `json:"is_ca"`
	SelfSigned   bool     `json:"self_signed"`
	// TrustStore marks a certificate that is part of the OS's bundled CA
	// list rather than one this machine serves or presents. A typical Linux
	// host carries ~150 of them, all healthy and none actionable, so they
	// would bury the handful of certificates an operator can actually do
	// something about. Reported, but separated.
	TrustStore   bool   `json:"trust_store,omitempty"`
	KeyAlgorithm string `json:"key_algorithm,omitempty"`
	SigAlgorithm string `json:"sig_algorithm,omitempty"`
}

// NeighborInfo is one host this endpoint has recently talked to, read from
// its ARP/NDP table. Collecting it puts nothing on the wire, and the union
// across a fleet is a map of the network — including devices that never
// answer a scan.
type NeighborInfo struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface,omitempty"`
	State     string `json:"state,omitempty"`
}

// PrivilegeInfo is what the agent can actually do on this endpoint.
//
// Running as root or LocalSystem is necessary but not sufficient: macOS
// gates whole categories of access behind TCC, which root does not bypass,
// and a Windows token carries privileges that are present but disabled
// until a process explicitly enables them. So rather than assume the agent
// is omnipotent because it's elevated, each agent measures what it can do
// and reports the gaps — the console can then show exactly which endpoints
// are not fully manageable and why, instead of failing mysteriously later.
type PrivilegeInfo struct {
	Account    string `json:"account"`           // the account the agent runs as
	UID        int    `json:"uid"`               // -1 on Windows
	Elevated   bool   `json:"elevated"`          // root, or a LocalSystem/Administrator token
	Service    string `json:"service,omitempty"` // systemd / launchd / windows-service
	FullRights bool   `json:"full_rights"`       // nothing in Limitations blocks management

	// Limitations are the things this agent currently cannot do, in words
	// an operator can act on. Empty means fully privileged.
	Limitations []string `json:"limitations,omitempty"`
	// Remedy pairs with Limitations: how to grant what's missing.
	Remedy []string `json:"remedy,omitempty"`

	// macOS
	FullDiskAccess bool `json:"full_disk_access,omitempty"`
	SIPEnabled     bool `json:"sip_enabled,omitempty"`
	MDMEnrolled    bool `json:"mdm_enrolled,omitempty"`

	// Windows
	IntegrityLevel    string   `json:"integrity_level,omitempty"`
	EnabledPrivileges []string `json:"enabled_privileges,omitempty"`
	MissingPrivileges []string `json:"missing_privileges,omitempty"`

	// Linux
	CapEffective string `json:"cap_effective,omitempty"`
}

// DiskInfo is one mounted filesystem.
type DiskInfo struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	FSType      string  `json:"fstype"`
	TotalGB     float64 `json:"total_gb"`
	FreeGB      float64 `json:"free_gb"`
	UsedGB      float64 `json:"used_gb"`
	UsedPercent float64 `json:"used_percent"`
}

// NetworkInterfaceInfo is one network interface as the host sees it.
type NetworkInterfaceInfo struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
}

// LoggedInUser is one active login session.
type LoggedInUser struct {
	User     string `json:"user"`
	Terminal string `json:"terminal,omitempty"`
	Host     string `json:"host,omitempty"`
	Started  string `json:"started,omitempty"`
	// SessionID is the Windows session number (quser's ID column), which
	// shadowing a session needs; 0 on other platforms and from agents
	// before 0.57.42. State is quser's STATE: "Active" or "Disc".
	SessionID int    `json:"session_id,omitempty"`
	State     string `json:"state,omitempty"`
}

// Reveal: sensitive-data discovery. A job is one rule's worth of work on
// one endpoint; the report is what came back.

// RevealPattern is a regular expression plus the name of a validator that
// confirms a match (Luhn for card numbers, the area/group/serial rules for
// SSNs, mod-97 for IBANs). The validator is named rather than sent so the
// agent runs only code it ships with.
type RevealPattern struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Regex    string `json:"regex"`
	Validate string `json:"validate,omitempty"` // "" | luhn | ssn | iban
}

// RevealPair requires two patterns to appear near each other in the same
// file before it counts. This is what separates "a file containing a
// sixteen-digit number" from "a file containing a card number next to an
// expiry date" — proximity is most of what makes a sensitive-data finding
// real rather than a coincidence of digits.
type RevealPair struct {
	A      string `json:"a"`      // pattern id
	B      string `json:"b"`      // pattern id
	Within int    `json:"within"` // characters between the two matches
}

type RevealJob struct {
	ScanID             string          `json:"scan_id"`
	RuleID             string          `json:"rule_id"`
	RuleName           string          `json:"rule_name,omitempty"`
	Roots              []string        `json:"roots"`
	Exclude            []string        `json:"exclude,omitempty"`    // directory names or path prefixes never entered
	Extensions         []string        `json:"extensions,omitempty"` // lower-case, without the dot; empty means the built-in text set
	MaxSizeBytes       int64           `json:"max_size_bytes,omitempty"`
	ModifiedWithinDays int             `json:"modified_within_days,omitempty"`
	Patterns           []RevealPattern `json:"patterns"`
	MinMatches         int             `json:"min_matches,omitempty"` // per file per pattern before it is reported
	// RequirePairs, when set, reports a file only if at least one listed
	// pair of patterns matched within its window of each other.
	RequirePairs      []RevealPair `json:"require_pairs,omitempty"`
	MaxFiles          int          `json:"max_files,omitempty"`
	TimeBudgetSeconds int          `json:"time_budget_seconds,omitempty"`
	Snippets          bool         `json:"snippets"`
}

// RevealMatch is one file that matched one pattern. Snippet is masked: a
// card number reads as 4111 **** **** 1111, so what leaves the endpoint is
// evidence that the data is there, not the data.
type RevealMatch struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Modified  string `json:"modified,omitempty"`
	PatternID string `json:"pattern_id"`
	Count     int    `json:"count"`     // raw regex matches
	Confirmed int    `json:"confirmed"` // of those, passed the validator (equal to Count when there is none)
	Snippet   string `json:"snippet,omitempty"`
}

type RevealReport struct {
	ScanID       string        `json:"scan_id"`
	RuleID       string        `json:"rule_id"`
	AgentID      string        `json:"agent_id"`
	Started      string        `json:"started"`
	Finished     string        `json:"finished"`
	FilesSeen    int           `json:"files_seen"`    // walked
	FilesScanned int           `json:"files_scanned"` // read and searched
	FilesMatched int           `json:"files_matched"`
	Skipped      int           `json:"skipped"` // binary, too large, unreadable
	Truncated    bool          `json:"truncated"`
	Error        string        `json:"error,omitempty"`
	Matches      []RevealMatch `json:"matches"`
}

// SensorReveal is the snapshot kind a scan report travels on. It is not a
// periodic sensor -- there is no loop -- but it uses the same durable path
// and the same broker permission as every other snapshot.
const SensorReveal SensorKind = "reveal"

// LocalAdmin is one principal that can administer the endpoint: a member
// of the local Administrators group on Windows, of sudo/wheel/admin or a
// sudoers grant on Linux, of the admin group on macOS. It is the endpoint
// half of Impact: who can take this machine over, so that the directory
// half can say what else they can then reach.
//
// SID is filled where the platform has one (Windows), and it is what the
// server resolves against the directory; the name is the fallback. Kind is
// what the endpoint could tell — "user", "group", or "unknown" — and the
// directory may know better.
type LocalAdmin struct {
	Name   string `json:"name"`             // account or group name, without a domain prefix
	Domain string `json:"domain,omitempty"` // the prefix, when there was one: the domain, or the machine itself
	SID    string `json:"sid,omitempty"`
	Kind   string `json:"kind"`             // user | group | unknown
	Source string `json:"source,omitempty"` // local | domain | builtin | unknown
	Via    string `json:"via,omitempty"`    // how the right is held: "Administrators", "sudo group", "sudoers", "uid 0", "admin group"
}

// HardwareInfo is the machine's fixed characteristics — a single row, but
// carried as a sensor so adding fields never needs a database migration.
type HardwareInfo struct {
	HostID               string  `json:"host_id,omitempty"`
	OSFamily             string  `json:"os_family,omitempty"`
	KernelArch           string  `json:"kernel_arch,omitempty"`
	CPUModel             string  `json:"cpu_model,omitempty"`
	CPUVendor            string  `json:"cpu_vendor,omitempty"`
	CPUCoresPhysical     int     `json:"cpu_cores_physical"`
	CPUCoresLogical      int     `json:"cpu_cores_logical"`
	CPUMHz               float64 `json:"cpu_mhz,omitempty"`
	MemTotalMB           uint64  `json:"mem_total_mb"`
	MemAvailableMB       uint64  `json:"mem_available_mb"`
	MemUsedPercent       float64 `json:"mem_used_percent"`
	SwapTotalMB          uint64  `json:"swap_total_mb"`
	VirtualizationSystem string  `json:"virtualization_system,omitempty"`
	VirtualizationRole   string  `json:"virtualization_role,omitempty"`
	BootTime             string  `json:"boot_time,omitempty"`
	UptimeHours          float64 `json:"uptime_hours"`
	LoadAvg1             float64 `json:"load_avg_1,omitempty"`
	LoadAvg5             float64 `json:"load_avg_5,omitempty"`
	LoadAvg15            float64 `json:"load_avg_15,omitempty"`
	TempMaxC             float64 `json:"temp_max_c,omitempty"`
	// The machine's identity for asset tracking: who made it, the model,
	// the serial number, the firmware date (a stand-in for its age), and
	// the chassis (laptop, desktop, server, mini PC, virtual).
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
	BIOSDate     string `json:"bios_date,omitempty"` // YYYY-MM-DD
	Chassis      string `json:"chassis,omitempty"`
}

// SensorSnapshot is what an agent publishes periodically for a given
// sensor. Data is the JSON-encoded sensor payload (e.g. []ProcessInfo) —
// kept as raw bytes here so the server can persist it to Postgres JSONB
// without needing a Go type per sensor kind on the read/write path.
type SensorSnapshot struct {
	AgentID   string          `json:"agent_id"`
	Sensor    SensorKind      `json:"sensor"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// AgentCommand is sent by the server to a single agent on its command
// subject (request/reply) for operational control that isn't a query.
// "set_sensor_interval" adjusts a sensor's periodic publish interval.
// "apply_patches" is deliberately narrow, not general command execution:
// it runs exactly one well-known, OS-native "install pending updates"
// invocation (apt-get upgrade, softwareupdate -i -a, or the Windows Update
// COM API) — see internal/agent/patches.go — rather than accepting
// arbitrary text, which is what keeps this off the "needs a full
// signing/authz story first" list in docs/ROADMAP.md even though a
// fleet-wide RCE-shaped command channel otherwise would be. The reply
// acknowledges the command started, not that patching finished — that can
// take minutes, so the agent republishes the patches sensor when done and
// the console just re-polls the cached snapshot.
type AgentCommand struct {
	DeploySettings  *DeploySettings  `json:"deploy_settings,omitempty"`
	Deploy          *DeployJob       `json:"deploy,omitempty"`
	Force           bool             `json:"force,omitempty"`
	CustomSensor    *CustomSensorDef `json:"custom_sensor,omitempty"`
	Cmd             string           `json:"cmd"` // "set_sensor_interval" | "apply_patches" | "run_software" | "notify_user" | "ask_user" | "kill_process"
	Sensor          SensorKind       `json:"sensor,omitempty"`
	IntervalSeconds int              `json:"interval_seconds,omitempty"`

	// Patches narrows "apply_patches" to these pending updates by name
	// (apt/dnf package names, macOS softwareupdate labels, Windows update
	// titles), the outcome of the server's patch lists and block lists. An
	// agent older than 0.44.0 ignores it and applies everything, which is
	// why the server refuses to dispatch a narrowed run to such an agent.
	// Selective distinguishes "the policy allowed nothing" (apply nothing)
	// from "no policy" (empty Patches, apply everything).
	Patches   []string `json:"patches,omitempty"`
	Selective bool     `json:"selective,omitempty"`

	// RebootMode is what "apply_patches" does once the updates installed
	// cleanly: "" leaves the endpoint alone, "if_required" restarts it when
	// the updates need one, "always" restarts it either way.
	// RebootWarnMinutes is the operating system's own restart countdown,
	// with its warning shown to whoever is signed in. Agents before 0.57.2
	// ignore both, so the server does not send a restart to them.
	RebootMode        string `json:"reboot_mode,omitempty"`
	RebootWarnMinutes int    `json:"reboot_warn_minutes,omitempty"`
	// MacOSViaMDM tells a Mac agent that the server hands macOS updates to
	// an MDM after this job, so a skipped one is not left to the user.
	MacOSViaMDM bool `json:"macos_via_mdm,omitempty"`
	// Cert carries a certificate renewal step (cert_csr, cert_install).
	Cert *CertJob `json:"cert,omitempty"`
	// Secret carries a renewed application credential to write
	// (secret_write).
	Secret *SecretWriteJob `json:"secret,omitempty"`
	// JIT carries a temporary sign-in account for a remote session
	// (jit_create, jit_remove).
	JIT *JITAccountJob `json:"jit,omitempty"`

	// Watch carries the integrity watch set for "watch".
	Watch *WatchConfig `json:"watch,omitempty"`

	// Settings carries a client configuration profile for "configure".
	// The agent applies what is set, persists it, and republishes facts so
	// the server sees the new state without waiting a minute.
	Settings *AgentSettings `json:"settings,omitempty"`

	// Command carries the software-package operation to run, for
	// "run_software" only. Unlike apply_patches — which is deliberately a
	// fixed command the agent constructs itself — this is authored by an
	// operator holding deploy.manage and runs with the agent's full
	// rights. That is the point of a software package, and it is why
	// authoring one is a privileged action and every run is recorded
	// against a deployment ID with its output.
	Command string `json:"command,omitempty"`

	// Checks carries the compliance policy for "run_compliance". Sent with
	// the command rather than configured on the endpoint, so a new
	// benchmark is a data change rather than a fleet-wide agent upgrade.
	Checks []ComplianceCheck `json:"checks,omitempty"`

	// Reveal carries a sensitive-data scan for "reveal_scan". The agent
	// answers "started" immediately and publishes the outcome as a
	// "reveal" sensor snapshot when the walk finishes, because a scan of a
	// home directory can outlive any request timeout.
	Reveal *RevealJob `json:"reveal,omitempty"`

	// Enforce carries the desired-state policy for "run_enforce". Whether
	// each setting may actually be remediated is decided per setting by the
	// server, not by the agent — see EnforceSetting.Enforce.
	Enforce *EnforcePolicySpec `json:"enforce,omitempty"`

	// PID and ProcessName target "kill_process". The name is not
	// redundant: between the sensor collection that showed the process and
	// the moment the kill lands, the PID may have been recycled onto
	// something else entirely. The agent checks the name still matches
	// before signalling anything.
	PID         int32  `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`

	// Update carries a signed update for "update_agent" when the operator
	// chose it explicitly (a downgrade, which needs a manifest naming this
	// agent). Without it the agent asks the server, as before.
	Update *UpdateOffer `json:"update,omitempty"`

	// Files are payloads to stage before the command runs, for
	// "run_software". The agent downloads each into a working directory,
	// verifies its hash and runs the command there.
	Files []PackageFileRef `json:"files,omitempty"`

	// Notify carries the message for "notify_user".
	Notify *EndUserNotification `json:"notify,omitempty"`

	// Survey carries the questionnaire for "ask_user". A separate command
	// from notify_user because the two are not the same act: a
	// notification is told to somebody and answered from a fixed
	// vocabulary; a survey asks them something and waits for their words.
	Survey *SurveyPrompt `json:"survey,omitempty"`

	// TimeoutSeconds caps how long the endpoint may spend on this command,
	// a per-package command timeout. 0 means the agent's
	// own default -- the right budget differs enormously between flushing a
	// DNS cache and installing an office suite, so it belongs with the
	// package rather than baked into the agent.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`

	// RunID and ActionID name the deployment record this command belongs
	// to. They exist so an agent can report the *real* outcome of a job
	// that outlives the request/reply — see AgentActionResult. An agent
	// that doesn't understand them simply ignores them, which is what
	// makes this safe to roll out ahead of the fleet.
	RunID    string `json:"run_id,omitempty"`
	ActionID string `json:"action_id,omitempty"`
}

// Custom sensors: operator-authored collection. The agent asks the server
// which ones apply to it (agent-initiated request/reply, like the patch-list
// query) rather than the server pushing them, because it is the agent's own
// timer that drives collection.
type CustomSensorRequest struct {
	Version int `json:"version,omitempty"`
	// The agent ID comes off the subject. Version 0 is the original
	// shell-only contract; version 1 understands explicit execution types;
	// version 2 supports checksum-verified Go executables.
}

// CustomSensorDef is one custom sensor as it applies to ONE agent: the
// server has already resolved the per-OS command down to the single command
// this endpoint should run, so the agent never has to know the others exist.
type CustomSensorDef struct {
	Inputs   map[string]string `json:"inputs,omitempty"`
	Artifact *SensorArtifact   `json:"artifact,omitempty"`
	Platform SensorPlatform    `json:"platform"`
	Revision string            `json:"revision,omitempty"`
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	// Sensor is the name results are published under, e.g. "custom_csn-abc".
	Sensor          string `json:"sensor"`
	Command         string `json:"command"`
	IntervalSeconds int    `json:"interval_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
}

type CustomSensorReply struct {
	Sensors []CustomSensorDef `json:"sensors"`
	Error   string            `json:"error,omitempty"`
}

// CustomSensorResult retains stdout and diagnostic status for inspection and
// old servers. The control plane owns normalization into Rows and Fields; it
// never trusts an agent-supplied row projection for targeting.
type CustomSensorResult struct {
	Fields    []SensorField    `json:"fields,omitempty"`
	Raw       *string          `json:"raw,omitempty"`
	Stderr    string           `json:"stderr,omitempty"`
	Revision  string           `json:"revision,omitempty"`
	Rows      []map[string]any `json:"rows,omitempty"`
	Truncated bool             `json:"truncated,omitempty"`
	Lines     []string         `json:"lines"`
	ExitCode  int              `json:"exit_code"`
	Error     string           `json:"error,omitempty"`
	TimedOut  bool             `json:"timed_out,omitempty"`
}

// EndUserNotification is a message shown to the person at the endpoint.
//
// Two kinds, because they are genuinely different acts: a
// "notice" informs, and a "restart" negotiates. A restart carries a
// countdown, a deadline and a bounded set of postponements, since the
// alternative -- rebooting a machine under whoever is using it -- is how a
// management tool teaches a company to uninstall it.
const (
	EUNKindNotice  = "notice"
	EUNKindRestart = "restart"
)

// The answers a person can give. A custom button relabels one of these; it
// never introduces a fourth, because every one of them already has a meaning
// the agent acts on and the deployment record stores.
const (
	EUNActionAcknowledged = "acknowledged"
	EUNActionPostponed    = "postponed"
	EUNActionRestartNow   = "restart_now"
)

// EUNButton is one operator-defined choice on a notification.
//
// Label is the only free text: Action stays inside the vocabulary above, so
// relabelling "Got it" to "Understood, thanks" changes what the person reads
// and nothing about what is recorded, what the agent does, or what a report
// can be run over afterwards. A button that could invent its own outcome
// would make the answer column untrustworthy the first time someone typed
// one.
type EUNButton struct {
	Label  string `json:"label"`
	Action string `json:"action"`
	// Minutes is how long "postponed" postpones for, and is ignored on
	// every other action.
	Minutes int `json:"minutes,omitempty"`
	// Primary draws the button as the emphasised one. At most one.
	Primary bool `json:"primary,omitempty"`
}

type EndUserNotification struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"` // "notice" | "restart"
	Title string `json:"title"`
	Body  string `json:"body,omitempty"`

	// Buttons, when set, replace the choices the window would otherwise
	// render for this kind. Empty means the defaults, which is what every
	// message sent before this field existed carries -- and what an agent
	// too old to understand the field will show regardless.
	Buttons []EUNButton `json:"buttons,omitempty"`
	// Deadline is when the message stops being worth showing at all.
	Deadline *time.Time `json:"deadline,omitempty"`

	// Restart only.
	AllowPostpone    bool  `json:"allow_postpone,omitempty"`
	CountdownMinutes int   `json:"countdown_minutes,omitempty"`
	GentleMinutes    int   `json:"gentle_minutes,omitempty"`
	PostponeMinutes  []int `json:"postpone_minutes,omitempty"`

	// RunID and ActionID tie the person's answer back to the deployment
	// that sent it, so "who did we ask and what did they say" is one
	// question with one answer rather than a log to correlate by hand.
	RunID    string `json:"run_id,omitempty"`
	ActionID string `json:"action_id,omitempty"`
}

// EUNResponse is what the person did about it. Recorded because the answer
// is the point: a restart prompt that nobody can prove was postponed twice
// is indistinguishable from one that was never shown.
type EUNResponse struct {
	Action string `json:"action"` // "acknowledged" | "postponed" | "restart_now" | "expired"
	// PostponeMinutes is set when Action is "postponed".
	PostponeMinutes int `json:"postpone_minutes,omitempty"`
}

// Engage: asking the person at the endpoint something, rather than telling
// them something.
//
// This rides the notification machinery — the Self Service window is the
// reliable channel, a native toast is the best-effort nudge — because a
// survey has exactly the delivery problem a notice has. What it does not
// share is the answer model: a notice is answered from a closed vocabulary
// the agent acts on, and a survey is answered in the person's own terms.
const (
	// SurveyRating is 1–5. Scored.
	SurveyRating = "rating"
	// SurveyChoice is one of Options. Scored only if the operator says
	// which options are positive — see SurveyQuestion.Positive.
	SurveyChoice = "choice"
	// SurveyText is free text. Never scored: sentiment inferred from prose
	// by keyword counting is a guess wearing a number's clothes, and the
	// whole point of the score is that it is arithmetic anyone can check.
	SurveyText = "text"
)

type SurveyQuestion struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Text     string   `json:"text"`
	Options  []string `json:"options,omitempty"`
	Required bool     `json:"required,omitempty"`
	// Positive lists the options that count as a good answer, for a choice
	// question the operator wants scored. Absent means the question is
	// collected and not scored — which is the safe default, because
	// guessing that "Other" is negative is how a sentiment score becomes
	// fiction.
	Positive []string `json:"positive,omitempty"`
}

// SurveyPrompt is one questionnaire as the endpoint receives it.
type SurveyPrompt struct {
	ID        string           `json:"id"`
	Title     string           `json:"title"`
	Intro     string           `json:"intro,omitempty"`
	Questions []SurveyQuestion `json:"questions"`
	// Anonymous drops the endpoint and user identity when the answer is
	// stored. It is a promise made to the person answering, so it is
	// carried on the prompt they are shown rather than applied later by
	// the server: what they were told is what happens.
	Anonymous bool       `json:"anonymous,omitempty"`
	Deadline  *time.Time `json:"deadline,omitempty"`

	RunID    string `json:"run_id,omitempty"`
	ActionID string `json:"action_id,omitempty"`
}

type SurveyAnswer struct {
	QuestionID string `json:"question_id"`
	Rating     int    `json:"rating,omitempty"`
	Choice     string `json:"choice,omitempty"`
	Text       string `json:"text,omitempty"`
}

// SurveyAnswers is what came back.
//
// Declined is not an empty response. Somebody who was asked and said no is
// a different fact from somebody who was never asked, and only the first
// one tells you the question was unwelcome. Collapsing them is how a
// survey answered by the four angriest people gets reported as the mood of
// the fleet.
type SurveyAnswers struct {
	SurveyID string         `json:"survey_id"`
	Answers  []SurveyAnswer `json:"answers,omitempty"`
	Declined bool           `json:"declined,omitempty"`
	User     string         `json:"user,omitempty"`
}

// AgentActionResult is how a long-running command reports what actually
// happened, published on AgentActionResult(agentID) once the work is done.
//
// It exists because AgentCommandResult can only ever say "the job started":
// installing patches takes minutes to hours, so the request/reply returns
// long before the outcome is known. Without this the control plane recorded
// every apply as successful the instant the agent acknowledged it, which
// made a failed or killed patch run indistinguishable from a clean one.
type AgentActionResult struct {
	DeployEvent *DeployEvent `json:"deploy_event,omitempty"`
	Status      string       `json:"status,omitempty"`
	AgentID     string       `json:"agent_id"`
	RunID       string       `json:"run_id"`
	ActionID    string       `json:"action_id"`
	// Kind mirrors store.AgentAction.Kind ("patch_apply", …) so a result
	// can be attributed even if the action row is missing.
	Kind string `json:"kind"`
	OK   bool   `json:"ok"`
	// TimedOut distinguishes "the agent gave up waiting" from "the command
	// failed". A cumulative Windows update that ran past the agent's cap is
	// a different operational problem than one that errored out, and the
	// two used to look identical (both surfaced as "exit status 1").
	TimedOut bool   `json:"timed_out,omitempty"`
	Detail   string `json:"detail,omitempty"`
	// Progress marks an interim report: Status is then one of the patch
	// taxonomy states ("downloading", "installing") and the action stays
	// open. A final report has Progress false.
	Progress bool `json:"progress,omitempty"`
	// RebootRequired on a final report means the updates are installed
	// but not in effect until the endpoint restarts: "pending restart".
	RebootRequired bool `json:"reboot_required,omitempty"`
	// Verification marks the agent's check after a restart on a patch job
	// it left at "pending restart": it closes that action rather than
	// reporting a new run. Older servers ignore the field and simply
	// record the final state, which is still the right answer.
	Verification bool `json:"verification,omitempty"`
	// Attempt counts retries of the same run (a package-manager lock held
	// by unattended-upgrades, say); the console shows "– Retry N".
	Attempt   int       `json:"attempt,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	// Survey carries a questionnaire's answers back. Structured rather
	// than stuffed into Detail because the answers are the data — a
	// sentiment score computed by parsing a human-readable sentence would
	// break the first time somebody's free text contained a comma.
	Survey *SurveyAnswers `json:"survey,omitempty"`
}

// PackageFileRef is one payload the endpoint should fetch before running a
// package's command.
//
// The URL carries a per-dispatch token rather than the file being on an open
// path: these are installers, often licensed. SHA256 is checked after
// download, because a file that silently truncated is worse than one that
// failed to arrive — the command would run against it anyway.
type PackageFileRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
	Size   int64  `json:"size,omitempty"`
}

// AgentCommandResult is the reply to an AgentCommand.
type AgentCommandResult struct {
	ActionLogs    []DeployEvent       `json:"action_logs,omitempty"`
	LogsTruncated bool                `json:"logs_truncated,omitempty"`
	DeployVersion int                 `json:"deploy_version,omitempty"`
	CustomSensor  *CustomSensorResult `json:"custom_sensor,omitempty"`
	OK            bool                `json:"ok"`
	Error         string              `json:"error,omitempty"`
	Output        string              `json:"output,omitempty"`
	Results       []ComplianceResult  `json:"results,omitempty"`

	// Enforced is the per-setting outcome of "run_enforce".
	Enforced []EnforceResult `json:"enforced,omitempty"`
}

// Self Service: the window a person opens on their own machine. The agent
// asks the server what this device may install and what has been done to
// it; the server owns every authorization decision, so the local UI can
// never talk the agent into installing something it isn't entitled to.
// ComplianceCheck is one benchmark item, sent from the control plane so a
// new benchmark is a data change rather than a fleet-wide agent upgrade.
//
// The rule syntax is Wazuh's SCA dialect, deliberately: it lets mustra read
// the CIS policies Wazuh publishes as YAML without running Wazuh's stack
// alongside this one or putting a second agent on every endpoint.
type ComplianceCheck struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Rationale   string   `json:"rationale,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Condition   string   `json:"condition,omitempty"` // all (default) | any | none
	Rules       []string `json:"rules"`
	// Controls maps a framework ("nist_800_53", "nist_800_171", "cmmc",
	// "hipaa"…) to the control IDs this check provides evidence for, as
	// the benchmark's `compliance:` block states them. Server-side
	// reporting only; agents ignore it.
	Controls map[string][]string `json:"controls,omitempty"`
}

// ComplianceResult is one check's outcome on one endpoint. "unknown" is a
// first-class state: a check whose rules couldn't be evaluated must not
// read as a pass, because a false assurance is the one failure mode
// compliance tooling cannot have.
type ComplianceResult struct {
	ID     string `json:"id"`
	Title  string `json:"title,omitempty"`
	State  string `json:"state"` // pass | fail | unknown
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Enforce: desired state, not a finding.
//
// Compliance answers "is this machine as it should be" and stops there.
// Enforce answers the same question and then does something about it, which
// is a different and much sharper tool: it changes machines on a timer with
// nobody watching. Everything in these types exists to keep that safe.
//
// A setting reuses the compliance rule dialect to *describe* the desired
// state, because that engine already reads files, commands, processes and
// the Windows registry, and inventing a second way to say "the firewall is
// on" would mean two dialects to learn and two to get wrong.

// EnforceSetting is one thing that must be true, and what to run when it
// isn't. Remediation is per platform and may be blank: a setting with no
// remediation for the platform it lands on reports drift rather than
// pretending it was fixed.
type EnforceSetting struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Severity  string   `json:"severity,omitempty"`
	Condition string   `json:"condition,omitempty"` // all (default) | any | none
	Rules     []string `json:"rules"`

	RemediateLinux   string `json:"remediate_linux,omitempty"`
	RemediateWindows string `json:"remediate_windows,omitempty"`
	RemediateDarwin  string `json:"remediate_darwin,omitempty"`

	// Enforce is decided per (endpoint, setting) by the server and sent
	// with the command, rather than being a property of the policy the
	// agent reads for itself. The server is the only party that knows this
	// remediation has already failed three times in a row on this machine,
	// and a remediation that has failed three times will fail a fourth —
	// while still running, every half hour, forever. False here means
	// "check it and report; do not touch it".
	Enforce bool `json:"enforce,omitempty"`
}

// EnforceResult is one setting's outcome on one endpoint.
//
// The states are deliberately more than pass/fail, because "it was wrong
// and I fixed it" and "it was wrong and I could not fix it" are the two
// answers anyone actually wants, and both are invisible in a boolean.
type EnforceResult struct {
	SettingID string `json:"setting_id"`
	Name      string `json:"name,omitempty"`
	State     string `json:"state"` // compliant | drifted | remediated | failed | unknown
	Detail    string `json:"detail,omitempty"`
	// Output of the remediation command, when one ran. Kept even on
	// success: "what did that command actually print on my domain
	// controller" is not a question to answer by running it again.
	Output string `json:"output,omitempty"`
}

// Real-time file events: a change reported as it happens.
//
// The hash baseline (SensorIntegrity) answers "has this changed since last
// time" and cannot miss a change made while the agent was down. This
// answers "when, exactly" — and it is the half that can catch a dropper
// within seconds of it landing rather than at the next sweep. Neither
// replaces the other, and this one deliberately does not claim to say
// *what* changed the file: attribution needs kernel plumbing mustra does
// not have, and a guess would be worse than the gap.

// FileEvent is one filesystem change on a watched path.
type FileEvent struct {
	Path string    `json:"path"`
	Op   string    `json:"op"` // create | write | remove | rename | chmod
	At   time.Time `json:"at"`
}

// FileEventBatch is what the agent publishes on a flush.
//
// Suppressed is load-bearing rather than diagnostic. A package install can
// touch hundreds of files under /etc in a second, and an agent that
// faithfully reported every one would produce exactly the flood that makes
// a security feed unreadable — so past the cap the events are counted
// instead of sent, and the count says so out loud. Silently dropping them
// would leave the console claiming a quiet minute.
type FileEventBatch struct {
	AgentID    string      `json:"agent_id"`
	Events     []FileEvent `json:"events"`
	Suppressed int         `json:"suppressed,omitempty"`
	Watching   int         `json:"watching,omitempty"` // directories under watch
	Since      time.Time   `json:"since"`
	Until      time.Time   `json:"until"`
}

// Real-time process events: something started, reported as it starts.
//
// The processes sensor is a snapshot on a timer, so anything that runs and
// exits between two collections never existed as far as the console is
// concerned — which is most of what an attacker runs. This is the other
// half, and how it is obtained differs by platform enough that the agent
// says which mechanism produced a batch rather than letting the reader
// assume.

// ProcessEvent is one process starting.
//
// Cmdline is the field worth having and the one most likely to be missing:
// a process that exits within milliseconds of starting is gone before its
// command line can be read, and reporting the name alone is better than
// dropping the event. Username has the same property.
type ProcessEvent struct {
	PID      int32     `json:"pid"`
	PPID     int32     `json:"ppid,omitempty"`
	Name     string    `json:"name"`
	Cmdline  string    `json:"cmdline,omitempty"`
	Username string    `json:"username,omitempty"`
	At       time.Time `json:"at"`
	// Count collapses identical invocations inside one flush. A hypervisor
	// runs `systemctl status canary.service` several hundred times a
	// minute; measured on a real one, collapsing by (name, command line,
	// user) cut 1530 events a minute to 169, and the surviving rows say
	// more — "×587" is a fact, five hundred and eighty-seven identical rows
	// are noise. PID is whichever came first, because for a repeated
	// identical command the individual PIDs carry nothing.
	Count int `json:"count,omitempty"`
}

// ProcessEventBatch is what the agent publishes on a flush.
//
// Source names the mechanism, because it decides what the absence of an
// event means. "netlink" sees every exec, including a process that lives
// for two milliseconds. "poll" compares snapshots, so it sees what was
// alive at a sample point and nothing shorter-lived than the interval —
// a real limit, and one a reader has to know about before concluding
// nothing ran.
type ProcessEventBatch struct {
	AgentID    string         `json:"agent_id"`
	Events     []ProcessEvent `json:"events"`
	Suppressed int            `json:"suppressed,omitempty"`
	// Unidentified counts execs seen by the kernel whose process was gone
	// before /proc could be read. Counted rather than invented: a name
	// guessed from nothing is worse than a gap, and a box with hundreds of
	// unidentifiable execs is itself the signal.
	Unidentified int       `json:"unidentified,omitempty"`
	Source       string    `json:"source"` // netlink | poll
	Since        time.Time `json:"since"`
	Until        time.Time `json:"until"`
}

// EnforcePolicySpec is what the agent receives: a name for logging and the
// settings to evaluate. No targeting, no schedule — the server resolved
// both before this was sent.
type EnforcePolicySpec struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Settings []EnforceSetting `json:"settings"`
}

// ShellRequest asks an agent to run one command in a live session.
//
// Deliberately request/reply per command rather than a streamed PTY. A PTY
// would be nicer to use and much harder to audit: every keystroke becomes
// a frame, and "what did this operator actually run" stops being a
// question the record can answer. One command in, one result out, every
// one logged with who asked — that is the property worth keeping, and it
// is the difference between a support tool and an unaccountable backdoor.
type ShellRequest struct {
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
	// WorkingDir persists between commands in a session, so `cd` behaves
	// the way anyone typing into a shell expects.
	WorkingDir string `json:"working_dir,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

// ShellReply is one command's result.
type ShellReply struct {
	Output     string `json:"output"`
	ExitCode   int    `json:"exit_code"`
	WorkingDir string `json:"working_dir,omitempty"`
	Error      string `json:"error,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

type SelfServiceRequest struct {
	Action string `json:"action"` // "state" | "install" | "request" | "install_result"
	ItemID string `json:"item_id,omitempty"`
	Reason string `json:"reason,omitempty"`
	User   string `json:"user,omitempty"`   // the local OS user who clicked
	RunID  string `json:"run_id,omitempty"` // echoed back on install_result
	OK     bool   `json:"ok,omitempty"`
	Detail string `json:"detail,omitempty"`
	// BrandingVersion is the branding the agent already holds, so a state
	// reply only carries the images and text when they have changed. The
	// window asks for state every time it is opened; resending a logo and a
	// background image on each of those would be most of the traffic.
	BrandingVersion string `json:"branding_version,omitempty"`
}

// SelfServiceBranding is how the Self Service window looks: every word,
// colour and image a person sees in it that is not their own data. Empty
// fields mean the built-in default, so a zero value is a valid, complete
// branding and an agent that never hears from a server still renders.
type SelfServiceBranding struct {
	WindowTitle string `json:"window_title,omitempty"`
	OrgName     string `json:"org_name,omitempty"`
	Welcome     string `json:"welcome,omitempty"`
	LogoDataURL string `json:"logo_data_url,omitempty"`

	HelpHeading string `json:"help_heading,omitempty"`
	HelpText    string `json:"help_text,omitempty"`
	HelpURL     string `json:"help_url,omitempty"`

	Theme      string `json:"theme,omitempty"` // "dark" | "light" | "system"
	Accent     string `json:"accent,omitempty"`
	Background string `json:"background,omitempty"`
	Sidebar    string `json:"sidebar,omitempty"`
	Surface    string `json:"surface,omitempty"`
	Text       string `json:"text,omitempty"`
	Font       string `json:"font,omitempty"`   // "system" | "segoe" | "serif" | "rounded" | "mono"
	Radius     *int   `json:"radius,omitempty"` // px; nil = default

	Pattern           string `json:"pattern,omitempty"`         // "waves" | "contours" | "dots" | "grid" | "none" | "image"
	PatternOpacity    *int   `json:"pattern_opacity,omitempty"` // 0-100; nil = default
	BackgroundDataURL string `json:"background_data_url,omitempty"`
	// How the background image sits in the window: "cover" (fill, the
	// default), "contain" (whole image), "tile" or "center" (actual size).
	BackgroundFit string `json:"background_fit,omitempty"`
	// Which part of the image stays in view when it is cropped or smaller
	// than the window: "center" (default), "top", "bottom", "left", "right".
	BackgroundPosition string `json:"background_position,omitempty"`
	// Gaussian blur on the image in px, 0-20; nil = none.
	BackgroundBlur *int `json:"background_blur,omitempty"`

	Tabs          []SelfServiceTab `json:"tabs,omitempty"` // order is display order
	DefaultTab    string           `json:"default_tab,omitempty"`
	ActivityEmpty string           `json:"activity_empty,omitempty"`
	HideCheckIn   bool             `json:"hide_check_in,omitempty"`
	HideBadges    bool             `json:"hide_badges,omitempty"`

	// CustomCSS is appended after everything else. It is the operator's
	// escape hatch for anything the fields above do not reach, and it is
	// CSS only: the window inserts it as text into a <style>, so it cannot
	// carry script.
	CustomCSS string `json:"custom_css,omitempty"`
}

// SelfServiceTab is one entry in the window's sidebar. The ID is from a
// fixed set (catalog, updates, history, activity, device); only the label,
// the position and whether it is shown are the operator's.
type SelfServiceTab struct {
	ID     string `json:"id"`
	Label  string `json:"label,omitempty"`
	Hidden bool   `json:"hidden,omitempty"`
}

// SelfServiceItem is one catalog entry as this device sees it.
type SelfServiceItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Icon        string `json:"icon"`
	Package     string `json:"package,omitempty"` // resolved for this device's OS
	Entitled    bool   `json:"entitled"`
	Pending     bool   `json:"pending"`     // a request is awaiting a decision
	CanRequest  bool   `json:"can_request"` // not entitled, but may ask
	Installed   bool   `json:"installed"`   // already present per installed_apps
}

// SelfServiceActivity is one thing mustra has done to this device.
type SelfServiceActivity struct {
	Kind      string `json:"kind"`
	Summary   string `json:"summary"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
	StartedAt string `json:"started_at"`
	By        string `json:"by,omitempty"`
}

type SelfServiceReply struct {
	// Telemetry answers action "telemetry_config": what this agent should
	// collect for the operator's monitoring stack (telemetry.go).
	Telemetry *TelemetryConfig `json:"telemetry,omitempty"`

	Deploy   *DeployJob            `json:"deploy,omitempty"`
	OK       bool                  `json:"ok"`
	Error    string                `json:"error,omitempty"`
	Hostname string                `json:"hostname,omitempty"`
	AgentID  string                `json:"agent_id,omitempty"`
	Items    []SelfServiceItem     `json:"items,omitempty"`
	Activity []SelfServiceActivity `json:"activity,omitempty"`
	// Install replies carry what to run — resolved server-side from the
	// catalog, never accepted from the local UI.
	Package string `json:"package,omitempty"`
	RunID   string `json:"run_id,omitempty"`
	Message string `json:"message,omitempty"`

	// LatestAgentVersion is the agent build this server is handing out, so
	// the Self Service window can tell someone their agent is behind. Agents
	// are not auto-updated: a fleet that silently replaces its own agent
	// binary is a fleet that can silently break, so the update is offered
	// rather than applied.
	LatestAgentVersion string `json:"latest_agent_version,omitempty"`
	// UpdateCommand is what the agent should run to update itself, built by
	// the server from its own recorded console URL. It is never accepted
	// from the local window — the same rule that keeps a package name
	// server-resolved.
	//
	// Only agents that predate signed updates read it. A current agent
	// ignores it entirely and applies Update instead, so a server-chosen
	// shell command is never the thing that replaces its binary.
	UpdateCommand string `json:"update_command,omitempty"`
	// Update is the signed update this endpoint may apply.
	Update *UpdateOffer `json:"update,omitempty"`

	// BrandingVersion is always set on a state reply ("" = the built-in
	// look); Branding only when it differs from what the agent said it had.
	BrandingVersion string               `json:"branding_version,omitempty"`
	Branding        *SelfServiceBranding `json:"branding,omitempty"`
}

// PatchListQuery is sent by an agent to the server (request/reply, agent as
// requester — the reverse direction of AgentCommand) right before it
// collects or applies patches, asking which repo scoping it should use.
// Empty request body; the agent ID comes from the subject itself (see
// internal/nats.PatchListQuery).
type PatchListQuery struct{}

// PatchListReply answers a PatchListQuery. An empty Repos means "no
// override configured for this agent — use the distro's natively
// configured repos," which is today's unchanged default behavior.
type PatchListReply struct {
	OSFamily string   `json:"os_family,omitempty"` // "apt" | "dnf"
	Repos    []string `json:"repos,omitempty"`     // apt: full sources.list-format lines; dnf: bare repo IDs
}

// Security posture: the endpoint's own protective controls, in one row.
//
// Firewall, disk encryption, antimalware and application control are the
// four things Enforce reports coverage on, and they are what the
// typed Enforce policies (internal/enforcekinds) hold in place. The sensor
// answers "what is the state right now" so coverage can be counted across
// the fleet without running a policy, and so a group can say "encrypted
// laptops" or "firewall off". It is published as a one-row list, like
// hardware, so targeting rules read its fields directly.
type SecurityPosture struct {
	FirewallEngine   string                 `json:"firewall_engine"` // windows-defender | ufw | firewalld | nftables | iptables | macos-alf | none | unknown
	FirewallEnabled  bool                   `json:"firewall_enabled"`
	FirewallProfiles []FirewallProfileState `json:"firewall_profiles,omitempty"`

	EncryptionEngine  string             `json:"encryption_engine"` // bitlocker | luks | filevault | none | unknown
	OSVolumeEncrypted bool               `json:"os_volume_encrypted"`
	Volumes           []VolumeEncryption `json:"volumes,omitempty"`

	AntivirusEngine            string `json:"antivirus_engine"` // defender | none | unknown
	AntivirusEnabled           bool   `json:"antivirus_enabled"`
	AntivirusRealtime          bool   `json:"antivirus_realtime"`
	AntivirusSignatureAgeHours int    `json:"antivirus_signature_age_hours"`
	AntivirusLastQuickScan     string `json:"antivirus_last_quick_scan,omitempty"`
	AntivirusTamperProtected   bool   `json:"antivirus_tamper_protected"`
	AntivirusCloudLevel        string `json:"antivirus_cloud_level,omitempty"` // off | basic | advanced

	AppControlEngine      string                 `json:"app_control_engine"` // applocker | none | unknown
	AppControlMode        string                 `json:"app_control_mode"`   // enforce | audit | off | mixed
	AppControlCollections []AppControlCollection `json:"app_control_collections,omitempty"`

	// RemoteShadow says whether RDS shadowing (the Jump menu's "Shadow
	// session") can work on a Windows endpoint. Absent on other platforms
	// and from agents before 0.57.44.
	RemoteShadow *RemoteShadowState `json:"remote_shadow,omitempty"`

	// RecoveryKeys are BitLocker recovery passwords read from the
	// endpoint. The server strips them from the snapshot and stores them
	// encrypted before anything else sees the row; they are never kept in
	// the sensor cache.
	RecoveryKeys []RecoveryKey `json:"recovery_keys,omitempty"`
	Errors       []string      `json:"errors,omitempty"`
}

// RemoteShadowState is what decides whether shadowing a Windows session
// can work: the shadow rule (the *Set rules for remote control of Remote
// Desktop Services user sessions* policy, or the RDP-Tcp default when no
// policy sets it), the *Remote Desktop - Shadow (TCP-In)* firewall rule,
// and the Remote Desktop service.
type RemoteShadowState struct {
	// Mode is off, control_with_consent, control_without_consent,
	// view_with_consent or view_without_consent.
	Mode string `json:"mode"`
	// Source is policy when Group Policy (or Enforce) sets the rule,
	// default when it is the RDP-Tcp default.
	Source string `json:"source"`
	// FirewallRule is whether the shadow firewall rule is enabled; it
	// matters only while the firewall is on.
	FirewallRule bool `json:"firewall_rule"`
	// Service is whether the Remote Desktop service (TermService) runs.
	Service bool `json:"service"`
	// Ready is whether a shadow request can reach the session; Reason
	// says why not.
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

type FirewallProfileState struct {
	Name            string `json:"name"`
	Enabled         bool   `json:"enabled"`
	DefaultInbound  string `json:"default_inbound,omitempty"`
	DefaultOutbound string `json:"default_outbound,omitempty"`
	LogBlocked      bool   `json:"log_blocked"`
}

type VolumeEncryption struct {
	Mount          string   `json:"mount"`
	Type           string   `json:"type,omitempty"` // os | data
	Status         string   `json:"status"`         // FullyEncrypted | EncryptionInProgress | FullyDecrypted | …
	ProtectionOn   bool     `json:"protection_on"`
	Method         string   `json:"method,omitempty"`
	Percent        int      `json:"percent"`
	Protectors     []string `json:"protectors,omitempty"`
	RecoveryKeyIDs []string `json:"recovery_key_ids,omitempty"`
}

type AppControlCollection struct {
	Type  string `json:"type"` // Exe | Msi | Script | Dll | Appx
	Mode  string `json:"mode"` // Enabled | AuditOnly | NotConfigured
	Rules int    `json:"rules"`
}

type RecoveryKey struct {
	Mount    string `json:"mount"`
	KeyID    string `json:"key_id"`
	Password string `json:"password"`
}

// Recorder events: the endpoint's other event sources, beyond process and
// file — registry writes, network connections, DNS lookups, logons.
//
// One shape for four kinds rather than four pipelines: they share the
// flush, the collapse, the cap, the storage and the Signals evaluator, and
// the cost of a few unused fields per row is nothing next to a second
// consumer to keep in step. Kind says which fields are meaningful; Summary
// is the one line a console row shows without knowing the kind.
type RecorderEvent struct {
	Kind    string    `json:"kind"` // registry | network | dns | logon
	At      time.Time `json:"at"`
	Count   int       `json:"count,omitempty"`
	PID     int32     `json:"pid,omitempty"`
	Process string    `json:"process,omitempty"`
	User    string    `json:"user,omitempty"`
	// Op: registry set|create|delete; network connect|listen; dns query;
	// logon success|failure|logoff.
	Op      string `json:"op,omitempty"`
	Summary string `json:"summary"`

	// registry
	Key       string `json:"key,omitempty"`
	ValueName string `json:"value_name,omitempty"`
	Data      string `json:"data,omitempty"`
	// network
	Protocol   string `json:"protocol,omitempty"` // tcp | udp
	LocalIP    string `json:"local_ip,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	// dns
	Query   string `json:"query,omitempty"`
	Answers string `json:"answers,omitempty"`
	// logon
	Domain    string `json:"domain,omitempty"`
	Source    string `json:"source,omitempty"` // where the logon came from (IP or host)
	LogonType string `json:"logon_type,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// RecorderBatch is one flush of recorder events. Sources names the
// mechanism per kind ("netpoll", "journal", "winevent", "sysmon",
// "regpoll", "dnscache", "none"), because what an empty feed proves
// depends on how it was produced.
type RecorderBatch struct {
	AgentID    string          `json:"agent_id"`
	Events     []RecorderEvent `json:"events"`
	Suppressed int             `json:"suppressed,omitempty"`
	// SuppressedByKind splits Suppressed by event kind. An older agent
	// sends only the total, which the server books as network events.
	SuppressedByKind map[string]int    `json:"suppressed_by_kind,omitempty"`
	Sources          map[string]string `json:"sources,omitempty"`
	Since            time.Time         `json:"since"`
	Until            time.Time         `json:"until"`
}

// CertJob is one step of renewing a certificate on an endpoint. cert_csr
// sends RequestID and Names and gets a CSR back (the key stays on the
// endpoint); cert_install sends the signed certificate, its chain, where it
// goes, how to reload the service, and the port to check it on.
type CertJob struct {
	RequestID  string   `json:"request_id"`
	Names      []string `json:"names,omitempty"`
	CertPath   string   `json:"cert_path,omitempty"`
	KeyPath    string   `json:"key_path,omitempty"` // empty: key and certificate share CertPath
	CertPEM    string   `json:"cert_pem,omitempty"`
	ChainPEM   string   `json:"chain_pem,omitempty"`
	ReloadCmd  string   `json:"reload_cmd,omitempty"`
	VerifyPort int      `json:"verify_port,omitempty"`
	// AD CS submission (cert_adcs_submit), sent to the Windows endpoint that
	// submits requests: the CSR another endpoint made, the CA's config
	// string (host\CA name) and the certificate template.
	CSRPEM   string `json:"csr_pem,omitempty"`
	CAConfig string `json:"ca_config,omitempty"`
	Template string `json:"template,omitempty"`
	// trust_root: Remove takes CertPEM (a root) out of the system trust
	// store instead of adding it.
	Remove bool `json:"remove,omitempty"`
	// Windows certificate store (CertPath Cert:\LocalMachine\My): bind the
	// installed certificate to an IIS site's https binding (IISSite, on
	// VerifyPort) or to Remote Desktop ("rdp"). FriendlyName marks it as
	// Mustra's, so the one it replaces can be found and removed.
	// An uploaded certificate (Cert Manager → New certificate → Upload):
	// its key comes with it instead of from cert_csr. KeyPEM for files;
	// for the Windows store, the whole thing as a PFX (base64) and its
	// one-time password.
	KeyPEM       string `json:"key_pem,omitempty"`
	PFXBase64    string `json:"pfx_base64,omitempty"`
	PFXPassword  string `json:"pfx_password,omitempty"`
	WinBind      string `json:"win_bind,omitempty"`
	IISSite      string `json:"iis_site,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	// cert_adcs_revoke: the serial (hex) to revoke at CAConfig, and the
	// RFC 5280 reason code.
	Serial string `json:"serial,omitempty"`
	Reason int    `json:"reason,omitempty"`
}

// BackupGuest is one virtual machine or container on a Proxmox VE node and
// what its backup storages hold for it (the backups sensor).
type BackupGuest struct {
	VMID          int      `json:"vmid"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`   // qemu, lxc
	Status        string   `json:"status"` // running, stopped
	Node          string   `json:"node"`
	MACs          []string `json:"macs,omitempty"`
	Covered       bool     `json:"covered"`               // an enabled backup job includes it
	Jobs          []string `json:"jobs,omitempty"`        // ids of the jobs that include it
	LastBackup    string   `json:"last_backup,omitempty"` // RFC 3339
	LastStorage   string   `json:"last_storage,omitempty"`
	LastSizeBytes int64    `json:"last_size_bytes,omitempty"`
	LastVerified  string   `json:"last_verified,omitempty"` // ok, failed, or empty when never verified
	Backups       int      `json:"backups"`
	Storages      []string `json:"storages,omitempty"`
	LastJobStatus string   `json:"last_job_status,omitempty"` // the node's latest vzdump task: OK, WARNINGS, or its error
	LastJobEnd    string   `json:"last_job_end,omitempty"`
}

// DirectoryInfo is how an endpoint belongs to a directory (Active Directory,
// Entra ID, both, or neither) and who is signed in to it, with what the
// directory says about each of them.
type DirectoryInfo struct {
	Joined                 bool            `json:"joined"`
	Kind                   string          `json:"kind"` // ad, entra, hybrid, workgroup
	Domain                 string          `json:"domain,omitempty"`
	Site                   string          `json:"site,omitempty"`
	DC                     string          `json:"dc,omitempty"`
	ComputerDN             string          `json:"computer_dn,omitempty"`
	ComputerOU             string          `json:"computer_ou,omitempty"`
	ComputerGroups         []string        `json:"computer_groups,omitempty"` // AD groups the computer account is in
	MachinePasswordLastSet string          `json:"machine_password_last_set,omitempty"`
	EntraTenant            string          `json:"entra_tenant,omitempty"`
	EntraDeviceID          string          `json:"entra_device_id,omitempty"`
	Users                  []DirectoryUser `json:"users"`
}

// DirectoryUser is one signed-in account. Source says where the details
// came from: "ad" (the domain), "local" (the machine's own accounts).
type DirectoryUser struct {
	Name                 string   `json:"name"`
	Source               string   `json:"source,omitempty"`
	UPN                  string   `json:"upn,omitempty"`
	DisplayName          string   `json:"display_name,omitempty"`
	Email                string   `json:"email,omitempty"`
	Title                string   `json:"title,omitempty"`
	Department           string   `json:"department,omitempty"`
	Manager              string   `json:"manager,omitempty"`
	DN                   string   `json:"dn,omitempty"`
	SID                  string   `json:"sid,omitempty"`
	Groups               []string `json:"groups,omitempty"`
	Enabled              *bool    `json:"enabled,omitempty"`
	Locked               bool     `json:"locked,omitempty"`
	PasswordLastSet      string   `json:"password_last_set,omitempty"`
	PasswordNeverExpires bool     `json:"password_never_expires,omitempty"`
	LastLogon            string   `json:"last_logon,omitempty"`
}

// SecretWriteJob puts a renewed application credential (a client secret,
// a certificate and key, a service-account key) where an application reads
// it: the whole of Path, or only the value of Key on its line in Path
// (KEY=value, key = value, key: value). ReloadCmd runs afterwards; if it
// fails the previous file is put back.
type SecretWriteJob struct {
	Path      string `json:"path"`
	Key       string `json:"key,omitempty"`
	Content   string `json:"content"`
	ReloadCmd string `json:"reload_cmd,omitempty"`
}

// JITAccountJob is a temporary local administrator for one remote session:
// created by jit_create just before the session opens, removed by
// jit_remove when it ends. The server mints the name and the secret and
// hands them to the remote desktop provider, so nobody types or sees them.
//
// ExpiresAt is the agent's own deadline: past it the agent removes the
// account by itself, whether or not the server ever asks, so an account
// outlives a lost server or a lost connection by minutes, not forever.
// Agents before 0.57.40 answer "unknown command".
type JITAccountJob struct {
	Username string `json:"username"`
	// Password signs in over RDP and VNC; SSH signs in with AuthorizedKey
	// instead, which a server that refuses passwords still accepts.
	Password      string    `json:"password,omitempty"`
	AuthorizedKey string    `json:"authorized_key,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	SessionID     string    `json:"session_id,omitempty"`
}
