package server

import "github.com/mustra-dev/mustra/internal/proto"

// A small starter policy, written here rather than taken from anyone
// else's benchmark so it can ship under this project's own licence.
//
// It is deliberately short. The point is not to be a complete CIS
// benchmark — that work is done far better by the published policies, and
// mustra reads those directly. This is enough to make the module useful
// out of the box and to show the rule syntax by example.
var starterLinuxPolicy = []proto.ComplianceCheck{
	{
		ID: "ssh-root-login", Severity: "high",
		Title:       "SSH does not permit direct root login",
		Rationale:   "Root logins over SSH remove the audit trail that sudo provides and make brute force worth attempting.",
		Remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config, then reload sshd.",
		Condition:   "any",
		Rules: []string{
			"not f:/etc/ssh/sshd_config",
			`f:/etc/ssh/sshd_config -> r:^\s*PermitRootLogin\s+(no|prohibit-password)`,
		},
	},
	{
		ID: "ssh-password-auth", Severity: "medium",
		Title:       "SSH password authentication is disabled",
		Rationale:   "Key-only authentication removes the entire class of guessable-credential attacks.",
		Remediation: "Set PasswordAuthentication no in /etc/ssh/sshd_config, then reload sshd.",
		Condition:   "any",
		Rules: []string{
			"not f:/etc/ssh/sshd_config",
			`f:/etc/ssh/sshd_config -> r:^\s*PasswordAuthentication\s+no`,
		},
	},
	{
		ID: "passwd-no-empty", Severity: "critical",
		Title:       "No account has an empty password",
		Rationale:   "An empty password field lets anyone authenticate as that account.",
		Remediation: "Lock or set a password on any account whose shadow entry has an empty hash.",
		Rules:       []string{`not f:/etc/shadow -> r:^[\w@.-]+::`},
	},
	{
		ID: "passwd-no-plus", Severity: "medium",
		Title:       "No legacy NIS entries in /etc/passwd",
		Rationale:   "A leading + entry is a legacy NIS directive that can widen who may log in.",
		Remediation: "Remove any line beginning with + from /etc/passwd.",
		Rules:       []string{`not f:/etc/passwd -> r:^\+:`},
	},
	{
		ID: "shadow-perms", Severity: "high",
		Title:       "/etc/shadow is not world-readable",
		Rationale:   "World-readable password hashes can be taken away and cracked offline at leisure.",
		Remediation: "chmod 0640 /etc/shadow and chown root:shadow /etc/shadow.",
		Rules:       []string{`c:stat -c %a /etc/shadow -> r:^(0|6|4)[04]0$`},
	},
	{
		ID: "ip-forward-off", Severity: "low",
		Title:       "IP forwarding is disabled",
		Rationale:   "A host that forwards packets can be used to reach networks it bridges. Expected to fail on routers and container hosts.",
		Remediation: "Set net.ipv4.ip_forward=0 in /etc/sysctl.d and apply, unless this host is meant to route.",
		Rules:       []string{`c:sysctl net.ipv4.ip_forward -> r:=\s*0$`},
	},
	{
		ID: "auditd-or-journald", Severity: "low",
		Title:       "A system audit or logging daemon is running",
		Rationale:   "Without one, nothing that happens on this host is recoverable after the fact.",
		Remediation: "Ensure auditd or systemd-journald is enabled and running.",
		Condition:   "any",
		Rules:       []string{"p:auditd", "p:systemd-journal", "p:rsyslogd"},
	},
	{
		ID: "cron-perms", Severity: "medium",
		Title:       "/etc/crontab is not world-writable",
		Rationale:   "A world-writable crontab is a direct path to root on the next tick.",
		Remediation: "chmod 0600 /etc/crontab.",
		Condition:   "any",
		Rules: []string{
			"not f:/etc/crontab",
			`c:stat -c %a /etc/crontab -> r:^[0-7][0-7][0-5]$`,
		},
	},
	{
		ID: "unattended-upgrades", Severity: "medium",
		Title:       "Automatic security updates are configured",
		Rationale:   "Most compromises use a vulnerability with a patch already available.",
		Remediation: "Install unattended-upgrades and enable the security origin.",
		Condition:   "any",
		Rules: []string{
			"f:/etc/apt/apt.conf.d/20auto-upgrades -> r:Unattended-Upgrade\"\\s+\"1\"",
			"f:/etc/dnf/automatic.conf -> r:apply_updates\\s*=\\s*yes",
		},
	},
	{
		ID: "sudo-logfile", Severity: "low",
		Title:       "sudo is present and configured",
		Rationale:   "Privilege escalation through sudo is auditable; direct root use is not.",
		Remediation: "Install sudo and grant administrators access through it rather than the root account.",
		Rules:       []string{"f:/etc/sudoers"},
	},
}

// starterControls maps the starter checks to NIST SP 800-53 rev. 5 and
// SP 800-171 rev. 2. Where a CIS benchmark has the same check, the mapping
// is the one Wazuh's CIS content gives it (Debian 12, or Ubuntu 24.04 for
// IP forwarding), so the starter policy and an imported benchmark report
// the same control for the same setting. The last three have no CIS
// equivalent there and are mustra's own reading: automatic security
// updates are flaw remediation (SI-2, 3.14.1); a "+" NIS entry in
// /etc/passwd admits accounts nobody manages here (AC-2, IA-2; 3.5.1,
// 3.5.2).
var starterControls = map[string]map[string][]string{
	"ssh-root-login":      {"nist_800_53": {"AC-6"}, "nist_800_171": {"3.1.5", "3.1.6", "3.1.7", "3.13.3"}},
	"ssh-password-auth":   {"nist_800_53": {"AC-2", "IA-2", "IA-5", "AC-11", "AC-7", "AU-6"}, "nist_800_171": {"3.5.7"}},
	"passwd-no-empty":     {"nist_800_53": {"AC-2", "IA-2", "IA-5", "AC-11", "AC-7", "AU-6"}, "nist_800_171": {"3.5.7"}},
	"passwd-no-plus":      {"nist_800_53": {"AC-2", "IA-2"}, "nist_800_171": {"3.5.1", "3.5.2"}},
	"shadow-perms":        {"nist_800_53": {"AC-5", "AC-6"}, "nist_800_171": {"3.1.1", "3.1.2", "3.1.5", "3.1.3", "3.8.2"}},
	"ip-forward-off":      {"nist_800_53": {"CM-2", "CM-3", "CM-6", "CM-7"}, "nist_800_171": {"3.4.7", "3.4.8", "3.13.6"}},
	"auditd-or-journald":  {"nist_800_53": {"AU-7"}, "nist_800_171": {"3.3.1"}},
	"cron-perms":          {"nist_800_53": {"AC-5", "AC-6"}, "nist_800_171": {"3.1.1", "3.1.2", "3.1.5", "3.1.3", "3.8.2"}},
	"unattended-upgrades": {"nist_800_53": {"SI-2"}, "nist_800_171": {"3.14.1"}},
	"sudo-logfile":        {"nist_800_53": {"AU-3", "AU-7"}, "nist_800_171": {"3.3.1"}},
}

func init() {
	for i := range starterLinuxPolicy {
		starterLinuxPolicy[i].Controls = starterControls[starterLinuxPolicy[i].ID]
	}
}
