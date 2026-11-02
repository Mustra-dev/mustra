package server

// Watchlist templates: the paths a standard's file-integrity clause is
// usually read to mean, per platform. A template is a starting point the
// operator edits, not a certification; the agent skips any path the
// endpoint does not have, so one list can carry every platform's paths.
type watchTemplate struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Paths        []string `json:"paths"`
	RegistryKeys []string `json:"registry_keys"`
}

var linuxAuth = []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/pam.d", "/etc/security", "/etc/ssh", "/root/.ssh", "/etc/login.defs"}
var linuxSched = []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/etc/systemd/system", "/etc/init.d", "/etc/rc.local"}
var linuxNet = []string{"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/hosts.allow", "/etc/hosts.deny", "/etc/sysctl.conf", "/etc/sysctl.d", "/etc/iptables", "/etc/nftables.conf", "/etc/ufw"}
var linuxAudit = []string{"/etc/audit", "/etc/rsyslog.conf", "/etc/rsyslog.d", "/etc/logrotate.conf", "/etc/logrotate.d", "/var/log/audit"}
var linuxBoot = []string{"/boot/grub", "/boot/grub2", "/etc/default/grub", "/etc/modprobe.d", "/etc/ld.so.preload", "/etc/ld.so.conf.d"}
var linuxPkgs = []string{"/etc/apt/sources.list", "/etc/apt/sources.list.d", "/etc/apt/trusted.gpg.d", "/etc/yum.repos.d", "/usr/local/bin", "/usr/local/sbin"}
var darwinCore = []string{"/etc/sudoers", "/etc/sudoers.d", "/etc/hosts", "/etc/ssh", "/etc/pam.d", "/Library/LaunchDaemons", "/Library/LaunchAgents", "/etc/periodic", "/private/etc/authorization"}
var winCore = []string{`C:\Windows\System32\drivers\etc`, `C:\Windows\System32\Tasks`, `C:\Windows\System32\GroupPolicy`, `C:\Windows\System32\config`, `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`}
var winRegPersist = []string{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, `HKLM\SYSTEM\CurrentControlSet\Services`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`}
var winRegPolicy = []string{`HKLM\SOFTWARE\Policies\Microsoft\Windows\System`, `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders`, `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`}
var winRegAudit = []string{`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security`, `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog`, `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit`}

func cat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

var watchTemplates = []watchTemplate{
	{ID: "pci-dss", Name: "PCI-DSS", Description: "Requirement 10.5 / 11.5: critical system files, configuration and content files, and log files, on every platform.",
		Paths: cat(linuxAuth, linuxSched, linuxNet, linuxAudit, linuxBoot, darwinCore, winCore), RegistryKeys: cat(winRegPersist, winRegPolicy, winRegAudit)},
	{ID: "cis-controls", Name: "CIS Controls", Description: "Controls 3, 4 and 8: authentication, secure configuration, scheduled execution and audit logging.",
		Paths: cat(linuxAuth, linuxSched, linuxNet, linuxAudit, linuxPkgs, darwinCore, winCore), RegistryKeys: cat(winRegPersist, winRegPolicy, winRegAudit)},
	{ID: "hipaa", Name: "HIPAA", Description: "§164.312(c): integrity controls over authentication, access configuration and audit trails.",
		Paths: cat(linuxAuth, linuxAudit, linuxNet, darwinCore, winCore), RegistryKeys: cat(winRegPolicy, winRegAudit)},
	{ID: "sox", Name: "SOX", Description: "Change control over privileged access, scheduled jobs and logging on in-scope systems.",
		Paths: cat(linuxAuth, linuxSched, linuxAudit, darwinCore, winCore), RegistryKeys: cat(winRegPersist, winRegAudit)},
	{ID: "nerc-cip", Name: "NERC-CIP", Description: "CIP-010: configuration change monitoring — boot, kernel modules, network, services and accounts.",
		Paths: cat(linuxAuth, linuxSched, linuxNet, linuxBoot, linuxPkgs, darwinCore, winCore), RegistryKeys: cat(winRegPersist, winRegPolicy)},
	{ID: "exchange", Name: "Microsoft Exchange", Description: "Exchange Server web roots and transport configuration, where webshells and transport agents land.",
		Paths:        []string{`C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth`, `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\ecp\auth`, `C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess`, `C:\Program Files\Microsoft\Exchange Server\V15\Bin`, `C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Shared`, `C:\inetpub\wwwroot\aspnet_client`},
		RegistryKeys: []string{`HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\Setup`, `HKLM\SYSTEM\CurrentControlSet\Services\MSExchangeTransport`}},
	{ID: "persistence", Name: "Persistence (mustra)", Description: "Everywhere an attacker parks to survive a reboot, beyond the built-in set: startup folders, shells' rc files, kernel module and preload hooks.",
		Paths: cat([]string{"/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/root/.bashrc", "/root/.profile", "/etc/environment", "/etc/update-motd.d", "/usr/lib/systemd/system", "/etc/xdg/autostart"}, linuxBoot, []string{"/Library/StartupItems", "/Library/Preferences/com.apple.loginwindow.plist"}, winCore), RegistryKeys: winRegPersist},
}
