// Package enforcekinds turns a typed policy -- Windows Firewall, BitLocker,
// Defender, AppLocker -- into the rule-plus-fix settings the Enforce engine
// already runs. The engine never learns about the types: an editor fills a
// form, this package compiles it, and what reaches the endpoint is the same
// "check, fix, check again" setting a hand-written policy would carry.
//
// That is deliberate. Each of these is often its own engine; here
// they are four compilers over one engine, which keeps report mode, the
// give-up counter, the audit trail and the dry run identical across them.
package enforcekinds

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Kind names a typed policy.
type Kind string

const (
	KindCustom    Kind = ""
	KindFirewall  Kind = "windows_firewall"
	KindBitLocker Kind = "bitlocker"
	KindDefender  Kind = "defender"
	KindAppLocker Kind = "applocker"
)

// Info describes a kind for the editor.
type Info struct {
	Kind        Kind   `json:"kind"`
	Label       string `json:"label"`
	OS          string `json:"os"`
	Description string `json:"description"`
	Defaults    any    `json:"defaults"`
}

// Kinds lists every typed policy with its default configuration.
func Kinds() []Info {
	return []Info{
		{Kind: KindFirewall, Label: "Windows Firewall", OS: "windows", Description: "Profile state, default actions, dropped-packet logging and a managed rule set, applied to the local firewall policy.", Defaults: DefaultFirewall()},
		{Kind: KindBitLocker, Label: "BitLocker", OS: "windows", Description: "Full-volume encryption with a recovery password protector; recovery keys are escrowed to mustra by the security posture sensor.", Defaults: DefaultBitLocker()},
		{Kind: KindDefender, Label: "Microsoft Defender", OS: "windows", Description: "Real-time protection, cloud-delivered protection, PUA blocking, signature freshness and scheduled scans.", Defaults: DefaultDefender()},
		{Kind: KindAppLocker, Label: "AppLocker", OS: "windows", Description: "Application control: audit or enforce, default allow rules for Windows and Program Files, and your own path, publisher or hash rules.", Defaults: DefaultAppLocker()},
	}
}

// Valid reports whether a kind is one this package compiles.
func Valid(k Kind) bool {
	for _, i := range Kinds() {
		if i.Kind == k {
			return true
		}
	}
	return k == KindCustom
}

// Compile turns a kind's configuration into settings. Setting IDs are
// deterministic per kind and item, so an edited policy keeps its history
// for the settings that did not change.
func Compile(kind Kind, config json.RawMessage) ([]proto.EnforceSetting, error) {
	switch kind {
	case KindFirewall:
		var c FirewallConfig
		if err := decode(config, &c); err != nil {
			return nil, err
		}
		return compileFirewall(c)
	case KindBitLocker:
		var c BitLockerConfig
		if err := decode(config, &c); err != nil {
			return nil, err
		}
		return compileBitLocker(c)
	case KindDefender:
		var c DefenderConfig
		if err := decode(config, &c); err != nil {
			return nil, err
		}
		return compileDefender(c)
	case KindAppLocker:
		var c AppLockerConfig
		if err := decode(config, &c); err != nil {
			return nil, err
		}
		return compileAppLocker(c)
	}
	return nil, fmt.Errorf("unknown policy kind %q", kind)
}

func decode(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return fmt.Errorf("the policy has no configuration")
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return nil
}

// stableID derives a setting id from what the setting is about, so it
// survives re-saves and re-orders.
func stableID(kind Kind, parts ...string) string {
	h := sha1.Sum([]byte(string(kind) + "|" + strings.Join(parts, "|")))
	return "set-" + string(kind) + "-" + hex.EncodeToString(h[:6])
}

// psq quotes a string for a single-quoted PowerShell literal.
func psq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// ---------------------------------------------------------------- firewall

type FirewallProfile struct {
	Enabled         bool   `json:"enabled"`
	DefaultInbound  string `json:"default_inbound"`  // block | allow
	DefaultOutbound string `json:"default_outbound"` // allow | block
}

type FirewallRule struct {
	Name            string `json:"name"`
	Direction       string `json:"direction"` // in | out
	Action          string `json:"action"`    // allow | block
	Protocol        string `json:"protocol"`  // tcp | udp | any
	LocalPorts      string `json:"local_ports,omitempty"`
	RemoteAddresses string `json:"remote_addresses,omitempty"`
	Program         string `json:"program,omitempty"`
	Enabled         bool   `json:"enabled"`
}

type FirewallConfig struct {
	Profiles   map[string]FirewallProfile `json:"profiles"` // domain | private | public
	LogDropped bool                       `json:"log_dropped"`
	Rules      []FirewallRule             `json:"rules"`
}

func DefaultFirewall() FirewallConfig {
	p := FirewallProfile{Enabled: true, DefaultInbound: "block", DefaultOutbound: "allow"}
	return FirewallConfig{Profiles: map[string]FirewallProfile{"domain": p, "private": p, "public": p}, LogDropped: true, Rules: []FirewallRule{}}
}

var profileNames = map[string]string{"domain": "Domain", "private": "Private", "public": "Public"}

func compileFirewall(c FirewallConfig) ([]proto.EnforceSetting, error) {
	var out []proto.EnforceSetting
	keys := make([]string, 0, len(c.Profiles))
	for k := range c.Profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name, ok := profileNames[strings.ToLower(k)]
		if !ok {
			return nil, fmt.Errorf("unknown firewall profile %q (domain, private or public)", k)
		}
		p := c.Profiles[k]
		in, err := action(p.DefaultInbound, "block")
		if err != nil {
			return nil, fmt.Errorf("%s profile: %w", name, err)
		}
		outAct, err := action(p.DefaultOutbound, "allow")
		if err != nil {
			return nil, fmt.Errorf("%s profile: %w", name, err)
		}
		enabled := "True"
		if !p.Enabled {
			enabled = "False"
		}
		// NotConfigured is Windows' own default -- Block inbound, Allow
		// outbound -- so a profile that was never touched satisfies a policy
		// asking for exactly that; the fix still writes it explicitly.
		inMatch, outMatch := in, outAct
		if in == "Block" {
			inMatch = "(Block|NotConfigured)"
		}
		if outAct == "Allow" {
			outMatch = "(Allow|NotConfigured)"
		}
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindFirewall, "profile", name), Severity: "high",
			Name: fmt.Sprintf("Firewall: %s profile %s, inbound %s, outbound %s", name, map[string]string{"True": "on", "False": "off"}[enabled], strings.ToLower(in), strings.ToLower(outAct)),
			Rules: []string{
				fmt.Sprintf("c:(Get-NetFirewallProfile -Name %s).Enabled -> r:^%s$", name, enabled),
				fmt.Sprintf("c:(Get-NetFirewallProfile -Name %s).DefaultInboundAction -> r:^%s$", name, inMatch),
				fmt.Sprintf("c:(Get-NetFirewallProfile -Name %s).DefaultOutboundAction -> r:^%s$", name, outMatch),
			},
			RemediateWindows: fmt.Sprintf("Set-NetFirewallProfile -Name %s -Enabled %s -DefaultInboundAction %s -DefaultOutboundAction %s", name, enabled, in, outAct),
		})
	}
	if c.LogDropped {
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindFirewall, "logblocked"), Severity: "medium", Name: "Firewall: dropped packets are logged on every profile",
			Rules:            []string{"c:(Get-NetFirewallProfile -All | Where-Object LogBlocked -ne $true | Measure-Object).Count -> r:^0$"},
			RemediateWindows: "Set-NetFirewallProfile -All -LogBlocked True",
		})
	}
	seen := map[string]bool{}
	for i, r := range c.Rules {
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			return nil, fmt.Errorf("firewall rule %d needs a name", i+1)
		}
		if seen[strings.ToLower(r.Name)] {
			return nil, fmt.Errorf("two firewall rules are named %q", r.Name)
		}
		seen[strings.ToLower(r.Name)] = true
		dir := map[string]string{"in": "Inbound", "inbound": "Inbound", "out": "Outbound", "outbound": "Outbound"}[strings.ToLower(r.Direction)]
		if dir == "" {
			return nil, fmt.Errorf("rule %q: direction must be in or out", r.Name)
		}
		act, err := action(r.Action, "")
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		proto_ := map[string]string{"tcp": "TCP", "udp": "UDP", "any": "Any", "": "Any"}[strings.ToLower(r.Protocol)]
		if proto_ == "" {
			return nil, fmt.Errorf("rule %q: protocol must be tcp, udp or any", r.Name)
		}
		ports := strings.ReplaceAll(strings.TrimSpace(r.LocalPorts), " ", "")
		if ports == "" || proto_ == "Any" {
			ports = "Any"
		}
		if ports != "Any" {
			for _, p := range strings.Split(ports, ",") {
				if !validPort(p) {
					return nil, fmt.Errorf("rule %q: %q is not a port or port range", r.Name, p)
				}
			}
		}
		addrs := strings.ReplaceAll(strings.TrimSpace(r.RemoteAddresses), " ", "")
		if addrs == "" {
			addrs = "Any"
		}
		if addrs != "Any" {
			for _, a := range strings.Split(addrs, ",") {
				if !validAddress(a) {
					return nil, fmt.Errorf("rule %q: %q is not an IP address, CIDR or range", r.Name, a)
				}
			}
		}
		enabled := "True"
		if !r.Enabled {
			enabled = "False"
		}
		display := "mustra: " + r.Name
		// The check prints one line describing the rule as it exists, and
		// the matcher is the literal line the policy wants. A missing rule
		// prints "missing", so the drift detail says which it was.
		check := fmt.Sprintf("c:$r = Get-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue; if ($r) { $pf = $r | Get-NetFirewallPortFilter; $af = $r | Get-NetFirewallAddressFilter; \"$($r.Direction)/$($r.Action)/$($r.Enabled)/$($pf.Protocol)/$(($pf.LocalPort) -join ',')/$(($af.RemoteAddress) -join ',')\" } else { 'missing' } -> %s/%s/%s/%s/%s/%s",
			psq(display), dir, act, enabled, proto_, ports, addrs)
		fix := fmt.Sprintf("Remove-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName %s -Direction %s -Action %s -Protocol %s -Enabled %s -Profile Any",
			psq(display), psq(display), dir, act, proto_, enabled)
		if ports != "Any" {
			fix += " -LocalPort " + ports
		}
		if addrs != "Any" {
			fix += " -RemoteAddress " + addrs
		}
		if p := strings.TrimSpace(r.Program); p != "" {
			fix += " -Program " + psq(p)
		}
		fix += " | Out-Null"
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindFirewall, "rule", strings.ToLower(r.Name)), Severity: "medium",
			Name: "Firewall rule: " + r.Name, Rules: []string{check}, RemediateWindows: fix,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the firewall policy configures nothing: enable a profile, logging, or add a rule")
	}
	return out, nil
}

func action(v, def string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		if def == "" {
			return "", fmt.Errorf("action must be allow or block")
		}
		return strings.Title(def), nil
	case "allow":
		return "Allow", nil
	case "block":
		return "Block", nil
	}
	return "", fmt.Errorf("action must be allow or block, not %q", v)
}

func validPort(p string) bool {
	lo, hi, isRange := strings.Cut(p, "-")
	ok := func(s string) bool {
		n := 0
		if s == "" {
			return false
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
			if n > 65535 {
				return false
			}
		}
		return n >= 1
	}
	if isRange {
		return ok(lo) && ok(hi)
	}
	return ok(p)
}

// validAddress accepts what New-NetFirewallRule -RemoteAddress does:
// addresses, CIDRs, ranges, and the keywords. Kept permissive on the
// characters and strict on the shape, since a bad address fails at apply
// time on the endpoint with a clear message anyway.
func validAddress(a string) bool {
	switch strings.ToLower(a) {
	case "any", "localsubnet", "dns", "dhcp", "wins", "defaultgateway", "internet", "intranet", "playtodevice":
		return true
	}
	for _, c := range a {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':' || c == '/' || c == '-') {
			return false
		}
	}
	return strings.ContainsAny(a, ".:")
}

// --------------------------------------------------------------- bitlocker

type BitLockerConfig struct {
	Volumes         string `json:"volumes"`           // os | all
	Method          string `json:"method"`            // XtsAes256 | XtsAes128 | Aes256 | Aes128
	RequireTPM      bool   `json:"require_tpm"`       // refuse to encrypt without a TPM
	AllowWithoutTPM bool   `json:"allow_without_tpm"` // set the policy that permits a recovery-password-only OS volume
	Escrow          bool   `json:"escrow"`            // recovery passwords must be escrowed to mustra (report-only check)
}

func DefaultBitLocker() BitLockerConfig {
	return BitLockerConfig{Volumes: "os", Method: "XtsAes256", RequireTPM: true, Escrow: true}
}

func compileBitLocker(c BitLockerConfig) ([]proto.EnforceSetting, error) {
	method := strings.TrimSpace(c.Method)
	switch method {
	case "":
		method = "XtsAes256"
	case "XtsAes256", "XtsAes128", "Aes256", "Aes128":
	default:
		return nil, fmt.Errorf("encryption method must be XtsAes256, XtsAes128, Aes256 or Aes128")
	}
	if c.Volumes != "os" && c.Volumes != "all" && c.Volumes != "" {
		return nil, fmt.Errorf("volumes must be os or all")
	}
	if c.RequireTPM && c.AllowWithoutTPM {
		return nil, fmt.Errorf("choose either require a TPM or allow encryption without one")
	}
	protector := "-TpmProtector"
	tpmGate := "if (-not ((Get-Tpm -ErrorAction SilentlyContinue).TpmReady)) { throw 'no ready TPM on this machine and the policy requires one' }; "
	if c.AllowWithoutTPM {
		protector = "-RecoveryPasswordProtector"
		tpmGate = "$fve = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE'; New-Item -Path $fve -Force | Out-Null; Set-ItemProperty -Path $fve -Name UseAdvancedStartup -Value 1 -Type DWord; Set-ItemProperty -Path $fve -Name EnableBDEWithNoTPM -Value 1 -Type DWord; Set-ItemProperty -Path $fve -Name UseTPM -Value 2 -Type DWord; Set-ItemProperty -Path $fve -Name UseTPMPIN -Value 2 -Type DWord; Set-ItemProperty -Path $fve -Name UseTPMKey -Value 2 -Type DWord; Set-ItemProperty -Path $fve -Name UseTPMKeyPIN -Value 2 -Type DWord; "
	} else if !c.RequireTPM {
		tpmGate = "if (-not ((Get-Tpm -ErrorAction SilentlyContinue).TpmReady)) { throw 'no ready TPM; enable \"allow without TPM\" in the policy to use a recovery password instead' }; "
	}
	// The OS volume is enabled in one remediation and judged by two
	// settings: "protected" accepts encryption in progress, so a machine
	// that is busy encrypting is not a failure that burns attempts, and
	// "complete" is report-only and stays drifted until 100% -- success is
	// not claimed before the volume is actually encrypted.
	// A server without the BitLocker feature has no cmdlets at all; the
	// fix installs the feature first where Install-WindowsFeature exists
	// (a client edition has the cmdlets built in).
	osFix := "if (-not (Get-Command Enable-BitLocker -ErrorAction SilentlyContinue)) { if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) { Install-WindowsFeature BitLocker -IncludeManagementTools | Out-Null; Import-Module BitLocker -ErrorAction SilentlyContinue } else { throw 'the BitLocker cmdlets are not available on this machine' } }; " +
		tpmGate +
		"$v = Get-BitLockerVolume -MountPoint $env:SystemDrive; " +
		"if (($v.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword').Count -eq 0) { Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null }; " +
		"$v = Get-BitLockerVolume -MountPoint $env:SystemDrive; " +
		"if ($v.VolumeStatus -eq 'FullyDecrypted') { Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod " + method + " " + protector + " -SkipHardwareTest | Out-Null } " +
		"elseif ($v.ProtectionStatus -eq 'Off') { Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null }"
	out := []proto.EnforceSetting{
		{
			ID: stableID(KindBitLocker, "os-protected"), Severity: "critical",
			Name: "BitLocker: OS volume is encrypting or encrypted with a recovery password protector",
			Rules: []string{
				"c:(Get-BitLockerVolume -MountPoint $env:SystemDrive).VolumeStatus -> r:^(FullyEncrypted|EncryptionInProgress)$",
				"c:((Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword' | Measure-Object).Count -> r:^[1-9]",
			},
			RemediateWindows: osFix,
		},
		{
			ID: stableID(KindBitLocker, "os-complete"), Severity: "high",
			Name: "BitLocker: OS volume encryption is complete and protection is on",
			Rules: []string{
				"c:(Get-BitLockerVolume -MountPoint $env:SystemDrive).VolumeStatus -> r:^FullyEncrypted$",
				"c:(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -> r:^On$",
			},
		},
		{
			ID: stableID(KindBitLocker, "os-method", method), Severity: "medium",
			Name:  "BitLocker: OS volume uses " + method,
			Rules: []string{"c:(Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionMethod -> r:^" + method + "$"},
		},
	}
	if c.Volumes == "all" {
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindBitLocker, "data-protected"), Severity: "high",
			Name:  "BitLocker: every fixed data volume is protected and auto-unlocks",
			Rules: []string{"c:(Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'Data' -and $_.ProtectionStatus -ne 'On' } | Measure-Object).Count -> r:^0$"},
			RemediateWindows: "Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'Data' -and $_.ProtectionStatus -ne 'On' } | ForEach-Object { " +
				"if ($_.VolumeStatus -eq 'FullyDecrypted') { Enable-BitLocker -MountPoint $_.MountPoint -EncryptionMethod " + method + " -RecoveryPasswordProtector | Out-Null; Enable-BitLockerAutoUnlock -MountPoint $_.MountPoint | Out-Null } " +
				"else { Resume-BitLocker -MountPoint $_.MountPoint | Out-Null } }",
		})
	}
	if c.Escrow {
		// Escrow is done by the security posture sensor, not by a command:
		// the agent reads the recovery passwords and the server stores
		// them encrypted. This setting only reports whether there is a
		// password to escrow, which is the half the endpoint can know.
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindBitLocker, "escrow"), Severity: "high",
			Name:  "BitLocker: a recovery password exists to escrow",
			Rules: []string{"c:(Get-BitLockerVolume | ForEach-Object { $_.KeyProtector } | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' -and $_.RecoveryPassword } | Measure-Object).Count -> r:^[1-9]"},
		})
	}
	return out, nil
}

// ---------------------------------------------------------------- defender

type DefenderConfig struct {
	RealTime               bool   `json:"realtime"`
	CloudLevel             string `json:"cloud_level"` // off | basic | advanced
	PUA                    string `json:"pua"`         // off | audit | block
	SignatureMaxAgeHours   int    `json:"signature_max_age_hours"`
	DailyQuickScan         bool   `json:"daily_quick_scan"`
	NetworkProtection      bool   `json:"network_protection"`
	CheckTamperProtection  bool   `json:"check_tamper_protection"`
	ControlledFolderAccess bool   `json:"controlled_folder_access"`
}

func DefaultDefender() DefenderConfig {
	return DefenderConfig{RealTime: true, CloudLevel: "advanced", PUA: "block", SignatureMaxAgeHours: 48, DailyQuickScan: true, NetworkProtection: false, CheckTamperProtection: true}
}

func compileDefender(c DefenderConfig) ([]proto.EnforceSetting, error) {
	out := []proto.EnforceSetting{{
		ID: stableID(KindDefender, "service"), Severity: "critical", Name: "Defender: antimalware service is running",
		Rules:            []string{"c:(Get-MpComputerStatus).AMServiceEnabled -> r:^True$"},
		RemediateWindows: "Set-Service WinDefend -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service WinDefend",
	}}
	if c.RealTime {
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindDefender, "realtime"), Severity: "critical", Name: "Defender: real-time protection is on",
			Rules:            []string{"c:(Get-MpComputerStatus).RealTimeProtectionEnabled -> r:^True$"},
			RemediateWindows: "Set-MpPreference -DisableRealtimeMonitoring $false",
		})
	}
	switch strings.ToLower(c.CloudLevel) {
	case "", "off":
	case "basic", "advanced":
		level := map[string]string{"basic": "1", "advanced": "2"}[strings.ToLower(c.CloudLevel)]
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindDefender, "cloud", level), Severity: "high", Name: "Defender: cloud-delivered protection is " + strings.ToLower(c.CloudLevel),
			Rules:            []string{"c:(Get-MpPreference).MAPSReporting -> r:^" + level + "$"},
			RemediateWindows: "Set-MpPreference -MAPSReporting " + strings.Title(strings.ToLower(c.CloudLevel)) + " -SubmitSamplesConsent SendSafeSamples",
		})
	default:
		return nil, fmt.Errorf("cloud level must be off, basic or advanced")
	}
	switch strings.ToLower(c.PUA) {
	case "", "off":
	case "audit", "block":
		val := map[string]string{"block": "1", "audit": "2"}[strings.ToLower(c.PUA)]
		mode := map[string]string{"block": "Enabled", "audit": "AuditMode"}[strings.ToLower(c.PUA)]
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindDefender, "pua", val), Severity: "medium", Name: "Defender: potentially unwanted applications are " + map[string]string{"block": "blocked", "audit": "audited"}[strings.ToLower(c.PUA)],
			Rules:            []string{"c:(Get-MpPreference).PUAProtection -> r:^" + val + "$"},
			RemediateWindows: "Set-MpPreference -PUAProtection " + mode,
		})
	default:
		return nil, fmt.Errorf("PUA protection must be off, audit or block")
	}
	if c.SignatureMaxAgeHours > 0 {
		h := fmt.Sprint(c.SignatureMaxAgeHours)
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindDefender, "signatures", h), Severity: "high", Name: fmt.Sprintf("Defender: signatures are no older than %s hours", h),
			Rules:            []string{"c:(((Get-Date) - (Get-MpComputerStatus).AntivirusSignatureLastUpdated).TotalHours -le " + h + ") -> r:^True$"},
			RemediateWindows: "Update-MpSignature",
		})
	}
	if c.DailyQuickScan {
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindDefender, "quickscan"), Severity: "low", Name: "Defender: a quick scan runs every day",
			Rules:            []string{"c:(Get-MpPreference).ScanScheduleDay -> r:^0$", "c:(Get-MpPreference).ScanParameters -> r:^1$"},
			RemediateWindows: "Set-MpPreference -ScanScheduleDay Everyday -ScanParameters QuickScan",
		})
	}
	if c.NetworkProtection {
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindDefender, "netprot"), Severity: "medium", Name: "Defender: network protection is enabled",
			Rules:            []string{"c:(Get-MpPreference).EnableNetworkProtection -> r:^1$"},
			RemediateWindows: "Set-MpPreference -EnableNetworkProtection Enabled",
		})
	}
	if c.ControlledFolderAccess {
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindDefender, "cfa"), Severity: "medium", Name: "Defender: controlled folder access is enabled",
			Rules:            []string{"c:(Get-MpPreference).EnableControlledFolderAccess -> r:^1$"},
			RemediateWindows: "Set-MpPreference -EnableControlledFolderAccess Enabled",
		})
	}
	if c.CheckTamperProtection {
		// Tamper protection cannot be switched on from PowerShell by
		// design, so this is report-only: drift here means "somebody has
		// to do it in the Security Center or Intune".
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindDefender, "tamper"), Severity: "high", Name: "Defender: tamper protection is on (report only)",
			Rules: []string{"c:(Get-MpComputerStatus).IsTamperProtected -> r:^True$"},
		})
	}
	return out, nil
}

// --------------------------------------------------------------- applocker

type AppLockerRule struct {
	Type        string `json:"type"`   // path | publisher | hash
	Action      string `json:"action"` // allow | deny
	Value       string `json:"value"`  // path: %PROGRAMFILES%\App\*; publisher: "O=..., L=..., C=US|Product|Binary"; hash: "SHA256hex|file.exe|length"
	Description string `json:"description,omitempty"`
	UserOrGroup string `json:"user_or_group,omitempty"` // SID; default S-1-1-0 Everyone
	Collection  string `json:"collection,omitempty"`    // exe (default) | msi | script | dll | appx
}

type AppLockerConfig struct {
	Mode         string          `json:"mode"`          // audit | enforce | off
	Collections  []string        `json:"collections"`   // exe, msi, script, dll, appx
	DefaultRules bool            `json:"default_rules"` // allow Windows, Program Files, and Administrators everything
	Rules        []AppLockerRule `json:"rules"`
}

func DefaultAppLocker() AppLockerConfig {
	return AppLockerConfig{Mode: "audit", Collections: []string{"exe", "msi", "script"}, DefaultRules: true, Rules: []AppLockerRule{}}
}

var collectionTypes = map[string]string{"exe": "Exe", "msi": "Msi", "script": "Script", "dll": "Dll", "appx": "Appx"}

func compileAppLocker(c AppLockerConfig) ([]proto.EnforceSetting, error) {
	mode := map[string]string{"audit": "AuditOnly", "enforce": "Enabled", "off": "NotConfigured", "": "AuditOnly"}[strings.ToLower(c.Mode)]
	if mode == "" {
		return nil, fmt.Errorf("mode must be audit, enforce or off")
	}
	if len(c.Collections) == 0 {
		return nil, fmt.Errorf("choose at least one rule collection (exe, msi, script, dll, appx)")
	}
	xml, err := AppLockerXML(c)
	if err != nil {
		return nil, err
	}
	out := []proto.EnforceSetting{{
		ID: stableID(KindAppLocker, "service"), Severity: "high", Name: "AppLocker: Application Identity service is automatic and running",
		Rules:            []string{"c:(Get-Service AppIDSvc).Status -> r:^Running$", "c:(Get-Service AppIDSvc).StartType -> r:^Automatic"},
		RemediateWindows: "sc.exe config appidsvc start= auto | Out-Null; Start-Service AppIDSvc",
	}}
	// One setting per collection checks the enforcement mode and that our
	// rules are present; one remediation writes the whole policy, since
	// Set-AppLockerPolicy replaces the local policy as a unit.
	fix := "$dir = Join-Path $env:ProgramData 'mustra'; New-Item -ItemType Directory -Path $dir -Force | Out-Null; $path = Join-Path $dir 'applocker.xml'; " +
		"[IO.File]::WriteAllText($path, @'\n" + xml + "\n'@); Set-AppLockerPolicy -XmlPolicy $path"
	ruleCount := map[string]int{}
	for _, r := range c.Rules {
		col := strings.ToLower(r.Collection)
		if col == "" {
			col = "exe"
		}
		ruleCount[col]++
	}
	for _, col := range c.Collections {
		typ, ok := collectionTypes[strings.ToLower(col)]
		if !ok {
			return nil, fmt.Errorf("unknown rule collection %q", col)
		}
		n := ruleCount[strings.ToLower(col)]
		if c.DefaultRules {
			n += defaultRuleCount(strings.ToLower(col))
		}
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindAppLocker, "collection", typ, mode), Severity: "high",
			Name: fmt.Sprintf("AppLocker: %s rules are %s with %d managed rule(s)", typ, map[string]string{"AuditOnly": "audited", "Enabled": "enforced", "NotConfigured": "not configured"}[mode], n),
			Rules: []string{
				fmt.Sprintf("c:$p = [xml](Get-AppLockerPolicy -Local -Xml); $c = $p.AppLockerPolicy.RuleCollection | Where-Object Type -eq '%s'; if ($c) { $c.EnforcementMode } else { 'absent' } -> r:^%s$", typ, mode),
				fmt.Sprintf("c:$p = [xml](Get-AppLockerPolicy -Local -Xml); $c = $p.AppLockerPolicy.RuleCollection | Where-Object Type -eq '%s'; if ($c) { ($c.ChildNodes | Where-Object { $_.Name -like 'mustra:*' } | Measure-Object).Count } else { 0 } -> r:^%d$", typ, n),
			},
			RemediateWindows: fix,
		})
	}
	return out, nil
}

func defaultRuleCount(col string) int {
	switch col {
	case "exe", "script":
		return 3
	case "msi", "dll":
		return 3
	case "appx":
		return 1
	}
	return 0
}

// AppLockerXML renders the policy Set-AppLockerPolicy consumes. Rule ids
// are derived from the rule text so a re-save produces the same document.
func AppLockerXML(c AppLockerConfig) (string, error) {
	mode := map[string]string{"audit": "AuditOnly", "enforce": "Enabled", "off": "NotConfigured", "": "AuditOnly"}[strings.ToLower(c.Mode)]
	var b strings.Builder
	b.WriteString(`<AppLockerPolicy Version="1">`)
	byCol := map[string][]AppLockerRule{}
	for _, r := range c.Rules {
		col := strings.ToLower(r.Collection)
		if col == "" {
			col = "exe"
		}
		byCol[col] = append(byCol[col], r)
	}
	for _, col := range c.Collections {
		typ, ok := collectionTypes[strings.ToLower(col)]
		if !ok {
			return "", fmt.Errorf("unknown rule collection %q", col)
		}
		fmt.Fprintf(&b, `<RuleCollection Type="%s" EnforcementMode="%s">`, typ, mode)
		if c.DefaultRules {
			for _, r := range defaultRules(strings.ToLower(col)) {
				b.WriteString(r)
			}
		}
		for i, r := range byCol[strings.ToLower(col)] {
			x, err := ruleXML(typ, r, i)
			if err != nil {
				return "", err
			}
			b.WriteString(x)
		}
		b.WriteString(`</RuleCollection>`)
	}
	b.WriteString(`</AppLockerPolicy>`)
	return b.String(), nil
}

func guid(parts ...string) string {
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	x := hex.EncodeToString(h[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", x[0:8], x[8:12], x[12:16], x[16:20], x[20:32])
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

func pathRule(id, name, desc, sid, action, path string) string {
	return fmt.Sprintf(`<FilePathRule Id="%s" Name="%s" Description="%s" UserOrGroupSid="%s" Action="%s"><Conditions><FilePathCondition Path="%s"/></Conditions></FilePathRule>`,
		id, xmlEscape(name), xmlEscape(desc), sid, action, xmlEscape(path))
}

// defaultRules mirror the "create default rules" set the AppLocker MMC
// offers: everything under Windows and Program Files for everyone, and
// everything for local administrators. Without them, enforcing a
// collection locks the machine.
func defaultRules(col string) []string {
	const everyone, admins = "S-1-1-0", "S-1-5-32-544"
	switch col {
	case "exe", "script":
		return []string{
			pathRule(guid("default", col, "programfiles"), "mustra: default allow Program Files", "Default rule", everyone, "Allow", `%PROGRAMFILES%\*`),
			pathRule(guid("default", col, "windows"), "mustra: default allow Windows", "Default rule", everyone, "Allow", `%WINDIR%\*`),
			pathRule(guid("default", col, "admins"), "mustra: default allow Administrators everything", "Default rule", admins, "Allow", `*`),
		}
	case "msi":
		return []string{
			pathRule(guid("default", col, "installer"), "mustra: default allow Windows Installer files in Installer", "Default rule", everyone, "Allow", `%WINDIR%\Installer\*`),
			pathRule(guid("default", col, "signed"), "mustra: default allow digitally signed Windows Installer files", "Default rule", everyone, "Allow", `*.msi`),
			pathRule(guid("default", col, "admins"), "mustra: default allow Administrators everything", "Default rule", admins, "Allow", `*`),
		}
	case "dll":
		return []string{
			pathRule(guid("default", col, "programfiles"), "mustra: default allow Program Files", "Default rule", everyone, "Allow", `%PROGRAMFILES%\*`),
			pathRule(guid("default", col, "windows"), "mustra: default allow Windows", "Default rule", everyone, "Allow", `%WINDIR%\*`),
			pathRule(guid("default", col, "admins"), "mustra: default allow Administrators everything", "Default rule", admins, "Allow", `*`),
		}
	case "appx":
		return []string{fmt.Sprintf(`<FilePublisherRule Id="%s" Name="mustra: default allow all signed packaged apps" Description="Default rule" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>`, guid("default", col, "signed"))}
	}
	return nil
}

func ruleXML(typ string, r AppLockerRule, i int) (string, error) {
	act := map[string]string{"allow": "Allow", "deny": "Deny", "": "Allow"}[strings.ToLower(r.Action)]
	if act == "" {
		return "", fmt.Errorf("AppLocker rule %d: action must be allow or deny", i+1)
	}
	sid := strings.TrimSpace(r.UserOrGroup)
	if sid == "" {
		sid = "S-1-1-0"
	}
	if !strings.HasPrefix(sid, "S-1-") {
		return "", fmt.Errorf("AppLocker rule %d: user or group must be a SID (S-1-…)", i+1)
	}
	value := strings.TrimSpace(r.Value)
	if value == "" {
		return "", fmt.Errorf("AppLocker rule %d needs a value", i+1)
	}
	name := "mustra: " + strings.TrimSpace(r.Description)
	if strings.TrimSpace(r.Description) == "" {
		name = "mustra: " + strings.ToLower(r.Type) + " " + act + " " + value
	}
	id := guid("rule", typ, strings.ToLower(r.Type), act, sid, value)
	switch strings.ToLower(r.Type) {
	case "path":
		return pathRule(id, name, r.Description, sid, act, value), nil
	case "publisher":
		parts := strings.SplitN(value, "|", 3)
		for len(parts) < 3 {
			parts = append(parts, "*")
		}
		return fmt.Sprintf(`<FilePublisherRule Id="%s" Name="%s" Description="%s" UserOrGroupSid="%s" Action="%s"><Conditions><FilePublisherCondition PublisherName="%s" ProductName="%s" BinaryName="%s"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>`,
			id, xmlEscape(name), xmlEscape(r.Description), sid, act, xmlEscape(strings.TrimSpace(parts[0])), xmlEscape(strings.TrimSpace(parts[1])), xmlEscape(strings.TrimSpace(parts[2]))), nil
	case "hash":
		parts := strings.SplitN(value, "|", 3)
		hash := strings.ToUpper(strings.TrimPrefix(strings.TrimSpace(parts[0]), "0x"))
		if len(hash) != 64 {
			return "", fmt.Errorf("AppLocker rule %d: a hash rule needs a SHA256 (64 hex characters)", i+1)
		}
		file, length := "file", "0"
		if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
			file = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 && strings.TrimSpace(parts[2]) != "" {
			length = strings.TrimSpace(parts[2])
		}
		return fmt.Sprintf(`<FileHashRule Id="%s" Name="%s" Description="%s" UserOrGroupSid="%s" Action="%s"><Conditions><FileHashCondition><FileHash Type="SHA256" Data="0x%s" SourceFileName="%s" SourceFileLength="%s"/></FileHashCondition></Conditions></FileHashRule>`,
			id, xmlEscape(name), xmlEscape(r.Description), sid, act, hash, xmlEscape(file), length), nil
	}
	return "", fmt.Errorf("AppLocker rule %d: type must be path, publisher or hash", i+1)
}
