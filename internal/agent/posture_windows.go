//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectPostureWindows asks the platform APIs the typed Enforce policies
// use, so what the sensor reports and what a policy checks cannot drift
// apart: NetSecurity for the firewall, the BitLocker module for volumes
// (including recovery passwords, which the server escrows), Defender's
// Get-MpComputerStatus/Get-MpPreference, and the local AppLocker policy.
//
// Each probe is its own try/catch so one missing module (BitLocker on a
// Home edition, say) does not blank the others.
func collectPosturePlatform(ctx context.Context) proto.SecurityPosture {
	const script = `
$ErrorActionPreference = 'Stop'
$out = [ordered]@{ errors = @() }
try {
  $profiles = Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled; default_inbound = "$($_.DefaultInboundAction)"; default_outbound = "$($_.DefaultOutboundAction)"; log_blocked = [bool]$_.LogBlocked } }
  $out.firewall_profiles = @($profiles)
} catch { $out.errors += "firewall: $($_.Exception.Message)" }
try {
  $vols = Get-BitLockerVolume | ForEach-Object {
    $rp = @($_.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
    [ordered]@{
      mount = $_.MountPoint; type = "$($_.VolumeType)"; status = "$($_.VolumeStatus)"; protection_on = ("$($_.ProtectionStatus)" -eq 'On')
      method = "$($_.EncryptionMethod)"; percent = [int]$_.EncryptionPercentage
      protectors = @($_.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
      recovery_key_ids = @($rp | ForEach-Object { "$($_.KeyProtectorId)" })
      recovery_keys = @($rp | Where-Object { $_.RecoveryPassword } | ForEach-Object { [ordered]@{ key_id = "$($_.KeyProtectorId)"; password = "$($_.RecoveryPassword)" } })
    }
  }
  $out.volumes = @($vols)
} catch { $out.errors += "bitlocker: $($_.Exception.Message)" }
try {
  $st = Get-MpComputerStatus
  $pref = Get-MpPreference
  $age = -1
  if ($st.AntivirusSignatureLastUpdated) { $age = [int]((Get-Date) - $st.AntivirusSignatureLastUpdated).TotalHours }
  $out.defender = [ordered]@{
    service = [bool]$st.AMServiceEnabled; realtime = [bool]$st.RealTimeProtectionEnabled; signature_age_hours = $age
    last_quick_scan = if ($st.QuickScanEndTime) { $st.QuickScanEndTime.ToString('o') } else { '' }
    tamper = [bool]$st.IsTamperProtected; maps = [int]$pref.MAPSReporting
  }
} catch { $out.errors += "defender: $($_.Exception.Message)" }
try {
  $p = [xml](Get-AppLockerPolicy -Local -Xml)
  $cols = @($p.AppLockerPolicy.RuleCollection | ForEach-Object { [ordered]@{ type = "$($_.Type)"; mode = "$($_.EnforcementMode)"; rules = @($_.ChildNodes).Count } })
  $svc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
  $out.applocker = [ordered]@{ collections = $cols; service_running = ($svc -and $svc.Status -eq 'Running') }
} catch { $out.errors += "applocker: $($_.Exception.Message)" }
try {
  $ts = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
  $rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
  $v = (Get-ItemProperty $ts -Name Shadow -ErrorAction SilentlyContinue).Shadow; $src = 'policy'
  if ($null -eq $v) { $v = (Get-ItemProperty $rdp -Name Shadow -ErrorAction SilentlyContinue).Shadow; $src = 'default' }
  if ($null -eq $v) { $v = 1 }
  $rule = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -ErrorAction SilentlyContinue | Where-Object { "$($_.Enabled)" -eq 'True' -and ($_ | Get-NetFirewallApplicationFilter).Program -like '*RdpSa.exe' })
  $svc = Get-Service TermService -ErrorAction SilentlyContinue
  $out.shadow = [ordered]@{ value = [int]$v; source = $src; firewall_rule = ($rule.Count -gt 0); service = [bool]($svc -and $svc.Status -eq 'Running') }
} catch { $out.errors += "shadow: $($_.Exception.Message)" }
$out | ConvertTo-Json -Depth 6 -Compress`

	p := proto.SecurityPosture{FirewallEngine: "unknown", EncryptionEngine: "unknown", AntivirusEngine: "unknown", AppControlEngine: "unknown"}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		p.Errors = append(p.Errors, "posture script: "+err.Error()+": "+strings.TrimSpace(stderr.String()))
		return p
	}
	var raw struct {
		Errors           []string `json:"errors"`
		FirewallProfiles []struct {
			Name            string `json:"name"`
			Enabled         bool   `json:"enabled"`
			DefaultInbound  string `json:"default_inbound"`
			DefaultOutbound string `json:"default_outbound"`
			LogBlocked      bool   `json:"log_blocked"`
		} `json:"firewall_profiles"`
		Volumes []struct {
			Mount          string   `json:"mount"`
			Type           string   `json:"type"`
			Status         string   `json:"status"`
			ProtectionOn   bool     `json:"protection_on"`
			Method         string   `json:"method"`
			Percent        int      `json:"percent"`
			Protectors     []string `json:"protectors"`
			RecoveryKeyIDs []string `json:"recovery_key_ids"`
			RecoveryKeys   []struct {
				KeyID    string `json:"key_id"`
				Password string `json:"password"`
			} `json:"recovery_keys"`
		} `json:"volumes"`
		Defender *struct {
			Service       bool   `json:"service"`
			Realtime      bool   `json:"realtime"`
			SignatureAge  int    `json:"signature_age_hours"`
			LastQuickScan string `json:"last_quick_scan"`
			Tamper        bool   `json:"tamper"`
			MAPS          int    `json:"maps"`
		} `json:"defender"`
		Shadow *struct {
			Value        int    `json:"value"`
			Source       string `json:"source"`
			FirewallRule bool   `json:"firewall_rule"`
			Service      bool   `json:"service"`
		} `json:"shadow"`
		AppLocker *struct {
			Collections []struct {
				Type  string `json:"type"`
				Mode  string `json:"mode"`
				Rules int    `json:"rules"`
			} `json:"collections"`
			ServiceRunning bool `json:"service_running"`
		} `json:"applocker"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &raw); err != nil {
		p.Errors = append(p.Errors, "posture output: "+err.Error())
		return p
	}
	p.Errors = append(p.Errors, raw.Errors...)

	if !hasError(raw.Errors, "firewall") {
		p.FirewallEngine = "windows-defender"
		p.FirewallEnabled = len(raw.FirewallProfiles) > 0
		for _, f := range raw.FirewallProfiles {
			p.FirewallProfiles = append(p.FirewallProfiles, proto.FirewallProfileState{Name: f.Name, Enabled: f.Enabled, DefaultInbound: f.DefaultInbound, DefaultOutbound: f.DefaultOutbound, LogBlocked: f.LogBlocked})
			if !f.Enabled {
				p.FirewallEnabled = false
			}
		}
	}
	if !hasError(raw.Errors, "bitlocker") {
		p.EncryptionEngine = "bitlocker"
		if len(raw.Volumes) == 0 {
			p.EncryptionEngine = "none"
		}
		for _, v := range raw.Volumes {
			typ := strings.ToLower(v.Type)
			if typ == "operatingsystem" {
				typ = "os"
			}
			vol := proto.VolumeEncryption{Mount: v.Mount, Type: typ, Status: v.Status, ProtectionOn: v.ProtectionOn, Method: v.Method, Percent: v.Percent, Protectors: v.Protectors, RecoveryKeyIDs: v.RecoveryKeyIDs}
			p.Volumes = append(p.Volumes, vol)
			if typ == "os" && v.Status == "FullyEncrypted" && v.ProtectionOn {
				p.OSVolumeEncrypted = true
			}
			for _, k := range v.RecoveryKeys {
				if k.Password != "" {
					p.RecoveryKeys = append(p.RecoveryKeys, proto.RecoveryKey{Mount: v.Mount, KeyID: k.KeyID, Password: k.Password})
				}
			}
		}
	}
	if raw.Defender != nil {
		p.AntivirusEngine = "defender"
		p.AntivirusEnabled = raw.Defender.Service
		p.AntivirusRealtime = raw.Defender.Realtime
		p.AntivirusSignatureAgeHours = raw.Defender.SignatureAge
		p.AntivirusLastQuickScan = raw.Defender.LastQuickScan
		p.AntivirusTamperProtected = raw.Defender.Tamper
		p.AntivirusCloudLevel = map[int]string{0: "off", 1: "basic", 2: "advanced"}[raw.Defender.MAPS]
	} else if hasError(raw.Errors, "defender") {
		p.AntivirusEngine = "unknown"
	}
	if raw.AppLocker != nil {
		p.AppControlEngine = "applocker"
		modes := map[string]bool{}
		for _, c := range raw.AppLocker.Collections {
			p.AppControlCollections = append(p.AppControlCollections, proto.AppControlCollection{Type: c.Type, Mode: c.Mode, Rules: c.Rules})
			modes[c.Mode] = true
		}
		switch {
		case len(raw.AppLocker.Collections) == 0 || !raw.AppLocker.ServiceRunning:
			p.AppControlMode = "off"
			if len(raw.AppLocker.Collections) == 0 {
				p.AppControlEngine = "none"
			}
		case len(modes) > 1:
			p.AppControlMode = "mixed"
		case modes["Enabled"]:
			p.AppControlMode = "enforce"
		case modes["AuditOnly"]:
			p.AppControlMode = "audit"
		default:
			p.AppControlMode = "off"
		}
	}
	if raw.Shadow != nil {
		firewallActive := false
		for _, f := range raw.FirewallProfiles {
			firewallActive = firewallActive || f.Enabled
		}
		if hasError(raw.Errors, "firewall") {
			firewallActive = true // unknown: assume the rule is needed
		}
		p.RemoteShadow = shadowState(raw.Shadow.Value, raw.Shadow.Source, raw.Shadow.FirewallRule, raw.Shadow.Service, firewallActive)
	}
	return p
}

func hasError(errs []string, prefix string) bool {
	for _, e := range errs {
		if strings.HasPrefix(e, prefix+":") {
			return true
		}
	}
	return false
}
