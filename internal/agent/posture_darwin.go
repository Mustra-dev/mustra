//go:build darwin

package agent

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectPostureDarwin: the application firewall's global state and
// FileVault. XProtect is always on and not configurable, so antimalware
// reports "xprotect" enabled; there is no application-control model here
// (Gatekeeper is closer to code signing than to AppLocker).
func collectPosturePlatform(ctx context.Context) proto.SecurityPosture {
	p := proto.SecurityPosture{FirewallEngine: "macos-alf", EncryptionEngine: "filevault", AntivirusEngine: "xprotect", AntivirusEnabled: true, AntivirusRealtime: true, AppControlEngine: "none", AppControlMode: "off"}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").CombinedOutput(); err == nil {
		p.FirewallEnabled = strings.Contains(string(out), "enabled")
	} else {
		p.Errors = append(p.Errors, "firewall: "+err.Error())
	}
	if out, err := exec.CommandContext(cctx, "fdesetup", "status").CombinedOutput(); err == nil {
		on := strings.Contains(string(out), "FileVault is On")
		p.OSVolumeEncrypted = on
		status := "FullyDecrypted"
		if on {
			status = "FullyEncrypted"
		}
		if strings.Contains(string(out), "Encryption in progress") {
			status = "EncryptionInProgress"
		}
		p.Volumes = []proto.VolumeEncryption{{Mount: "/", Type: "os", Status: status, ProtectionOn: on, Method: "FileVault", Percent: map[bool]int{true: 100, false: 0}[on]}}
	} else {
		p.Errors = append(p.Errors, "filevault: "+err.Error())
	}
	return p
}
