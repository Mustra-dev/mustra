//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"os/exec"
	"time"
)

func readIdentity(ctx context.Context) machineIdentity {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$c = Get-CimInstance Win32_ComputerSystem; $b = Get-CimInstance Win32_BIOS; $e = Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1
[ordered]@{ m = $c.Manufacturer; model = $c.Model; s = $b.SerialNumber; d = if ($b.ReleaseDate) { $b.ReleaseDate.ToString('yyyy-MM-dd') } else { '' }; ch = [string]($e.ChassisTypes | Select-Object -First 1) } | ConvertTo-Json -Compress`).Output()
	if err != nil {
		return machineIdentity{}
	}
	var v struct{ M, Model, S, D, Ch string }
	if json.Unmarshal(out, &v) != nil {
		return machineIdentity{}
	}
	return machineIdentity{Manufacturer: v.M, Model: v.Model, Serial: v.S, BIOSDate: normalizeBIOSDate(v.D), Chassis: chassisName(v.Ch)}
}
