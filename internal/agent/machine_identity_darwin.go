//go:build darwin

package agent

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

func readIdentity(ctx context.Context) machineIdentity {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "system_profiler", "SPHardwareDataType", "-json").Output()
	if err != nil {
		return machineIdentity{}
	}
	var v struct {
		Items []struct {
			Name   string `json:"machine_name"`
			Model  string `json:"machine_model"`
			Number string `json:"model_number"`
			Serial string `json:"serial_number"`
		} `json:"SPHardwareDataType"`
	}
	if json.Unmarshal(out, &v) != nil || len(v.Items) == 0 {
		return machineIdentity{}
	}
	it := v.Items[0]
	model := strings.TrimSpace(it.Name + " (" + it.Model + ")")
	chassis := "desktop"
	if strings.Contains(strings.ToLower(it.Name), "book") {
		chassis = "laptop"
	}
	return machineIdentity{Manufacturer: "Apple", Model: model, Serial: it.Serial, Chassis: chassis}
}
