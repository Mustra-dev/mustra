package agent

import (
	"context"
	"strings"
	"sync"
	"time"
)

// machineIdentity is what a machine says it is: make, model, serial,
// firmware date, chassis. It does not change while the agent runs, and
// reading it costs a PowerShell or system_profiler start on some
// platforms, so it is read once every few hours.
type machineIdentity struct {
	Manufacturer, Model, Serial, BIOSDate, Chassis string
}

var identityCache struct {
	sync.Mutex
	id machineIdentity
	at time.Time
}

func cachedIdentity(ctx context.Context) machineIdentity {
	identityCache.Lock()
	defer identityCache.Unlock()
	if !identityCache.at.IsZero() && time.Since(identityCache.at) < 6*time.Hour {
		return identityCache.id
	}
	id := readIdentity(ctx)
	id.Manufacturer = cleanIdentity(id.Manufacturer)
	id.Model = cleanIdentity(id.Model)
	id.Serial = cleanIdentity(id.Serial)
	if virtualVendor(id.Manufacturer + " " + id.Model) {
		id.Chassis = "virtual"
	}
	identityCache.id, identityCache.at = id, time.Now()
	return id
}

// cleanIdentity drops the placeholders firmware vendors ship unfilled.
func cleanIdentity(v string) string {
	v = strings.TrimSpace(strings.ReplaceAll(v, "\x00", ""))
	switch strings.ToLower(v) {
	case "", "to be filled by o.e.m.", "to be filled by oem", "default string", "system serial number", "system product name",
		"system manufacturer", "not specified", "not applicable", "none", "0", "0123456789", "123456789", "oem", "n/a":
		return ""
	}
	return v
}

// virtualVendor recognises a hypervisor's made-up machine. Windows does
// not report virtualization to the agent, and QEMU's chassis type is
// "Other", so the vendor string is the reliable tell.
func virtualVendor(s string) bool {
	s = strings.ToLower(s)
	for _, v := range []string{"qemu", "vmware", "virtualbox", "innotek", "xen", "bochs", "parallels", "kvm", "virtual machine", "amazon ec2", "google compute engine"} {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

// chassisName maps the SMBIOS chassis type to a word.
func chassisName(code string) string {
	switch strings.TrimSpace(code) {
	case "3", "4", "5", "6", "7", "15", "16", "24":
		return "desktop"
	case "8", "9", "10", "14", "31", "32":
		return "laptop"
	case "11":
		return "handheld"
	case "13":
		return "all-in-one"
	case "17", "23", "25", "28":
		return "server"
	case "30":
		return "tablet"
	case "35", "36":
		return "mini PC"
	case "1", "2", "":
		return ""
	}
	return "other"
}

// normalizeBIOSDate turns "08/17/2023" or "20230817000000.000000+000"
// into 2023-08-17.
func normalizeBIOSDate(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 8 && strings.Trim(v[:8], "0123456789") == "" {
		return v[0:4] + "-" + v[4:6] + "-" + v[6:8]
	}
	if t, err := time.Parse("01/02/2006", v); err == nil {
		return t.Format("2006-01-02")
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.Format("2006-01-02")
	}
	return ""
}
