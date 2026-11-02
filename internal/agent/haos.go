package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Home Assistant OS has no systemd and no shell on the host, so the agent
// runs there as a Supervisor add-on (deploy/haos-addon). Inside the add-on
// container, gopsutil reads the container's /etc/os-release and reports
// Alpine, and os.Hostname returns the container's name. Both are wrong in a
// way that matters: "alpine" would send the vulnerability scanner after the
// add-on's own apk packages. The Supervisor knows the real host, and every
// add-on with hassio_api gets a token to ask it.

// supervisorHost is what the Supervisor says about the machine.
type supervisorHost struct {
	Hostname  string
	OSName    string // "Home Assistant OS 18.3"
	OSVersion string // "18.3"
	Kernel    string
	// The data partition, in GB: the disk that fills up on HAOS (backups,
	// the recorder database, add-on images). The add-on container mounts
	// no host filesystem the agent could measure, so the Supervisor is the
	// only one that can say.
	DiskTotalGB, DiskUsedGB, DiskFreeGB float64
}

// platformHAOS is the platform value an add-on agent reports. Nothing in the
// server treats it as a package-managed distribution, which is correct: HAOS
// updates as a whole image through the Supervisor, never package by package.
const platformHAOS = "haos"

// supervisorURL is a variable so tests can stand in for the Supervisor.
var supervisorURL = "http://supervisor"

var supervisorCache struct {
	sync.Mutex
	at   time.Time
	host *supervisorHost
}

// inHAOSAddon reports whether the Supervisor is reachable from here at all.
func inHAOSAddon() bool { return os.Getenv("SUPERVISOR_TOKEN") != "" }

// haosHostInfo returns the Supervisor's view of the host, or nil outside an
// add-on or when the Supervisor does not answer. Cached for five minutes:
// facts are collected every minute, and the host's name and OS version do
// not change between two of them.
func haosHostInfo(ctx context.Context) *supervisorHost {
	if !inHAOSAddon() {
		return nil
	}
	supervisorCache.Lock()
	defer supervisorCache.Unlock()
	if supervisorCache.host != nil && time.Since(supervisorCache.at) < 5*time.Minute {
		return supervisorCache.host
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var hostInfo struct {
		Hostname        string  `json:"hostname"`
		OperatingSystem string  `json:"operating_system"`
		Kernel          string  `json:"kernel"`
		DiskTotal       float64 `json:"disk_total"`
		DiskUsed        float64 `json:"disk_used"`
		DiskFree        float64 `json:"disk_free"`
	}
	if err := supervisorGet(ctx, "/host/info", &hostInfo); err != nil {
		// Keep a stale answer rather than flip the endpoint back to Alpine
		// because the Supervisor was busy for five seconds.
		return supervisorCache.host
	}
	h := &supervisorHost{Hostname: hostInfo.Hostname, OSName: hostInfo.OperatingSystem, Kernel: hostInfo.Kernel,
		DiskTotalGB: hostInfo.DiskTotal, DiskUsedGB: hostInfo.DiskUsed, DiskFreeGB: hostInfo.DiskFree}
	var osInfo struct {
		Version string `json:"version"`
	}
	if supervisorGet(ctx, "/os/info", &osInfo) == nil {
		h.OSVersion = osInfo.Version
	} else {
		h.OSVersion = strings.TrimPrefix(h.OSName, "Home Assistant OS ")
	}
	supervisorCache.host, supervisorCache.at = h, time.Now()
	return h
}

// haosDataDisk is the HAOS data partition as the Supervisor reports it, or
// nil outside an add-on or when it reports no size.
func haosDataDisk(ctx context.Context) *proto.DiskInfo {
	h := haosHostInfo(ctx)
	if h == nil || h.DiskTotalGB <= 0 {
		return nil
	}
	return &proto.DiskInfo{
		Device:      "hassos-data",
		Mountpoint:  "/mnt/data",
		FSType:      "ext4",
		TotalGB:     round2(h.DiskTotalGB),
		FreeGB:      round2(h.DiskFreeGB),
		UsedGB:      round2(h.DiskUsedGB),
		UsedPercent: round2(h.DiskUsedGB / h.DiskTotalGB * 100),
	}
}

// supervisorGet reads one Supervisor endpoint's "data" object into out.
func supervisorGet(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, supervisorURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SUPERVISOR_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("supervisor %s: %s", path, resp.Status)
	}
	var env struct {
		Result string          `json:"result"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return err
	}
	if env.Result != "ok" {
		return fmt.Errorf("supervisor %s: result %q", path, env.Result)
	}
	return json.Unmarshal(env.Data, out)
}

// updateByRestart is set by a supervisor that installs the agent's staged,
// verified build when it restarts it, as the HAOS add-on's run.sh does.
// There, handing the installer to systemd-run is impossible and
// unnecessary: exiting is the update (stageForRestart).
func updateByRestart() bool { return os.Getenv("MUSTRA_UPDATE_BY_RESTART") == "1" }

// exitForUpdate leaves long enough for the command reply to reach the
// server, then exits with EX_TEMPFAIL so the supervisor's loop installs the
// staged build and restarts. A variable so a test can stay alive. The identity database commits on every write, so there is
// nothing to flush.
var exitForUpdate = func() {
	go func() {
		time.Sleep(3 * time.Second)
		os.Exit(75)
	}()
}

// On HAOS the add-ons are the host's services and its installed software:
// there is no systemd to list, and the only packages the add-on container
// could find are its own Alpine ones. The Supervisor has both answers.

type supervisorAddon struct {
	Name    string `json:"name"`
	Slug    string `json:"slug"`
	Version string `json:"version"`
	State   string `json:"state"`
}

// haosAddons reads the add-on list from /supervisor/info rather than
// /addons: the add-on's hassio_role is "default", which may read any /info
// endpoint but gets 403 from /addons. Asking for "manager" to get the same
// list would also grant starting, stopping and uninstalling add-ons.
func haosAddons(ctx context.Context) ([]supervisorAddon, error) {
	var out struct {
		Addons []supervisorAddon `json:"addons"`
	}
	if err := supervisorGet(ctx, "/supervisor/info", &out); err != nil {
		return nil, err
	}
	return out.Addons, nil
}

func collectServicesHAOS(ctx context.Context) ([]proto.ServiceInfo, error) {
	addons, err := haosAddons(ctx)
	if err != nil {
		return nil, err
	}
	svcs := make([]proto.ServiceInfo, 0, len(addons)+1)
	svcs = append(svcs, proto.ServiceInfo{Name: "homeassistant", DisplayName: "Home Assistant Core", Status: "running"})
	for _, a := range addons {
		status := a.State
		if status == "started" {
			status = "running"
		}
		svcs = append(svcs, proto.ServiceInfo{Name: a.Slug, DisplayName: a.Name, Status: status})
	}
	return svcs, nil
}

func collectAppsHAOS(ctx context.Context) ([]proto.InstalledApp, error) {
	addons, err := haosAddons(ctx)
	if err != nil {
		return nil, err
	}
	apps := make([]proto.InstalledApp, 0, len(addons)+3)
	for _, part := range []struct{ path, name string }{
		{"/os/info", "Home Assistant OS"},
		{"/core/info", "Home Assistant Core"},
		{"/supervisor/info", "Home Assistant Supervisor"},
	} {
		var v struct {
			Version string `json:"version"`
		}
		if supervisorGet(ctx, part.path, &v) == nil && v.Version != "" {
			apps = append(apps, proto.InstalledApp{Name: part.name, Version: v.Version, Publisher: "Home Assistant"})
		}
	}
	for _, a := range addons {
		apps = append(apps, proto.InstalledApp{Name: a.Name, Version: a.Version, Publisher: "Home Assistant add-on"})
	}
	return apps, nil
}

// collectPatchesHAOS reports what Home Assistant would update: the OS, Core,
// the Supervisor and each add-on, from the same /info endpoints the
// "default" role may read. HAOS has no package manager the agent could
// scan, so before this the endpoint never reported any patches at all.
// Installing them stays with Home Assistant (Settings → System → Updates):
// that would need the "manager" role, which also starts, stops and
// uninstalls add-ons.
func collectPatchesHAOS(ctx context.Context) ([]proto.PatchInfo, error) {
	type versions struct {
		Version         string `json:"version"`
		VersionLatest   string `json:"version_latest"`
		UpdateAvailable bool   `json:"update_available"`
	}
	var patches []proto.PatchInfo
	add := func(name string, v versions, restart bool) {
		if v.UpdateAvailable && v.VersionLatest != "" {
			patches = append(patches, proto.PatchInfo{Name: name, CurrentVersion: v.Version, NewVersion: v.VersionLatest, RestartRequired: restart})
		}
	}
	var osInfo, core versions
	if err := supervisorGet(ctx, "/os/info", &osInfo); err != nil {
		return nil, err
	}
	if err := supervisorGet(ctx, "/core/info", &core); err != nil {
		return nil, err
	}
	var sup struct {
		versions
		Addons []struct {
			Name string `json:"name"`
			versions
		} `json:"addons"`
	}
	if err := supervisorGet(ctx, "/supervisor/info", &sup); err != nil {
		return nil, err
	}
	add("Home Assistant OS", osInfo, true)
	add("Home Assistant Core", core, false)
	add("Home Assistant Supervisor", sup.versions, false)
	for _, a := range sup.Addons {
		add("Add-on: "+a.Name, a.versions, false)
	}
	return patches, nil
}
