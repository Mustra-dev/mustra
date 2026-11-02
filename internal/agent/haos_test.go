package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestHAOSHostInfoFromSupervisor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/host/info":
			w.Write([]byte(`{"result":"ok","data":{"hostname":"homeassistant","operating_system":"Home Assistant OS 18.3","kernel":"6.18.52-haos","disk_total":129.2,"disk_used":16.2,"disk_free":107.7}}`))
		case "/os/info":
			w.Write([]byte(`{"result":"ok","data":{"version":"18.3"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := supervisorURL
	supervisorURL = srv.URL
	defer func() { supervisorURL = old }()
	supervisorCache.host = nil

	t.Setenv("SUPERVISOR_TOKEN", "tok")
	h := haosHostInfo(context.Background())
	if h == nil || h.Hostname != "homeassistant" || h.OSVersion != "18.3" || h.Kernel != "6.18.52-haos" {
		t.Fatalf("got %+v", h)
	}

	// The add-on mounts none of the host's filesystems; the data disk comes
	// from the Supervisor, in both the disks sensor and the health score.
	disks, err := collectDisks(context.Background())
	if err != nil || len(disks) != 1 || disks[0].TotalGB != 129.2 || disks[0].UsedPercent != 12.54 {
		t.Fatalf("disks = %+v %v", disks, err)
	}
	if s := takeSample(context.Background()); s.diskPct != 12.54 {
		t.Fatalf("health disk = %v, want 12.54", s.diskPct)
	}

	f, err := collectFacts(context.Background(), "a", localAgentInfoMust(t), "0")
	if err != nil {
		t.Fatal(err)
	}
	if f.Platform != platformHAOS || f.PlatformVer != "18.3" {
		t.Fatalf("facts platform = %q %q, want haos 18.3", f.Platform, f.PlatformVer)
	}
}

func TestHAOSHostInfoOutsideAddon(t *testing.T) {
	t.Setenv("SUPERVISOR_TOKEN", "")
	if h := haosHostInfo(context.Background()); h != nil {
		t.Fatalf("expected nil outside an add-on, got %+v", h)
	}
}

func localAgentInfoMust(t *testing.T) proto.AgentInfo {
	t.Helper()
	i, err := localAgentInfo("default", "0")
	if err != nil {
		t.Fatal(err)
	}
	if i.Hostname != "homeassistant" {
		t.Fatalf("hostname = %q, want the Supervisor's", i.Hostname)
	}
	return i
}

// The answers from the real Home Assistant host on 2026-10-18: Core and one
// add-on have updates, the OS and the Supervisor do not.
func TestCollectPatchesHAOS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/os/info":
			w.Write([]byte(`{"result":"ok","data":{"version":"18.3","version_latest":"18.3","update_available":false}}`))
		case "/core/info":
			w.Write([]byte(`{"result":"ok","data":{"version":"2026.10.0","version_latest":"2026.10.2","update_available":true}}`))
		case "/supervisor/info":
			w.Write([]byte(`{"result":"ok","data":{"version":"2026.10.2","version_latest":"2026.10.2","update_available":false,"addons":[` +
				`{"name":"Mosquitto broker","slug":"core_mosquitto","version":"7.0.17","version_latest":"7.0.18","update_available":true},` +
				`{"name":"mustra agent","slug":"local_mustra_agent","version":"1.0.1","version_latest":"1.0.1","update_available":false}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("SUPERVISOR_TOKEN", "test")
	old := supervisorURL
	supervisorURL = srv.URL
	defer func() { supervisorURL = old }()

	got, err := collectPatchesHAOS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "Home Assistant Core" || got[0].NewVersion != "2026.10.2" || got[0].CurrentVersion != "2026.10.0" ||
		got[1].Name != "Add-on: Mosquitto broker" || got[1].NewVersion != "7.0.18" {
		t.Fatalf("got %+v", got)
	}
}
