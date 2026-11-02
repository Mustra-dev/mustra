package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestMacOSUpdateDeclaration(t *testing.T) {
	now := time.Date(2026, 10, 27, 20, 15, 0, 0, time.UTC)
	var d struct {
		Type, Identifier string
		Payload          map[string]string
	}
	if err := json.Unmarshal(macOSUpdateDeclaration("27.1", macOSDeadline(now, false)), &d); err != nil {
		t.Fatal(err)
	}
	if d.Type != "com.apple.configuration.softwareupdate.enforcement.specific" || d.Identifier != macOSDeclarationID ||
		d.Payload["TargetOSVersion"] != "27.1" || d.Payload["TargetLocalDateTime"] != "2026-10-30T20:15:00" {
		t.Errorf("declaration %+v", d)
	}
	if got := macOSDeadline(now, true); !got.Before(now) {
		t.Errorf("install-now deadline %v is not in the past", got)
	}
	summary := "Install macOS Tahoe 27.1 through Fleet MDM (target 27.1, deadline 2026-10-30T20:15)"
	if m := targetVersionRE.FindStringSubmatch(summary); m == nil || m[1] != "27.1" {
		t.Errorf("target from summary: %v", m)
	}
	if dl, ok := macOSActionDeadline(summary); !ok || !dl.Equal(time.Date(2026, 10, 30, 20, 15, 0, 0, time.UTC)) {
		t.Errorf("deadline from summary: %v %v", dl, ok)
	}
	if m := targetVersionRE.FindStringSubmatch("Install macOS 26.7 through Fleet MDM (target 26.7)"); m == nil || m[1] != "26.7" {
		t.Errorf("old summary no longer parses: %v", m)
	}
}

func TestPickMacOSTarget(t *testing.T) {
	pending := []proto.PatchInfo{
		{Name: "macOS Tahoe 27.1-26B10", NewVersion: "27.1"},
		{Name: "macOS Tahoe 27.0.2-26A500", NewVersion: "27.0.2"},
		{Name: "macOS 28 Beta", NewVersion: "28.0"},
		{Name: "Safari", NewVersion: "27.1"},
	}
	all := func(string) bool { return true }
	if p, ok := pickMacOSTarget(pending, "27.0.1", all, false); !ok || p.NewVersion != "27.1" {
		t.Errorf("minor: %v %v", p, ok)
	}
	if p, ok := pickMacOSTarget(pending, "27.0.1", all, true); !ok || p.NewVersion != "28.0" {
		t.Errorf("major allowed: %v %v", p, ok)
	}
	only := func(n string) bool { return strings.Contains(n, "27.0.2") }
	if p, ok := pickMacOSTarget(pending, "27.0.1", only, true); !ok || p.NewVersion != "27.0.2" {
		t.Errorf("patch lists: %v %v", p, ok)
	}
	if _, ok := pickMacOSTarget(nil, "27.0.1", all, true); ok {
		t.Error("picked from nothing")
	}
}

// The Fleet calls: which Macs a free-tier profile reaches, and replacing
// the declaration (delete, then a multipart upload).
func TestFleetDeclarationCalls(t *testing.T) {
	var deleted []string
	var uploaded string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/fleet/hosts":
			if r.URL.Query().Get("mdm_enrollment_status") != "enrolled" {
				t.Errorf("hosts query %s", r.URL.RawQuery)
			}
			io.WriteString(w, `{"hosts":[{"uuid":"A","hostname":"mbp","platform":"darwin","team_id":null},
				{"uuid":"B","hostname":"mini","platform":"darwin","team_id":3},
				{"uuid":"C","hostname":"win","platform":"windows","team_id":null}]}`)
		case r.Method == "GET" && r.URL.Path == "/api/v1/fleet/configuration_profiles":
			io.WriteString(w, `{"profiles":[{"profile_uuid":"old-1","identifier":"com.mustra.macos-update"},{"profile_uuid":"x","identifier":"com.other"}]}`)
		case r.Method == "DELETE":
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/api/v1/fleet/configuration_profiles/"))
		case r.Method == "POST" && r.URL.Path == "/api/v1/fleet/configuration_profiles":
			f, h, err := r.FormFile("profile")
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(f)
			uploaded = h.Filename + ":" + string(b)
			io.WriteString(w, `{"profile_uuid":"new-1"}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	defer srv.Close()
	c := &fleetClient{base: srv.URL, token: "t", http: srv.Client()}
	macs, err := c.unassignedMacs(t.Context())
	if err != nil || len(macs) != 1 || macs[0].UUID != "A" {
		t.Fatalf("unassigned Macs %+v %v", macs, err)
	}
	id, err := c.replaceDeclaration(t.Context(), macOSDeclarationID, "mustra-macos-update.json", []byte(`{"Identifier":"com.mustra.macos-update"}`))
	if err != nil || id != "new-1" {
		t.Fatalf("upload: %q %v", id, err)
	}
	if len(deleted) != 1 || deleted[0] != "old-1" {
		t.Errorf("deleted %v, want the old declaration only", deleted)
	}
	if uploaded != `mustra-macos-update.json:{"Identifier":"com.mustra.macos-update"}` {
		t.Errorf("uploaded %q", uploaded)
	}
}

func TestMacOSVersionNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"27.1", "27.0.1", true}, {"27.0.1", "27.1", false}, {"27.1", "27.1", false}, {"27.1", "27.1.0", false},
		{"28.0", "27.9.9", true}, {"26.7.1", "26.7", true}, {"26.6", "26.7", false},
	} {
		if got := macOSVersionNewer(c.a, c.b); got != c.want {
			t.Errorf("macOSVersionNewer(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestFleetCanInstallMacOS(t *testing.T) {
	tier := "free"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/config" {
			t.Errorf("unexpected %s", r.URL)
		}
		io.WriteString(w, `{"license":{"tier":"`+tier+`"}}`)
	}))
	defer srv.Close()
	c := &fleetClient{base: srv.URL, token: "t", http: srv.Client()}
	if !c.canInstallMacOS(t.Context(), "26.7") {
		t.Error("macOS 26 takes the MDM commands on any tier")
	}
	if c.canInstallMacOS(t.Context(), "27.0.1") {
		t.Error("macOS 27 on Fleet free: declarations need Premium")
	}
	tier = "premium"
	if !c.canInstallMacOS(t.Context(), "27.0.1") {
		t.Error("macOS 27 on Fleet Premium")
	}
}
