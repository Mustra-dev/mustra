package server

import (
	"encoding/json"
	"testing"
	"time"
)

// Responses that were maps with keys added only in some cases are
// structs now, and a key still appears exactly when it did: these are
// the JSON each answered with before, case by case.
func TestConditionalResponseKeys(t *testing.T) {
	zero, empty, guac, url, keySet := 0, []string{}, "offer", "https://guac.example", true
	when := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	score := 87.5
	for _, c := range []struct {
		name string
		v    any
		want string
	}{
		{"a sync that matched nothing", entraSyncCounts{Devices: 3}, `{"devices":3}`},
		{"a sync that matched", entraSyncCounts{Devices: 3, Matched: 2, Intune: 1}, `{"devices":3,"intune":1,"matched":2}`},
		{"unrestricted access", myAccessResponse{Unrestricted: true, TotalEndpoints: 4, ActionGroupEndpoints: map[string]int{}},
			`{"action_group_endpoints":{},"content_sets":null,"content_unrestricted":false,"total_endpoints":4,"unrestricted":true}`},
		{"access limited to nothing", myAccessResponse{TotalEndpoints: 4, Endpoints: &zero, Hostnames: &empty, ActionGroupEndpoints: map[string]int{}},
			`{"action_group_endpoints":{},"content_sets":null,"content_unrestricted":false,"endpoints":0,"hostnames":[],"total_endpoints":4,"unrestricted":false}`},
		{"remote config for a viewer, not Guacamole", remoteConfigResponse{Provider: "custom", Enabled: true}, `{"enabled":true,"provider":"custom"}`},
		{"remote config for an admin, Guacamole", remoteConfigResponse{Provider: "guacamole", JIT: &guac, Recording: new(bool), GuacamoleURL: &url, GuacamoleKeySet: &keySet, BeyondTrustSite: new(string), CustomURL: new(string)},
			`{"beyondtrust_site":"","custom_url":"","enabled":false,"guacamole_key_set":true,"guacamole_url":"https://guac.example","jit":"offer","provider":"guacamole","recording":false}`},
		{"scores before any scan", complianceScoresResponse{Endpoints: []endpointScore{}}, `{"auto_scan":"","endpoints":[],"scored":0}`},
		{"scores after one", complianceScoresResponse{Endpoints: []endpointScore{}, Scored: 1, FleetScore: &score}, `{"auto_scan":"","endpoints":[],"fleet_score":87.5,"scored":1}`},
		{"a shell without an expiry", openShellResponse{SessionID: "s", Hostname: "h", WorkingDir: "/"}, `{"hostname":"h","session_id":"s","working_dir":"/"}`},
		{"a shell with one", openShellResponse{SessionID: "s", Hostname: "h", WorkingDir: "/", ExpiresAt: &when},
			`{"expires_at":"2026-10-21T12:00:00Z","hostname":"h","session_id":"s","working_dir":"/"}`},
		{"a remote session without a temporary account", openRemoteResponse{URL: "u", Provider: "p", Address: "a"}, `{"address":"a","provider":"p","url":"u"}`},
		{"one with", openRemoteResponse{URL: "u", Provider: "p", Address: "a", JITAccount: "mustra-1"}, `{"address":"a","jit_account":"mustra-1","provider":"p","url":"u"}`},
		{"a token without install commands", createEnrollTokenResponse{Token: "t", CommandsError: "no public URL"}, `{"commands_error":"no public URL","record":`},
		{"a token with them", createEnrollTokenResponse{Token: "t", Commands: map[string]string{"unix": "u", "windows": "w"}}, `{"commands":{"unix":"u","windows":"w"},"record":`},
	} {
		b, err := json.Marshal(c.v)
		if err != nil {
			t.Fatal(err)
		}
		got := string(b)
		if len(got) > len(c.want) && c.want[len(c.want)-1] == ':' {
			got = got[:len(c.want)] // the record is a store type, not the point here
		}
		if got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}
