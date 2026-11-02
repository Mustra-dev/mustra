package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// A stand-in for login.microsoftonline.com and graph.microsoft.com.
func fakeGraph(t *testing.T, secret string, actions *[]string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/tenant-1/oauth2/v2.0/token":
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != secret || r.Form.Get("grant_type") != "client_credentials" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		case r.Header.Get("Authorization") != "Bearer tok":
			w.WriteHeader(http.StatusUnauthorized)
			return
		case r.URL.Path == "/v1.0/devices" && r.URL.Query().Get("page") == "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value":           []map[string]any{{"deviceId": "AAAAAAAA-0000-0000-0000-000000000001", "displayName": "LAPTOP-1", "operatingSystem": "Windows", "trustType": "AzureAd", "isCompliant": true}},
				"@odata.nextLink": srv.URL + "/v1.0/devices?page=2"})
		case r.URL.Path == "/v1.0/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"deviceId": "aaaaaaaa-0000-0000-0000-000000000002", "displayName": "web01.corp", "operatingSystem": "Windows", "trustType": "ServerAd"}}})
		case r.URL.Path == "/v1.0/deviceManagement/managedDevices":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
				{"id": "intune-1", "azureADDeviceId": "aaaaaaaa-0000-0000-0000-000000000001", "deviceName": "LAPTOP-1", "complianceState": "noncompliant", "userPrincipalName": "alice@corp.example", "serialNumber": "SN1"},
				{"id": "intune-2", "azureADDeviceId": "00000000-0000-0000-0000-000000000000", "deviceName": "iPad", "complianceState": "compliant"}}})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1.0/deviceManagement/managedDevices/"):
			*actions = append(*actions, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv
}

func TestEntraFetchMergeAndMatch(t *testing.T) {
	var actions []string
	srv := fakeGraph(t, "s3cret", &actions)
	defer srv.Close()
	g := newGraphClient("tenant-1", "client", "s3cret")
	g.loginBase, g.graphBase = srv.URL, srv.URL
	devices, intuneErr, err := fetchEntraDevices(context.Background(), g)
	if err != nil || intuneErr != nil {
		t.Fatal(err, intuneErr)
	}
	if len(devices) != 3 {
		t.Fatalf("two Entra devices (two pages) and one Intune-only device: %+v", devices)
	}
	laptop := devices[0]
	if laptop.IntuneID != "intune-1" || laptop.ComplianceState != "noncompliant" || laptop.UserUPN != "alice@corp.example" || laptop.EntraCompliant == nil || !*laptop.EntraCompliant {
		t.Errorf("Intune should merge into the Entra device by ID (case-insensitively): %+v", laptop)
	}
	if devices[2].Key != "intune:intune-2" || devices[2].Name != "iPad" {
		t.Errorf("an Intune device Entra lacks is kept on its own: %+v", devices[2])
	}
	matchDevices(devices, map[string]string{"aaaaaaaa-0000-0000-0000-000000000001": "agt-laptop"},
		map[string][]string{"web01": {"agt-web"}, "ipad": {"agt-a", "agt-b"}})
	if devices[0].AgentID != "agt-laptop" || devices[1].AgentID != "agt-web" || devices[2].AgentID != "" {
		t.Errorf("matching: by Entra device ID, else a unique short hostname: %v %v %v", devices[0].AgentID, devices[1].AgentID, devices[2].AgentID)
	}
	if err := g.do(context.Background(), http.MethodPost, "/v1.0/deviceManagement/managedDevices/intune-1/rebootNow", nil); err != nil || len(actions) != 1 {
		t.Fatalf("action: %v %v", err, actions)
	}

	bad := newGraphClient("tenant-1", "client", "wrong")
	bad.loginBase, bad.graphBase = srv.URL, srv.URL
	if _, _, err := fetchEntraDevices(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "AADSTS7000215") || strings.Contains(err.Error(), "Trace ID") {
		t.Fatalf("a refused secret must say why, briefly: %v", err)
	}
	_ = store.EntraDevice{}
}
