package server

import (
	"context"
	"encoding/json"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensorbuild"
	"github.com/mustra-dev/mustra/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGoBuildCacheAndFailure(t *testing.T) {
	t.Setenv("MUSTRA_PACKAGE_FILE_DIR", t.TempDir())
	calls := 0
	fail := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/build" {
			t.Error(r.URL.Path)
		}
		result := sensorbuild.Result{Data: []byte("executable")}
		if fail {
			result = sensorbuild.Result{Error: "syntax error"}
		}
		json.NewEncoder(w).Encode(result)
	}))
	defer upstream.Close()
	s := &Server{cfg: Config{ScriptToolsURL: upstream.URL}}
	c := store.CustomSensor{Commands: map[string]string{"linux": "package main;func main(){}"}, Platforms: map[string]proto.SensorPlatform{"linux": {Language: "go"}}}
	for i := 0; i < 2; i++ {
		if err := s.buildGoSensors(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("built %d times; want one per architecture", calls)
	}
	old := sensorbuild.Key(goRequest(c, "linux", "amd64"))
	c.Commands["linux"] = "bad source"
	fail = true
	if s.buildGoSensors(context.Background(), c) == nil {
		t.Fatal("accepted build failure")
	}
	if _, err := readGoArtifact(old); err != nil {
		t.Fatal("lost last usable artifact", err)
	}
}
func TestGoArtifactDownloadRequiresToken(t *testing.T) {
	s := &Server{dlTokens: newDownloadTokens()}
	r := httptest.NewRequest("GET", "/sensor-artifacts/bad", nil)
	r.SetPathValue("key", "bad")
	w := httptest.NewRecorder()
	s.handleGoSensorArtifact(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func TestGoCapabilityGate(t *testing.T) {
	c := store.CustomSensor{Enabled: true, Commands: map[string]string{"linux": "package main;func main(){}"}, Platforms: map[string]proto.SensorPlatform{"linux": {Language: "go"}}}
	for _, version := range []int{0, 1} {
		_, status := customStatus(c, "linux", nil, version, time.Now())
		if status != "unsupported" {
			t.Fatalf("version %d: %s", version, status)
		}
	}
	_, status := customStatus(c, "linux", nil, 2, time.Now())
	if status != "never_reported" {
		t.Fatal(status)
	}
}
