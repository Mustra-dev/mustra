package server

import (
	"encoding/json"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

// The endpoint list says which agent build the server hands out, so the
// console can count endpoints behind it before any of them has updated.
func TestAgentsPayloadCarriesServingVersion(t *testing.T) {
	raw, err := encodeAgents([]store.AgentRecord{{AgentID: "a", AgentVersion: "0.56.0"}})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Agents         []store.AgentRecord `json:"agents"`
		ServingVersion string              `json:"serving_version"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.ServingVersion != version.Agent() || len(out.Agents) != 1 {
		t.Fatalf("got %+v, want serving_version %q", out, version.Agent())
	}
}
