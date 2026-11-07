package server

import (
	"encoding/json"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// A snapshot must survive ingestion with its fields, since normalization
// re-encodes through the type; and one from outside the type is refused.
func TestNormalizeContainersSnapshot(t *testing.T) {
	raw, _ := json.Marshal([]proto.ContainerInfo{{Name: "db", Image: "postgres:16.4", Update: proto.ContainerUpdateAvailable, NewerTag: "17.1", NewerTagInMajor: "16.5"}})
	out, err := normalizeSnapshotData(proto.SensorContainers, raw)
	if err != nil {
		t.Fatal(err)
	}
	var got []proto.ContainerInfo
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 1 || got[0].NewerTagInMajor != "16.5" {
		t.Fatalf("got %s (%v)", out, err)
	}
	if _, err := normalizeSnapshotData(proto.SensorContainers, []byte(`{"name":"not a list"}`)); err == nil {
		t.Error("accepted a snapshot of the wrong shape")
	}
}
