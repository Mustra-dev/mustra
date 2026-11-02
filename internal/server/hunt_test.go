package server

import (
	"encoding/json"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestMatchProcess(t *testing.T) {
	data := mustJSON(t, []proto.ProcessInfo{
		{Name: "sshd", Username: "root"},
		{Name: "XMRig", Username: "nobody"},
		{Name: "xmrig", Username: "nobody"},
	})
	ioc := store.IOC{Kind: store.IOCProcessName, Value: "xmrig"}

	hits := matchProcess(ioc, data)
	// Case-insensitive, because a process name's casing is not a reliable
	// signal and an indicator that misses on capitalisation is worse than
	// none: it reads as "all clear".
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2 (XMRig and xmrig): %+v", len(hits), hits)
	}
	if hits[0].context == "" {
		t.Error("a hit with no context tells nobody what was found")
	}
}

func TestMatchProcessDedupesWithinAnEndpoint(t *testing.T) {
	procs := make([]proto.ProcessInfo, 20)
	for i := range procs {
		procs[i] = proto.ProcessInfo{Name: "evil", Username: "root"}
	}
	hits := matchProcess(store.IOC{Kind: store.IOCProcessName, Value: "evil"}, mustJSON(t, procs))
	// Twenty copies of one process is one finding. Otherwise a fork bomb
	// produces twenty identical rows and the count stops meaning anything.
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
}

func TestMatchFileHash(t *testing.T) {
	const bad = "aa" + "bb" + "cc"
	data := mustJSON(t, []proto.IntegrityFile{
		{Path: "/etc/passwd", Hash: "0011"},
		{Path: "/tmp/dropper", Hash: "AABBCC"}, // upper case on the wire
	})
	hits := matchFileHash(store.IOC{Kind: store.IOCFileHash, Value: bad}, data)
	if len(hits) != 1 || hits[0].value != "/tmp/dropper" {
		t.Fatalf("got %+v, want one hit on /tmp/dropper", hits)
	}
}

func TestMatchFilePathIsSubstring(t *testing.T) {
	data := mustJSON(t, []proto.IntegrityFile{
		{Path: "/etc/cron.d/backup"},
		{Path: "/etc/cron.d/.hidden-miner"},
	})
	// A filename is usually all anyone has; requiring the full path would
	// mean knowing where it landed before going to look for it.
	hits := matchFilePath(store.IOC{Kind: store.IOCFilePath, Value: "hidden-miner"}, data)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1: %+v", len(hits), hits)
	}
}

func TestMatchNeighborIPIsExact(t *testing.T) {
	data := mustJSON(t, []proto.NeighborInfo{
		{IP: "198.51.100.4"},
		{IP: "203.0.113.42"},
	})
	if hits := matchNeighborIP(store.IOC{Value: "203.0.113.42"}, data); len(hits) != 1 {
		t.Fatalf("exact IP should match once, got %d", len(hits))
	}
	// Substring matching on an address would make 198.51.100.4 match 198.51.100.40.
	if hits := matchNeighborIP(store.IOC{Value: "203.0.113"}, data); len(hits) != 0 {
		t.Fatalf("a partial address must not match, got %+v", hits)
	}
}

func TestMatchInstalledApp(t *testing.T) {
	data := mustJSON(t, []proto.InstalledApp{
		{Name: "AnyDesk", Version: "7.1.3"},
		{Name: "Firefox", Version: "120"},
	})
	hits := matchInstalledApp(store.IOC{Value: "anydesk"}, data)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if hits[0].context != "installed: AnyDesk 7.1.3" {
		t.Errorf("context = %q, want the version included", hits[0].context)
	}
}

// One endpoint publishing something unreadable must not stop the other
// thirty-eight being checked.
func TestMatchersSurviveMalformedPayloads(t *testing.T) {
	junk := []byte(`{"not":"an array"}`)
	for name, m := range map[string]matcher{
		"process":   matchProcess,
		"file hash": matchFileHash,
		"file path": matchFilePath,
		"neighbour": matchNeighborIP,
		"app":       matchInstalledApp,
	} {
		t.Run(name, func(t *testing.T) {
			if hits := m(store.IOC{Value: "anything"}, junk); hits != nil {
				t.Fatalf("expected no hits from malformed data, got %+v", hits)
			}
		})
	}
}
