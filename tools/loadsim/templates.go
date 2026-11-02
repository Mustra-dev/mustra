//go:build loadsim

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// payloads are a real agent's captured messages (loadsim capture), reduced
// to the parts a simulated agent re-stamps with its own identity: the data
// of each sensor kind, and the event batches.
type payloads struct {
	sensors    map[string]json.RawMessage // kind -> SensorSnapshot.Data
	kinds      []string
	facts      proto.Facts
	procEvents json.RawMessage // raw ProcessEventBatch with the template agent's id
	recEvents  json.RawMessage
	templateID string
}

func loadPayloads(dir string) (*payloads, error) {
	p := &payloads{sensors: map[string]json.RawMessage{}}
	files, err := filepath.Glob(filepath.Join(dir, "sensor.*.json"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var snap proto.SensorSnapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		p.sensors[string(snap.Sensor)] = snap.Data
		p.templateID = snap.AgentID
	}
	raw, err := os.ReadFile(filepath.Join(dir, "facts.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &p.facts); err != nil {
		return nil, err
	}
	p.procEvents, _ = os.ReadFile(filepath.Join(dir, "procevents.json"))
	p.recEvents, _ = os.ReadFile(filepath.Join(dir, "recevents.json"))
	p.synthesizeMissing()
	for k := range p.sensors {
		p.kinds = append(p.kinds, k)
	}
	sort.Strings(p.kinds)
	return p, nil
}

// synthesizeMissing fills sensors a container cannot produce realistically
// (no systemd, no pending updates) with data shaped like a typical Ubuntu
// server's: ~200 units and a couple of dozen pending upgrades, some of
// them security, named after packages the captured inventory really has.
func (p *payloads) synthesizeMissing() {
	if raw, ok := p.sensors["services"]; !ok || len(raw) < 64 {
		var svcs []proto.ServiceInfo
		for i := range 200 {
			st := "running"
			if i%4 == 0 {
				st = "exited"
			}
			svcs = append(svcs, proto.ServiceInfo{Name: fmt.Sprintf("svc-%03d.service", i),
				DisplayName: fmt.Sprintf("Simulated service number %d for load testing", i), Status: st, StartType: "enabled"})
		}
		p.sensors["services"], _ = json.Marshal(svcs)
	}
	if raw, ok := p.sensors["patches"]; !ok || len(raw) < 64 {
		var apps []proto.InstalledApp
		_ = json.Unmarshal(p.sensors["installed_apps"], &apps)
		var patches []proto.PatchInfo
		for i := 0; i < len(apps) && len(patches) < 24; i += 7 {
			sev := ""
			if len(patches)%3 == 0 {
				sev = "security"
			}
			v := apps[i].Version
			if v == "" {
				v = "1.0"
			}
			patches = append(patches, proto.PatchInfo{Name: apps[i].Name, CurrentVersion: v, NewVersion: v + "+sim1", Severity: sev})
		}
		p.sensors["patches"], _ = json.Marshal(patches)
	}
}

// restamp replaces the template agent's id inside an event batch.
func (p *payloads) restamp(raw json.RawMessage, agentID string) []byte {
	if p.templateID == "" {
		return raw
	}
	return []byte(strings.ReplaceAll(string(raw), p.templateID, agentID))
}
