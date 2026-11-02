package server

// Live answers. Interact normally answers from the sensor cache: instant,
// and offline endpoints included, but as old as each sensor's last
// collection (fifteen minutes by default). "Ask live" first asks the online
// endpoints for the sensors the question reads that have a live query —
// processes, services, installed apps and patches — waits a bounded time
// for their answers, and lays them over the cache. Everything else, and
// every endpoint that did not answer in time, is answered from the cache
// as before, and the result says how many answered live.

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/groups"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// liveQueryKinds are the sensors a live query can refresh.
var liveQueryKinds = map[string]proto.QueryKind{
	"processes":      proto.QueryKindProcesses,
	"services":       proto.QueryKindServices,
	"installed_apps": proto.QueryKindInstalledApps,
	"patches":        proto.QueryKindPatches,
}

// liveWait bounds how long a live question waits for answers.
var liveWait = 20 * time.Second

// liveSummary is what a live question reports alongside its answer.
type liveSummary struct {
	Sensors  []string `json:"sensors"`  // refreshed live
	Asked    int      `json:"asked"`    // online endpoints asked
	Answered int      `json:"answered"` // that answered every live sensor in time
}

// liveSensorsFor lists the live-capable sensors a question reads, from its
// get list (filters included) and its conditions (groups opened).
func liveSensorsFor(get []string, where []groups.Rule) []string {
	seen := map[string]bool{}
	var out []string
	add := func(field string) {
		sensor, _, ok := strings.Cut(field, ".")
		if _, live := liveQueryKinds[sensor]; ok && live && !seen[sensor] {
			seen[sensor] = true
			out = append(out, sensor)
		}
	}
	for _, g := range get {
		f, _, _ := splitGetFilter(g)
		add(f)
	}
	leaves, _ := groups.ExpandGroups(where)
	for _, r := range leaves {
		if r.Op == "same_row" {
			var children []groups.Rule
			_ = json.Unmarshal([]byte(r.Value), &children)
			for _, c := range children {
				add(c.Field)
			}
			continue
		}
		add(r.Field)
	}
	return out
}

// askLive runs the live queries and returns the rows each agent answered,
// by sensor, in the cache's own shape.
func (s *Server) askLive(ctx context.Context, sensors []string, online int) (map[string]map[string][]map[string]any, liveSummary) {
	sum := liveSummary{Sensors: sensors, Asked: online}
	fresh := map[string]map[string][]map[string]any{}
	if len(sensors) == 0 || online == 0 || s.queryMgr == nil {
		return fresh, sum
	}
	var queries []*activeQuery
	for _, sensor := range sensors {
		aq, err := s.queryMgr.Start(liveQueryKinds[sensor], nil, bnats.QAll(), online)
		if err != nil {
			s.logger.Warn("live question: query failed to start", "sensor", sensor, "error", err)
			continue
		}
		queries = append(queries, aq)
	}
	deadline := time.Now().Add(liveWait)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		done := true
		for _, aq := range queries {
			if aq.snapshot().Responded < aq.Expected {
				done = false
			}
		}
		if done {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	answeredAll := map[string]int{}
	for i, aq := range queries {
		sensor := sensors[i]
		for _, r := range aq.snapshot().Results {
			if r.Error != "" || r.Pending {
				continue
			}
			var payload any
			switch sensor {
			case "processes":
				payload = r.Processes
			case "services":
				payload = r.Services
			case "installed_apps":
				payload = r.InstalledApps
			case "patches":
				payload = r.Patches
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				continue
			}
			rows := []map[string]any{}
			if string(raw) != "null" && json.Unmarshal(raw, &rows) != nil {
				continue
			}
			if fresh[r.AgentID] == nil {
				fresh[r.AgentID] = map[string][]map[string]any{}
			}
			fresh[r.AgentID][sensor] = rows
			answeredAll[r.AgentID]++
		}
	}
	for _, n := range answeredAll {
		if n == len(queries) {
			sum.Answered++
		}
	}
	return fresh, sum
}

// overlayLive replaces cached sensor rows with the live answers.
func overlayLive(devices []groups.Device, fresh map[string]map[string][]map[string]any) []groups.Device {
	if len(fresh) == 0 {
		return devices
	}
	out := make([]groups.Device, len(devices))
	for i, d := range devices {
		if live, ok := fresh[d.AgentID]; ok {
			sensors := make(map[string][]map[string]any, len(d.Sensors)+len(live))
			for k, v := range d.Sensors {
				sensors[k] = v
			}
			for k, v := range live {
				sensors[k] = v
			}
			d.Sensors = sensors
		}
		out[i] = d
	}
	return out
}
