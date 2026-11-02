package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Threat hunting over cached sensor data.
//
// Every indicator is matched against a snapshot the fleet already published,
// so a hunt across thirty-nine endpoints is a handful of queries rather than
// thirty-nine machines woken up to search their own disks. That is the same
// bargain the whole sensor model makes, and it is why asking "is this hash
// anywhere in my estate" is a question you can afford to ask on a timer.
//
// The limit is worth stating plainly, because it decides whether a clean
// hunt means anything: a hunt sees exactly what the sensors see. A file
// outside the integrity watch set, or a process that started and exited
// between two collections, is invisible to it. This finds known-bad in the
// places mustra already looks; it is not a filesystem sweep and it is not
// real-time detection.

const huntInterval = 15 * time.Minute

func (s *Server) huntLoop(ctx context.Context) {
	// A first pass shortly after start, so a server that has just been
	// restarted is not blind for a quarter of an hour.
	select {
	case <-ctx.Done():
		return
	case <-time.After(90 * time.Second):
	}
	s.runHunt(ctx)

	ticker := time.NewTicker(huntInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runHunt(ctx)
		}
	}
}

// runHunt evaluates every enabled indicator and records what it finds.
// Returns how many sightings were new.
func (s *Server) runHunt(ctx context.Context) int {
	iocs, err := s.store.ListIOCs(ctx)
	if err != nil {
		s.logger.Warn("hunt: could not load indicators", "error", err)
		return 0
	}

	// Group by kind so each sensor is read once for all the indicators that
	// need it, rather than once per indicator.
	byKind := map[string][]store.IOC{}
	for _, i := range iocs {
		if i.Enabled && strings.TrimSpace(i.Value) != "" {
			// See handleProcessEvents: the matchers compare this value, so
			// trimming only the test leaves a padded indicator permanently
			// dead rather than merely untidy.
			i.Value = strings.TrimSpace(i.Value)
			byKind[i.Kind] = append(byKind[i.Kind], i)
		}
	}
	if len(byKind) == 0 {
		return 0
	}

	// Collected across the whole sweep, then announced once per indicator.
	// Notifying per endpoint meant one indicator matching thirty-seven
	// machines produced thirty-seven notifications — which is precisely the
	// tray-nobody-opens problem this is supposed to avoid.
	fresh := map[string][]string{} // ioc id -> hostnames newly seen on
	byID := map[string]store.IOC{}
	for _, i := range iocs {
		byID[i.ID] = i
	}

	s.huntSensor(ctx, string(proto.SensorProcesses), byKind[store.IOCProcessName], matchProcess, fresh)
	s.huntSensor(ctx, string(proto.SensorIntegrity), byKind[store.IOCFileHash], matchFileHash, fresh)
	s.huntSensor(ctx, string(proto.SensorIntegrity), byKind[store.IOCFilePath], matchFilePath, fresh)
	s.huntSensor(ctx, string(proto.SensorNeighbors), byKind[store.IOCIPAddress], matchNeighborIP, fresh)
	s.huntSensor(ctx, string(proto.SensorInstalledApps), byKind[store.IOCAppName], matchInstalledApp, fresh)

	total := 0
	for iocID, hosts := range fresh {
		total += len(hosts)
		ioc := byID[iocID]
		severity := ioc.Severity
		if severity != "critical" && severity != "info" {
			severity = "warning"
		}
		s.notify(ctx, severity, "Threat Response",
			"Indicator found: "+ioc.Name, summariseHosts(hosts), "/hunt#findings")
	}
	return total
}

// summariseCount names a few of anything and counts the rest, with the
// caller supplying the noun. summariseHosts used to be used for paths too,
// which produced "seen on 5 endpoints, including /etc/cron.d/a" for five
// paths on one machine — a wrong blast-radius claim in a security alert,
// which is the worst place to overstate anything.
func summariseCount(items []string, noun string) string {
	const show = 3
	if len(items) <= show {
		return "seen at " + strings.Join(items, ", ")
	}
	return fmt.Sprintf("seen at %d %s, including %s",
		len(items), noun, strings.Join(items[:show], ", "))
}

// summariseHosts names a few and counts the rest. A notification listing
// thirty-seven hostnames is one nobody reads to the end; the count is what
// tells you how bad it is, and the names are enough to start somewhere.
func summariseHosts(hosts []string) string {
	const show = 3
	if len(hosts) <= show {
		return "seen on " + strings.Join(hosts, ", ")
	}
	return fmt.Sprintf("seen on %d endpoints, including %s",
		len(hosts), strings.Join(hosts[:show], ", "))
}

// matcher returns the values on one endpoint that this indicator matched,
// with a short human explanation of where each came from.
type matcher func(ioc store.IOC, data []byte) []huntHit

type huntHit struct {
	value   string
	context string
}

// huntSensor records what one sensor's data matches, collecting newly-seen
// hostnames into fresh rather than announcing them itself — the caller
// aggregates so that one indicator produces one notification.
func (s *Server) huntSensor(ctx context.Context, sensor string, iocs []store.IOC,
	match matcher, fresh map[string][]string) {

	if len(iocs) == 0 {
		return
	}
	rows, err := s.store.ListSensorDataForSensor(ctx, sensor)
	if err != nil {
		s.logger.Warn("hunt: could not read sensor", "sensor", sensor, "error", err)
		return
	}

	for _, ioc := range iocs {
		for _, row := range rows {
			seenHere := false
			for _, hit := range match(ioc, row.Data) {
				isNew, err := s.store.RecordIOCFinding(ctx, store.IOCFinding{
					ID: idgen.New("ioc-f-"), IOCID: ioc.ID, AgentID: row.AgentID,
					MatchedValue: hit.value, Context: hit.context,
				})
				if err != nil {
					s.logger.Warn("hunt: could not record finding", "ioc", ioc.Name, "error", err)
					continue
				}
				if !isNew {
					continue
				}
				// Only the first sighting counts. A hunt runs on a timer, and
				// re-announcing the same finding every fifteen minutes is how
				// a tray of real alerts becomes one nobody opens.
				s.logger.Warn("indicator matched", "ioc", ioc.Name, "kind", ioc.Kind,
					"host", row.Hostname, "matched", hit.value)
				if !seenHere {
					host := row.Hostname
					if host == "" {
						host = row.AgentID
					}
					fresh[ioc.ID] = append(fresh[ioc.ID], host)
					seenHere = true
				}
			}
		}
	}
}

// --- matchers ---
//
// Each decodes the sensor payload it was given and reports what matched.
// A payload that will not decode is skipped rather than failing the hunt:
// one endpoint publishing something malformed should not stop the other
// thirty-eight being checked.

func matchProcess(ioc store.IOC, data []byte) []huntHit {
	var procs []proto.ProcessInfo
	if json.Unmarshal(data, &procs) != nil {
		return nil
	}
	var hits []huntHit
	for _, p := range procs {
		if strings.EqualFold(p.Name, ioc.Value) {
			who := p.Username
			if who == "" {
				who = "unknown user"
			}
			hits = append(hits, huntHit{
				value:   p.Name,
				context: "process " + p.Name + " running as " + who,
			})
		}
	}
	return dedupe(hits)
}

func matchFileHash(ioc store.IOC, data []byte) []huntHit {
	var files []proto.IntegrityFile
	if json.Unmarshal(data, &files) != nil {
		return nil
	}
	var hits []huntHit
	for _, f := range files {
		if f.Hash != "" && strings.EqualFold(f.Hash, ioc.Value) {
			hits = append(hits, huntHit{
				value:   f.Path,
				context: "file at " + f.Path + " matches the hash",
			})
		}
	}
	return dedupe(hits)
}

func matchFilePath(ioc store.IOC, data []byte) []huntHit {
	var files []proto.IntegrityFile
	if json.Unmarshal(data, &files) != nil {
		return nil
	}
	needle := strings.ToLower(ioc.Value)
	var hits []huntHit
	for _, f := range files {
		// Substring rather than exact: an indicator is usually a filename or
		// a directory, and requiring the full path would mean knowing where
		// it landed before you go looking for it.
		if strings.Contains(strings.ToLower(f.Path), needle) {
			hits = append(hits, huntHit{value: f.Path, context: "file present at " + f.Path})
		}
	}
	return dedupe(hits)
}

func matchNeighborIP(ioc store.IOC, data []byte) []huntHit {
	var nb []proto.NeighborInfo
	if json.Unmarshal(data, &nb) != nil {
		return nil
	}
	var hits []huntHit
	for _, n := range nb {
		if n.IP == ioc.Value {
			hits = append(hits, huntHit{
				value:   n.IP,
				context: "this endpoint has recently talked to " + n.IP,
			})
		}
	}
	return dedupe(hits)
}

func matchInstalledApp(ioc store.IOC, data []byte) []huntHit {
	var apps []proto.InstalledApp
	if json.Unmarshal(data, &apps) != nil {
		return nil
	}
	needle := strings.ToLower(ioc.Value)
	var hits []huntHit
	for _, a := range apps {
		if strings.Contains(strings.ToLower(a.Name), needle) {
			v := a.Name
			if a.Version != "" {
				v += " " + a.Version
			}
			hits = append(hits, huntHit{value: a.Name, context: "installed: " + v})
		}
	}
	return dedupe(hits)
}

// dedupe collapses repeats within one endpoint — twenty copies of the same
// process name is one finding, not twenty.
func dedupe(hits []huntHit) []huntHit {
	if len(hits) < 2 {
		return hits
	}
	seen := map[string]bool{}
	out := hits[:0]
	for _, h := range hits {
		if seen[h.value] {
			continue
		}
		seen[h.value] = true
		out = append(out, h)
	}
	return out
}
