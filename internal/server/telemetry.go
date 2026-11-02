package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Telemetry export: agents collect host metrics (internal/agent/
// metrics*.go, node_exporter's names) and send them here on
// beacon.telemetry.<agent>.metrics; the server labels each series with the
// endpoint it came from and hands them to the operator's Prometheus, by
// remote_write, by being scraped at /metrics/endpoints, or both. Agents
// never talk to Prometheus themselves: they keep their one outbound
// connection, and a laptop off the network still reports.

const settingTelemetry = "telemetry"
const settingTelemetryRemoteWriteSecret = "telemetry.remote_write.secret"

// telemetrySettings is the whole configuration: GET/PUT /api/telemetry.
type telemetrySettings struct {
	Metrics telemetryMetricsSettings `json:"metrics"`
	// RemoteWrite pushes every batch to a Prometheus remote_write endpoint
	// (Prometheus with --web.enable-remote-write-receiver, Mimir, Grafana
	// Cloud, VictoriaMetrics...).
	RemoteWrite telemetryRemoteWrite `json:"remote_write"`
	// Scrape serves the latest batch of every endpoint at
	// /metrics/endpoints, behind the Prometheus integration's token.
	Scrape telemetryScrape `json:"scrape"`
	// Labels shape every series: Job is the job label (default "mustra");
	// Extra labels are added to every series.
	Labels telemetryLabels `json:"labels"`
}

type telemetryMetricsSettings struct {
	Enabled bool `json:"enabled"`
	// IntervalSeconds is how often agents collect, 5-3600; default 15.
	IntervalSeconds int `json:"interval_seconds"`
	// Collectors to run; empty runs all of them.
	Collectors []string `json:"collectors"`
	// GroupIDs limits collection to these computer groups; empty means
	// every endpoint.
	GroupIDs []string `json:"group_ids"`
}

type telemetryRemoteWrite struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	// Username with the secret makes basic auth; the secret alone is sent
	// as a bearer token.
	Username string `json:"username"`
	// SecretSet says a password or token is stored; it is never returned.
	SecretSet bool `json:"secret_set" api:"readonly"`
	// Secret replaces the stored password/token when not empty; clearing
	// it takes ClearSecret.
	Secret      string `json:"secret,omitempty" api:"writeonly"`
	ClearSecret bool   `json:"clear_secret,omitempty"`
}

type telemetryScrape struct {
	Enabled bool `json:"enabled"`
}

type telemetryLabels struct {
	Job   string            `json:"job"`
	Extra map[string]string `json:"extra"`
	// Groups add labels to the endpoints of a computer group, e.g.
	// device_class=laptop, so alert rules can leave laptops out. A group's
	// label beats an extra label of the same name; where an endpoint is in
	// several groups that set the same label, the later entry wins.
	Groups []telemetryGroupLabels `json:"groups"`
	// ProxmoxGuests adds vmid, node and guest_type (lxc or qemu) to the
	// series of an endpoint that is a Proxmox VE guest, as its node's agent
	// reports it (matched by MAC address, then name, as backup status
	// does). A group or extra label of the same name wins.
	ProxmoxGuests bool `json:"proxmox_guests"`
}

type telemetryGroupLabels struct {
	GroupID string            `json:"group_id"`
	Labels  map[string]string `json:"labels"`
}

// telemetryCollectorNames are what the console offers; they match the
// agent's metricCollectors.
var telemetryCollectorNames = []string{"cpu", "memory", "load", "filesystem", "diskstats", "netdev", "stat", "uname", "time", "hwmon", "filefd", "health",
	"pressure", "vmstat", "netstat", "sockstat", "timex", "conntrack", "zfs", "cpufreq", "os", "thermal", "entropy", "arp", "systemd", "netclass"}

func (s *Server) telemetrySettings(ctx context.Context) telemetrySettings {
	var t telemetrySettings
	if raw, err := s.store.GetSetting(ctx, settingTelemetry); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &t)
	}
	if t.Metrics.IntervalSeconds == 0 {
		t.Metrics.IntervalSeconds = 15
	}
	if t.Labels.Job == "" {
		t.Labels.Job = "mustra"
	}
	if stored, _ := s.store.GetSetting(ctx, settingTelemetryRemoteWriteSecret); stored != "" {
		t.RemoteWrite.SecretSet = true
	}
	t.RemoteWrite.Secret, t.RemoteWrite.ClearSecret = "", false
	return t
}

// telemetryConfigFor is what one agent is told to collect.
func (s *Server) telemetryConfigFor(ctx context.Context, agentID string) proto.TelemetryConfig {
	t := s.telemetrySettings(ctx)
	cfg := proto.TelemetryConfig{}
	if t.Metrics.Enabled {
		in := true
		if len(t.Metrics.GroupIDs) > 0 {
			in = s.telemetryMembers(ctx, t.Metrics.GroupIDs)[agentID]
		}
		if in {
			cfg.Metrics = proto.MetricsConfig{Enabled: true, IntervalSeconds: t.Metrics.IntervalSeconds, Collectors: t.Metrics.Collectors}
		}
	}
	raw, _ := json.Marshal(cfg)
	sum := sha256.Sum256(raw)
	cfg.Revision = hex.EncodeToString(sum[:])[:12]
	return cfg
}

// telemetryHub holds the latest batch of every endpoint and the
// remote_write queue.
type telemetryHub struct {
	mu      sync.Mutex
	latest  map[string]telemetryEntry
	queue   []telemetryEntry
	stats   telemetryStats
	wake    chan struct{}
	enabled bool // a cached view of whether anything reads the batches
	members map[string]telemetryMembership
	lastUp  time.Time // when up series were last sent
	// proxmox caches telemetryProxmoxLabels for a few minutes: it reads
	// every Proxmox node's guest list and every endpoint's interfaces.
	proxmox   map[string]map[string]string
	proxmoxAt time.Time
}

type telemetryMembership struct {
	ids map[string]bool
	at  time.Time
}

type telemetryEntry struct {
	AgentID  string
	Received time.Time
	Batch    proto.MetricsBatch
}

// telemetryStats is what the console shows about the export.
type telemetryStats struct {
	BatchesReceived int64      `json:"batches_received"`
	BatchesSent     int64      `json:"batches_sent"`
	BatchesDropped  int64      `json:"batches_dropped"`
	SeriesSent      int64      `json:"series_sent"`
	LastSentAt      *time.Time `json:"last_sent_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	LastErrorAt     *time.Time `json:"last_error_at,omitempty"`
}

func newTelemetryHub() *telemetryHub {
	return &telemetryHub{latest: map[string]telemetryEntry{}, members: map[string]telemetryMembership{}, wake: make(chan struct{}, 1)}
}

// telemetryMaxQueue bounds batches waiting for remote_write: at fifteen
// seconds per endpoint, about ten minutes of a 50-endpoint fleet.
const telemetryMaxQueue = 2000

// telemetryStale is how long an endpoint's last batch is still served to a
// scrape: a stopped agent's series end rather than repeat forever.
const telemetryStale = 5 * time.Minute

func (s *Server) consumeTelemetryMetrics(ctx context.Context) (*nats.Subscription, error) {
	return s.nc.Subscribe(bnats.TelemetryMetricsWildcard(), func(msg *nats.Msg) {
		id, ok := bnats.TelemetryAgentID(msg.Subject)
		if !ok {
			return
		}
		var b proto.MetricsBatch
		if err := json.Unmarshal(msg.Data, &b); err != nil || (b.AgentID != "" && b.AgentID != id) {
			return
		}
		b.AgentID = id
		if b.Timestamp.IsZero() || b.Timestamp.After(time.Now().Add(time.Minute)) {
			b.Timestamp = time.Now().UTC()
		}
		e := telemetryEntry{AgentID: id, Received: time.Now(), Batch: b}
		h := s.telemetry
		h.mu.Lock()
		h.latest[id] = e
		h.stats.BatchesReceived++
		if h.enabled {
			if len(h.queue) >= telemetryMaxQueue {
				h.queue = h.queue[1:]
				h.stats.BatchesDropped++
			}
			h.queue = append(h.queue, e)
		}
		h.mu.Unlock()
		select {
		case h.wake <- struct{}{}:
		default:
		}
	})
}

// telemetrySeries is one labelled sample ready to send or serve.
type telemetrySeries struct {
	Name   string
	Type   string
	Labels [][2]string // sorted by name, __name__ excluded
	Value  float64
	TimeMs int64
}

// telemetryEndpoint is one endpoint as telemetry sees it: the labels the
// server puts on its series, whether it is heartbeating, and whether it is
// in the collection scope.
type telemetryEndpoint struct {
	Labels  [][2]string
	Online  bool
	InScope bool
}

// telemetryEndpoints resolves the labels of every endpoint, with group
// memberships (computed from rules, which is not free) cached briefly
// since this runs for every send.
func (s *Server) telemetryEndpoints(ctx context.Context, t telemetrySettings) map[string]telemetryEndpoint {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil
	}
	var scope map[string]bool
	if len(t.Metrics.GroupIDs) > 0 {
		scope = s.telemetryMembers(ctx, t.Metrics.GroupIDs)
	}
	groupMembers := make([]map[string]bool, len(t.Labels.Groups))
	for i, g := range t.Labels.Groups {
		groupMembers[i] = s.telemetryMembers(ctx, []string{g.GroupID})
	}
	var guests map[string]map[string]string
	if t.Labels.ProxmoxGuests {
		guests = s.telemetryProxmoxLabels(ctx)
	}
	out := make(map[string]telemetryEndpoint, len(agents))
	for _, a := range agents {
		var fromGroups map[string]string
		if g := guests[a.AgentID]; g != nil {
			fromGroups = map[string]string{}
			for k, v := range g {
				fromGroups[k] = v
			}
		}
		for i, g := range t.Labels.Groups {
			if groupMembers[i][a.AgentID] {
				if fromGroups == nil {
					fromGroups = map[string]string{}
				}
				for k, v := range g.Labels {
					fromGroups[k] = v
				}
			}
		}
		out[a.AgentID] = telemetryEndpoint{
			Labels:  endpointLabels(t.Labels, a.Hostname, a.Site, fromGroups),
			Online:  a.Online,
			InScope: scope == nil || scope[a.AgentID],
		}
	}
	return out
}

// telemetryProxmoxLabels maps the agent ID of each endpoint that is a
// Proxmox VE guest to its vmid, node and guest_type, from the guest lists
// the nodes' agents report for backup status. Cached for five minutes.
func (s *Server) telemetryProxmoxLabels(ctx context.Context) map[string]map[string]string {
	h := s.telemetry
	h.mu.Lock()
	cached, at := h.proxmox, h.proxmoxAt
	h.mu.Unlock()
	if cached != nil && time.Since(at) < 5*time.Minute {
		return cached
	}
	statuses, err := s.backupStatuses(ctx)
	if err != nil {
		return cached
	}
	out := map[string]map[string]string{}
	for _, g := range statuses {
		if g.AgentID == "" {
			continue
		}
		out[g.AgentID] = map[string]string{"vmid": strconv.Itoa(g.VMID), "node": g.Node, "guest_type": g.Type}
	}
	h.mu.Lock()
	h.proxmox, h.proxmoxAt = out, time.Now()
	h.mu.Unlock()
	return out
}

// telemetryMembers is agentsInGroups cached for a minute per group set. A
// group that no longer exists has no members: its labels stop applying,
// and a collection scope naming only deleted groups collects nothing
// rather than turning fleet-wide.
func (s *Server) telemetryMembers(ctx context.Context, groupIDs []string) map[string]bool {
	key := strings.Join(groupIDs, ",")
	h := s.telemetry
	h.mu.Lock()
	c, ok := h.members[key]
	h.mu.Unlock()
	if ok && time.Since(c.at) < time.Minute {
		return c.ids
	}
	ids, err := s.agentsInGroups(ctx, groupIDs)
	if err != nil {
		return c.ids // keep the last answer through a passing error
	}
	if ids == nil {
		ids = map[string]bool{}
	}
	h.mu.Lock()
	h.members[key] = telemetryMembership{ids: ids, at: time.Now()}
	h.mu.Unlock()
	return ids
}

// endpointLabels are the labels the server puts on every series of one
// endpoint: job, instance and instance_name (its hostname), then its site,
// replaced by an extra label named site, then the extra labels, then those
// of its groups. Nothing replaces job, instance or instance_name, and each
// name appears once, since Prometheus rejects a whole write request over
// one series with a repeated label.
func endpointLabels(l telemetryLabels, hostname, site string, fromGroups map[string]string) [][2]string {
	merged := map[string]string{}
	if site != "" {
		merged["site"] = site
	}
	for k, v := range l.Extra {
		merged[k] = v
	}
	for k, v := range fromGroups {
		merged[k] = v
	}
	lb := [][2]string{{"job", l.Job}, {"instance", hostname}, {"instance_name", hostname}}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		if validLabelName(k) && k != "job" && k != "instance" && k != "instance_name" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		lb = append(lb, [2]string{k, merged[k]})
	}
	return lb
}

// upSeries are, per endpoint in scope, an "up" sample (1 while it
// heartbeats, 0 once it has gone quiet) and, once it has sent any,
// mustra_metrics_last_received_timestamp_seconds (when its latest batch
// arrived). Pushed metrics have no scrape and so no up of Prometheus' own:
// up keeps an "up == 0" alert working, and the timestamp catches an
// endpoint that heartbeats but has stopped sending metrics, which up alone
// would call healthy.
func upSeries(endpoints map[string]telemetryEndpoint, received map[string]time.Time, now time.Time) []telemetrySeries {
	out := make([]telemetrySeries, 0, 2*len(endpoints))
	for id, e := range endpoints {
		if !e.InScope {
			continue
		}
		v := 0.0
		if e.Online {
			v = 1
		}
		lb := append([][2]string(nil), e.Labels...)
		sort.Slice(lb, func(i, j int) bool { return lb[i][0] < lb[j][0] })
		out = append(out, telemetrySeries{Name: "up", Type: "gauge", Labels: lb, Value: v, TimeMs: now.UnixMilli()})
		if at, ok := received[id]; ok {
			out = append(out, telemetrySeries{Name: "mustra_metrics_last_received_timestamp_seconds", Type: "gauge", Labels: lb,
				Value: float64(at.UnixMilli()) / 1000, TimeMs: now.UnixMilli()})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return labelKey(out[i].Labels) < labelKey(out[j].Labels)
	})
	return out
}

// lastReceived is when each endpoint's latest batch arrived.
func (h *telemetryHub) lastReceived() map[string]time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]time.Time, len(h.latest))
	for id, e := range h.latest {
		out[id] = e.Received
	}
	return out
}

func labelKey(lb [][2]string) string {
	var b strings.Builder
	for _, kv := range lb {
		b.WriteString(kv[0])
		b.WriteByte(0)
		b.WriteString(kv[1])
		b.WriteByte(0)
	}
	return b.String()
}

func expandBatch(b proto.MetricsBatch, endpoint [][2]string) []telemetrySeries {
	ts := b.Timestamp.UnixMilli()
	var out []telemetrySeries
	for _, f := range b.Families {
		if !validMetricName(f.Name) {
			continue
		}
		for _, smp := range f.Samples {
			if math.IsNaN(smp.Value) {
				continue
			}
			// The server's labels come first and win: an agent naming its own
			// instance or job must not pass for another host.
			lb := make([][2]string, 0, len(endpoint)+len(f.Labels))
			seen := map[string]bool{"__name__": true}
			for _, kv := range endpoint {
				if !seen[kv[0]] {
					lb = append(lb, kv)
					seen[kv[0]] = true
				}
			}
			for i, k := range f.Labels {
				if i < len(smp.Values) && validLabelName(k) && !seen[k] {
					lb = append(lb, [2]string{k, smp.Values[i]})
					seen[k] = true
				}
			}
			sort.Slice(lb, func(i, j int) bool { return lb[i][0] < lb[j][0] })
			out = append(out, telemetrySeries{Name: f.Name, Type: f.Type, Labels: lb, Value: smp.Value, TimeMs: ts})
		}
	}
	return out
}

func validMetricName(n string) bool {
	if n == "" || len(n) > 200 {
		return false
	}
	for i, r := range n {
		if !(r == '_' || r == ':' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func validLabelName(n string) bool {
	if n == "" || len(n) > 100 || strings.HasPrefix(n, "__") {
		return false
	}
	for i, r := range n {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// handleEndpointMetrics serves every endpoint's latest batch in the
// Prometheus text format, behind the Prometheus integration's token (as
// /metrics is). Samples carry the time the agent collected them.
func (s *Server) handleEndpointMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.prometheusTokenOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	t := s.telemetrySettings(ctx)
	if !t.Scrape.Enabled {
		http.Error(w, "endpoint metrics are not served for scraping; turn it on under Administration → Telemetry", http.StatusNotFound)
		return
	}
	endpoints := s.telemetryEndpoints(ctx, t)
	h := s.telemetry
	h.mu.Lock()
	entries := make([]telemetryEntry, 0, len(h.latest))
	for _, e := range h.latest {
		if time.Since(e.Received) <= telemetryStale {
			entries = append(entries, e)
		}
	}
	h.mu.Unlock()
	series := upSeries(endpoints, s.telemetry.lastReceived(), time.Now())
	for _, e := range entries {
		if ep, ok := endpoints[e.AgentID]; ok && ep.InScope {
			series = append(series, expandBatch(e.Batch, ep.Labels)...)
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(formatExposition(series)))
}

// formatExposition writes series in the Prometheus text format, grouped by
// name (one TYPE line each) and with the agents' own timestamps, so a
// scrape does not restamp a sample that is fifteen seconds old.
func formatExposition(series []telemetrySeries) string {
	byName := map[string][]telemetrySeries{}
	types := map[string]string{}
	for _, sr := range series {
		byName[sr.Name] = append(byName[sr.Name], sr)
		types[sr.Name] = sr.Type
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		typ := types[n]
		if typ != "counter" {
			typ = "gauge"
		}
		fmt.Fprintf(&b, "# TYPE %s %s\n", n, typ)
		for _, sr := range byName[n] {
			b.WriteString(n)
			b.WriteByte('{')
			for i, kv := range sr.Labels {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(kv[0])
				b.WriteString(`="`)
				b.WriteString(promEscape(kv[1]))
				b.WriteByte('"')
			}
			b.WriteString("} ")
			b.WriteString(strconv.FormatFloat(sr.Value, 'g', -1, 64))
			b.WriteByte(' ')
			b.WriteString(strconv.FormatInt(sr.TimeMs, 10))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func promEscape(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// telemetryStatusRow is one endpoint's line on the console.
type telemetryStatusRow struct {
	AgentID  string    `json:"agent_id"`
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	Received time.Time `json:"received"`
	Series   int       `json:"series"`
}

func (s *Server) telemetryStatus(ctx context.Context) ([]telemetryStatusRow, telemetryStats) {
	agents, _ := s.store.ListAgents(ctx, s.staleAfter())
	byID := map[string]store.AgentRecord{}
	for _, a := range agents {
		byID[a.AgentID] = a
	}
	h := s.telemetry
	h.mu.Lock()
	defer h.mu.Unlock()
	rows := make([]telemetryStatusRow, 0, len(h.latest))
	for id, e := range h.latest {
		n := 0
		for _, f := range e.Batch.Families {
			n += len(f.Samples)
		}
		a := byID[id]
		rows = append(rows, telemetryStatusRow{AgentID: id, Hostname: a.Hostname, OS: a.OS, Received: e.Received, Series: n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Hostname < rows[j].Hostname })
	return rows, h.stats
}
