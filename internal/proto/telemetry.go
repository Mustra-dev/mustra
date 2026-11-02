package proto

import "time"

// Telemetry: host metrics (and, separately, logs) an agent sends for the
// server to forward to the operator's monitoring stack, Prometheus for
// metrics. It travels on beacon.telemetry.<agent>.*, which no JetStream
// stream captures: a metrics batch is superseded fifteen seconds later and
// is not worth a durable store.

// TelemetryConfig is what the server tells an agent to collect. The agent
// asks for it (SelfServiceRequest action "telemetry_config") when it starts
// and every few minutes; a server that does not know the action leaves
// telemetry off.
type TelemetryConfig struct {
	// Revision changes whenever anything below does.
	Revision string        `json:"revision"`
	Metrics  MetricsConfig `json:"metrics"`
}

// MetricsConfig says whether and how often to collect host metrics.
type MetricsConfig struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"`
	// Collectors names which families to collect; empty means all the
	// agent knows (see the metrics collectors in internal/agent).
	Collectors []string `json:"collectors,omitempty"`
}

// MetricsBatch is one collection of host metrics. Families use the
// node_exporter names, so dashboards and alert rules written for
// node_exporter work on them; the server adds the instance labels.
type MetricsBatch struct {
	AgentID   string         `json:"agent_id"`
	Timestamp time.Time      `json:"ts"`
	Families  []MetricFamily `json:"families"`
}

// MetricFamily is one metric name with its samples. Labels names the
// label keys once; each sample carries the values in that order, which
// keeps a batch from repeating "mountpoint" a hundred times.
type MetricFamily struct {
	Name    string         `json:"n"`
	Type    string         `json:"t"` // counter | gauge
	Help    string         `json:"h,omitempty"`
	Labels  []string       `json:"l,omitempty"`
	Samples []MetricSample `json:"s"`
}

// MetricSample is one series' value.
type MetricSample struct {
	Values []string `json:"l,omitempty"`
	Value  float64  `json:"v"`
}
