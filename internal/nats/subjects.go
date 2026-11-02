// Package nats centralizes every NATS subject string and connection/
// JetStream helper used by mustra. No other package should hand-build a
// subject string — always call a builder from here so the addressing scheme
// stays in exactly one place.
package nats

import (
	"fmt"
	"regexp"
	"strings"
)

// The subject namespace is still "beacon.*" after the project was renamed
// to mustra. These strings are a wire protocol: every deployed agent is
// subscribed to them right now, and renaming would make the whole fleet go
// deaf until each one is reinstalled — for a prefix nobody ever sees. If
// it ever needs to change, do it as a dual-subscribe migration (server
// listens on both, agents publish the new one) rather than a flag day.

// SubjectRegister is where agents send RegisterRequest via request/reply.
const SubjectRegister = "beacon.register"

// QAll returns the subject every agent subscribes to.
func QAll() string { return "beacon.q.all" }

// QOS returns the subject for agents running a given OS (runtime.GOOS value,
// e.g. "windows", "linux", "darwin").
func QOS(os string) string { return fmt.Sprintf("beacon.q.os.%s", os) }

// QSite returns the subject for agents at a given site.
func QSite(site string) string { return fmt.Sprintf("beacon.q.site.%s", site) }

// QAgent returns the subject for a single agent by ID.
func QAgent(agentID string) string { return fmt.Sprintf("beacon.q.agent.%s", agentID) }

// Register returns the legacy registration request/reply subject. It
// carries no identity — anyone allowed to publish on it can claim any
// agent_id — so the server accepts it only from agents still on the shared
// credential, and only for IDs that have not enrolled (registration.go).
func Register() string { return SubjectRegister }

// RegisterAgent is the per-agent registration subject. The broker grants
// publish on it only to the connection authenticated as agentID, which is
// what binds a registration to the identity that sent it.
func RegisterAgent(agentID string) string { return SubjectRegister + "." + agentID }

// RegisterAgentWildcard is the server's subscription for RegisterAgent.
func RegisterAgentWildcard() string { return SubjectRegister + ".*" }

// EnrollToken is where a new agent exchanges an enrollment token for its
// own credential. Only a connection that authenticated with a currently
// valid token may publish here (see EnrollPermissions).
func EnrollToken() string { return "beacon.enroll.token" }

// EnrollLegacy is where an agent still holding the shared credential asks
// for its own. Published only by the short-lived legacy enrolment
// connection, and only while the operator allows the shared credential.
func EnrollLegacy() string { return "beacon.enroll.legacy" }

// AuthCalloutSubject is where nats-server asks the control plane to decide
// a connection (nats-server auth callout). Only the server's own user,
// which bypasses the callout, can subscribe to it.
const AuthCalloutSubject = "$SYS.REQ.USER.AUTH"

// agentIDPattern is the only shape an agent ID may have: what idgen mints
// for "agt-". Checked anywhere an ID arrives from the network, because the
// ID is spliced into NATS subjects (where "." or "*" would change their
// meaning) and into filesystem paths (where ".." would).
var agentIDPattern = regexp.MustCompile(`^agt-[0-9a-f]{32}$`)

// ValidAgentID reports whether id is a well-formed agent ID.
func ValidAgentID(id string) bool { return agentIDPattern.MatchString(id) }

// AgentIDFromSubject returns the agent ID of a beacon.agent.<id>.<kind>...
// subject — the identity the broker enforced for whoever published it —
// and false if the subject is not of that shape or the ID is malformed.
func AgentIDFromSubject(subject string) (string, bool) {
	parts := strings.Split(subject, ".")
	if len(parts) < 4 || parts[0] != "beacon" || parts[1] != "agent" {
		return "", false
	}
	if !ValidAgentID(parts[2]) {
		return "", false
	}
	return parts[2], true
}

// AgentHeartbeat returns the subject an agent publishes heartbeats to.
func AgentHeartbeat(agentID string) string {
	return fmt.Sprintf("beacon.agent.%s.heartbeat", agentID)
}

// AgentFacts returns the subject an agent publishes fact snapshots to.
func AgentFacts(agentID string) string {
	return fmt.Sprintf("beacon.agent.%s.facts", agentID)
}

// AgentWildcard returns the subject filter matching every per-agent subject
// (heartbeat, facts, and future additions) across all agents. Used to size
// the JetStream stream that captures agent-originated messages.
func AgentWildcard() string { return "beacon.agent.*.>" }

// AgentHeartbeatWildcard matches every agent's heartbeat subject. Used by the
// server's heartbeat consumer.
func AgentHeartbeatWildcard() string { return "beacon.agent.*.heartbeat" }

// AgentFactsWildcard matches every agent's facts subject. Used by the
// server's facts consumer.
func AgentFactsWildcard() string { return "beacon.agent.*.facts" }

// AgentSensor returns the subject an agent publishes a periodic sensor
// snapshot to (see proto.SensorKind).
func AgentSensor(agentID string, sensor string) string {
	return fmt.Sprintf("beacon.agent.%s.sensor.%s", agentID, sensor)
}

// AgentSensorWildcard matches every agent's every sensor subject. Used by
// the server's single sensor-snapshot consumer.
func AgentSensorWildcard() string { return "beacon.agent.*.sensor.*" }

// Cmd returns the targeted-command request/reply subject for a single
// agent — operational control (e.g. adjusting a sensor's publish interval)
// as opposed to a fleet-wide query.
func Cmd(agentID string) string { return fmt.Sprintf("beacon.cmd.%s", agentID) }

// PatchListQuery returns the subject an agent uses to ask the server which
// patch-list repo scoping (if any) applies to it — request/reply in the
// opposite direction of Cmd: the agent is the requester here, since this is
// driven by the agent's own periodic sensor timer, not a server-initiated
// action.
func PatchListQuery(agentID string) string { return fmt.Sprintf("beacon.patchlist.%s", agentID) }

// SelfService returns the subject an agent uses to ask the server about
// its own catalog and history, and to request an install. Agent-initiated,
// like PatchListQuery.
func SelfService(agentID string) string { return fmt.Sprintf("beacon.selfservice.%s", agentID) }

// Shell is the per-agent subject for an interactive command session. One
// subject per agent, with the session ID inside the message rather than in
// the subject, so an agent needs exactly one subscription no matter how
// many sessions it serves.
func Shell(agentID string) string { return "beacon.shell." + agentID }

// ShellWildcard subscribes the server to every agent's shell subject.
func ShellWildcard() string { return "beacon.shell.*" }

// SelfServiceWildcard matches every agent's Self Service subject.
func SelfServiceWildcard() string { return "beacon.selfservice.*" }

// PatchListQueryWildcard matches every agent's patch-list-query subject.
// Used once by the server at startup to open a single subscription instead
// of one per agent.
func PatchListQueryWildcard() string { return "beacon.patchlist.*" }

// Result returns the legacy subject an agent publishes a QueryResult to:
// keyed by query only, so the server cannot tell from the subject who sent
// it. Agents holding the old shared credential still use it; an agent with
// its own credential uses ResultFrom instead.
func Result(queryID string) string { return fmt.Sprintf("beacon.r.%s", queryID) }

// ResultFrom is the per-agent result subject: the answering agent's ID is
// the last token, and the broker only lets that agent publish there (see
// AgentPermissions), so the server attributes the result from the subject
// rather than from the agent_id field the sender wrote itself.
func ResultFrom(queryID, agentID string) string {
	return fmt.Sprintf("beacon.r.%s.%s", queryID, agentID)
}

// ResultWildcard matches every query's result subject, both the legacy
// three-token form and the per-agent four-token form. Used once by the
// server at startup to open a single long-lived subscription instead of one
// subscription per query.
func ResultWildcard() string { return "beacon.r.>" }

// ResultAgentFromSubject returns the agent ID carried by a per-agent result
// subject, and false for the legacy form (or anything malformed).
func ResultAgentFromSubject(subject string) (string, bool) {
	parts := strings.Split(subject, ".")
	if len(parts) != 4 || parts[0] != "beacon" || parts[1] != "r" {
		return "", false
	}
	if !ValidAgentID(parts[3]) {
		return "", false
	}
	return parts[3], true
}

// AgentActionResult returns the subject an agent publishes the final
// outcome of a long-running action to. Commands like apply_patches
// acknowledge immediately and finish minutes or hours later, so the reply
// to the command can only ever say "started" — this is how the real result
// gets back. It sits under the beacon.agent.* prefix deliberately, so the
// existing agent stream (AgentWildcard) captures it and a result survives
// the server being restarted mid-patch.
func AgentActionResult(agentID string) string {
	return fmt.Sprintf("beacon.agent.%s.actionresult", agentID)
}

// AgentActionResultWildcard matches every agent's action-result subject.
// Used by the server's single action-result consumer.
func AgentActionResultWildcard() string { return "beacon.agent.*.actionresult" }

// CustomSensors returns the subject an agent uses to ask which custom
// sensors apply to it. Agent-initiated request/reply, like PatchListQuery:
// collection is driven by the agent's own timer, so the agent asks rather
// than the server pushing.
func CustomSensors(agentID string) string {
	return fmt.Sprintf("beacon.customsensors.%s", agentID)
}

// CustomSensorsWildcard matches every agent's custom-sensor query subject.
func CustomSensorsWildcard() string { return "beacon.customsensors.*" }

// AgentFileEvents carries real-time filesystem events — a change reported
// as it happens rather than at the next hash sweep. Under beacon.agent.*
// so it lands in the same JetStream stream as heartbeats and sensor
// snapshots: a security event that evaporates on a reconnect is the one
// you most needed to keep.
func AgentFileEvents(agentID string) string {
	return fmt.Sprintf("beacon.agent.%s.fileevents", agentID)
}

// AgentFileEventsWildcard is the server-side subscription.
func AgentFileEventsWildcard() string { return "beacon.agent.*.fileevents" }

// AgentProcessEvents carries process starts as they happen — the other
// half of real-time detection, alongside file events.
func AgentProcessEvents(agentID string) string {
	return fmt.Sprintf("beacon.agent.%s.procevents", agentID)
}

// AgentProcessEventsWildcard is the server-side subscription.
func AgentProcessEventsWildcard() string { return "beacon.agent.*.procevents" }

// AgentRecorderEvents carries registry, network, DNS and logon events as
// they happen; the third real-time feed beside file and process events.
func AgentRecorderEvents(agentID string) string {
	return fmt.Sprintf("beacon.agent.%s.recevents", agentID)
}

// AgentRecorderEventsWildcard is the server-side subscription.
func AgentRecorderEventsWildcard() string { return "beacon.agent.*.recevents" }

// TelemetryMetrics carries an agent's host metrics batches. Deliberately
// outside beacon.agent.*: the agent stream would keep every batch, and a
// metrics batch is worthless fifteen seconds later.
func TelemetryMetrics(agentID string) string {
	return fmt.Sprintf("beacon.telemetry.%s.metrics", agentID)
}

// TelemetryMetricsWildcard matches every agent's metrics subject; the
// server's one subscription.
func TelemetryMetricsWildcard() string { return "beacon.telemetry.*.metrics" }

// TelemetryAgentID returns the agent a beacon.telemetry.<agent>.* subject
// names. The broker only lets an agent publish on its own, so the subject,
// not the message body, says who sent it.
func TelemetryAgentID(subject string) (string, bool) {
	parts := strings.Split(subject, ".")
	if len(parts) != 4 || parts[0] != "beacon" || parts[1] != "telemetry" || !ValidAgentID(parts[2]) {
		return "", false
	}
	return parts[2], true
}
