package nats

import (
	"fmt"
	"regexp"
	"strings"
)

// Broker permissions for everything that is not the server.
//
// They used to live in deploy/nats/nats.conf as one static role shared by
// every agent, with the agent ID in a "*" wildcard: any holder of the one
// agent password could publish as, and subscribe to, every other agent.
// Now the control plane answers the broker's auth callout and hands each
// connection a user JWT whose permissions are built here, from the
// identity it actually proved. The subject lists are derived from the
// builders in subjects.go — a subject an agent publishes on but is not
// granted here does not fail loudly, the publish just goes unacked, and on
// the durable outbox that blocks everything queued behind it. So a new
// agent-published subject belongs here at the same time it is added to
// subjects.go, and TestAgentPermissionsCoverPublishedSubjects checks it.

// Permissions is a broker permission set, independent of the JWT library
// so the agent side never needs it.
type Permissions struct {
	PubAllow []string
	SubAllow []string
	// PubDeny and SubDeny carve exceptions out of the allows; used to keep
	// a legacy shared-credential holder away from enrolled agents.
	PubDeny []string
	SubDeny []string
	// AllowResponses lets the connection publish exactly one reply to the
	// reply subject of each request it receives — how an agent answers a
	// command or a shell request without being able to publish into
	// anybody's inbox at will.
	AllowResponses bool
}

// AgentInboxPrefix is the private inbox prefix an enrolled agent uses for
// its own requests (nats.CustomInboxPrefix). It sits outside "_INBOX.>" on
// purpose: an agent still on the legacy shared credential may subscribe to
// "_INBOX.>", and must not be able to read replies meant for this one.
func AgentInboxPrefix(agentID string) string { return "_INBOX_" + agentID }

// ServerInboxPrefix is the server's own inbox prefix, outside "_INBOX.>"
// for the same reason: replies from enrolled agents to the server's
// requests (shell output, command results) must not be readable by a
// legacy credential holder subscribed to "_INBOX.>".
const ServerInboxPrefix = "_INBOX_SRV"

// enrollNoncePattern is the per-connection nonce an enrolment connection
// carries in its username, and so in its inbox prefix.
var enrollNoncePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Usernames of the connections that are not an enrolled agent. An enrolled
// agent's username is its agent ID.
const (
	// LegacyAgentUser is the shared agent account every pre-enrolment
	// install carries. Accepted only while the operator allows it.
	LegacyAgentUser = "mustra-agent"
	// enrollUserPrefix starts the username of a connection that presents
	// an enrollment token as its password: "mustra-enroll:<nonce>".
	enrollUserPrefix = "mustra-enroll:"
	// legacyEnrollUserPrefix starts the username of a connection that
	// presents the legacy shared password to exchange it for an identity
	// of its own: "mustra-legacy-enroll:<nonce>".
	legacyEnrollUserPrefix = "mustra-legacy-enroll:"
)

// EnrollUser and LegacyEnrollUser build enrolment usernames; ParseEnrollUser
// is their inverse, returning the nonce and whether it is the legacy kind.
func EnrollUser(nonce string) string       { return enrollUserPrefix + nonce }
func LegacyEnrollUser(nonce string) string { return legacyEnrollUserPrefix + nonce }

func ParseEnrollUser(user string) (nonce string, legacy bool, ok bool) {
	switch {
	case strings.HasPrefix(user, enrollUserPrefix):
		nonce = strings.TrimPrefix(user, enrollUserPrefix)
	case strings.HasPrefix(user, legacyEnrollUserPrefix):
		nonce, legacy = strings.TrimPrefix(user, legacyEnrollUserPrefix), true
	default:
		return "", false, false
	}
	if !enrollNoncePattern.MatchString(nonce) {
		return "", false, false
	}
	return nonce, legacy, true
}

// EnrollInboxPrefix is the inbox of one enrolment connection. Private to
// that connection because the reply carries the agent's new secret.
func EnrollInboxPrefix(nonce string) string { return "_INBOX_ENROLL_" + nonce }

// IsEnrollInbox reports whether subject lies inside some enrolment
// connection's inbox: EnrollInboxPrefix(<well-formed nonce>) followed by at
// least one more token. The server answers enrolment requests only there.
func IsEnrollInbox(subject string) bool {
	const p = "_INBOX_ENROLL_"
	if !strings.HasPrefix(subject, p) {
		return false
	}
	rest := subject[len(p):]
	nonce, tail, found := strings.Cut(rest, ".")
	return found && tail != "" && enrollNoncePattern.MatchString(nonce)
}

// AgentPermissions is everything one enrolled agent may do, and nothing it
// may do on another agent's behalf: every subject that names an agent names
// this one.
func AgentPermissions(agentID string) (Permissions, error) {
	if !ValidAgentID(agentID) {
		return Permissions{}, fmt.Errorf("invalid agent id %q", agentID)
	}
	return Permissions{
		PubAllow: []string{
			// Registration, bound to this identity by the subject.
			RegisterAgent(agentID),
			// Self-reporting. These land in the agent JetStream stream, and a
			// denied one blocks the ordered outbox (see the package comment).
			AgentHeartbeat(agentID),
			AgentFacts(agentID),
			AgentSensor(agentID, "*"),
			AgentActionResult(agentID),
			AgentFileEvents(agentID),
			AgentProcessEvents(agentID),
			AgentRecorderEvents(agentID),
			// Telemetry for the operator's monitoring stack; not stored.
			TelemetryMetrics(agentID),
			// Answers to fleet questions, in the form that names the sender.
			ResultFrom("*", agentID),
			// Agent-initiated request/reply: the agent is the requester.
			PatchListQuery(agentID),
			SelfService(agentID),
			CustomSensors(agentID),
			// JetStream discovery only. Deliberately not "$JS.API.>": that
			// would let an agent delete the streams the fleet reports through.
			"$JS.API.INFO",
			"$JS.API.STREAM.INFO.*",
		},
		SubAllow: []string{
			// Work sent to this agent, and only this agent.
			Cmd(agentID),
			Shell(agentID),
			// Fleet questions. All, by-OS and by-site are broadcasts every
			// agent receives anyway; by-agent is this one only.
			QAll(),
			"beacon.q.os.*",
			"beacon.q.site.>",
			QAgent(agentID),
			// Replies to this agent's own requests (and JetStream acks).
			AgentInboxPrefix(agentID) + ".>",
		},
		// Replies to the server's requests (cmd, shell).
		AllowResponses: true,
	}, nil
}

// EnrollPermissions is what a connection holding an enrollment token (or,
// legacy, the shared password) may do before it has an identity: ask for
// one, and hear the answer on its own inbox. Nothing else.
func EnrollPermissions(nonce string, legacy bool) (Permissions, error) {
	if !enrollNoncePattern.MatchString(nonce) {
		return Permissions{}, fmt.Errorf("invalid enrolment nonce")
	}
	subject := EnrollToken()
	if legacy {
		subject = EnrollLegacy()
	}
	return Permissions{
		PubAllow: []string{subject},
		SubAllow: []string{EnrollInboxPrefix(nonce) + ".>"},
	}, nil
}

// LegacyAgentPermissionsExcept is LegacyAgentPermissions with every subject
// that names one of the enrolled agents denied: while the shared password
// is still accepted, its holder can act as an agent that has not enrolled,
// but can no longer read an enrolled agent's commands or shell traffic, or
// report in its name.
func LegacyAgentPermissionsExcept(enrolled []string) Permissions {
	p := LegacyAgentPermissions()
	for _, id := range enrolled {
		if !ValidAgentID(id) {
			continue
		}
		p.PubDeny = append(p.PubDeny, "beacon.agent."+id+".>", PatchListQuery(id), SelfService(id), CustomSensors(id), "beacon.r.*."+id)
		p.SubDeny = append(p.SubDeny, Cmd(id), Shell(id), QAgent(id))
	}
	return p
}

// LegacyAgentPermissions is the old shared AGENT_PERMS from nats.conf,
// unchanged, for agents that have not enrolled yet. Any holder of the
// shared password can act as any agent with these; that is the exposure
// the transition exists to end, and why the operator can turn it off.
func LegacyAgentPermissions() Permissions {
	return Permissions{
		PubAllow: []string{
			SubjectRegister,
			AgentHeartbeatWildcard(),
			AgentFactsWildcard(),
			AgentSensorWildcard(),
			AgentActionResultWildcard(),
			"beacon.r.*",
			PatchListQueryWildcard(),
			SelfServiceWildcard(),
			CustomSensorsWildcard(),
			AgentFileEventsWildcard(),
			AgentProcessEventsWildcard(),
			AgentRecorderEventsWildcard(),
			// No "_INBOX.>" any more. It was how an agent answered the
			// server's requests, and it also let any holder of this
			// password publish forged replies into every inbox on the bus.
			// Replies now go through AllowResponses, which admits exactly
			// one publish to the reply subject of a request this connection
			// actually received.
			"$JS.API.INFO",
			"$JS.API.STREAM.INFO.*",
		},
		SubAllow: []string{
			"beacon.cmd.*",
			"beacon.shell.*",
			"beacon.q.>",
			"_INBOX.>",
		},
		AllowResponses: true,
	}
}

// ServerPublishDeny is what the control plane's own broker user may not
// publish: every subject only agents (or enrolling connections) send on.
// The server never publishes there itself, and a reply subject an agent
// chose is published with the server's rights — so these denies stop a
// reflected reply from ever landing on another agent's ingested subjects,
// even if a responder forgot to check it. deploy/nats/nats.conf carries
// the same list; TestNATSConfServerDeniesAgentSubjects keeps them equal.
func ServerPublishDeny() []string {
	return []string{
		"beacon.agent.>",
		SubjectRegister,
		SubjectRegister + ".>",
		ResultWildcard(),
		"beacon.patchlist.>",
		"beacon.selfservice.>",
		"beacon.customsensors.>",
		"beacon.telemetry.>",
		"beacon.enroll.>",
	}
}
