package nats

import "testing"

func TestSubjectBuilders(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"QAll", QAll(), "beacon.q.all"},
		{"QOS", QOS("windows"), "beacon.q.os.windows"},
		{"QSite", QSite("branch-1"), "beacon.q.site.branch-1"},
		{"QAgent", QAgent("agt-123"), "beacon.q.agent.agt-123"},
		{"Register", Register(), "beacon.register"},
		{"AgentHeartbeat", AgentHeartbeat("agt-123"), "beacon.agent.agt-123.heartbeat"},
		{"AgentFacts", AgentFacts("agt-123"), "beacon.agent.agt-123.facts"},
		{"AgentWildcard", AgentWildcard(), "beacon.agent.*.>"},
		{"AgentHeartbeatWildcard", AgentHeartbeatWildcard(), "beacon.agent.*.heartbeat"},
		{"AgentFactsWildcard", AgentFactsWildcard(), "beacon.agent.*.facts"},
		{"AgentSensor", AgentSensor("agt-123", "processes"), "beacon.agent.agt-123.sensor.processes"},
		{"AgentSensorWildcard", AgentSensorWildcard(), "beacon.agent.*.sensor.*"},
		{"Cmd", Cmd("agt-123"), "beacon.cmd.agt-123"},
		{"Result", Result("q-456"), "beacon.r.q-456"},
		{"ResultWildcard", ResultWildcard(), "beacon.r.>"},
		{"AgentActionResult", AgentActionResult("agt-123"), "beacon.agent.agt-123.actionresult"},
		{"AgentActionResultWildcard", AgentActionResultWildcard(), "beacon.agent.*.actionresult"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("got %q, want %q", c.got, c.want)
			}
		})
	}
}

// TestAgentSubjectsMatchWildcards guards the actual invariant the server
// relies on: its wildcard subscriptions must match what agents publish.
func TestAgentSubjectsMatchWildcards(t *testing.T) {
	agentID := "agt-789"
	if !subjectMatches(AgentHeartbeatWildcard(), AgentHeartbeat(agentID)) {
		t.Errorf("AgentHeartbeatWildcard %q does not match AgentHeartbeat %q", AgentHeartbeatWildcard(), AgentHeartbeat(agentID))
	}
	if !subjectMatches(AgentFactsWildcard(), AgentFacts(agentID)) {
		t.Errorf("AgentFactsWildcard %q does not match AgentFacts %q", AgentFactsWildcard(), AgentFacts(agentID))
	}
	if !subjectMatches(AgentSensorWildcard(), AgentSensor(agentID, "processes")) {
		t.Errorf("AgentSensorWildcard %q does not match AgentSensor %q", AgentSensorWildcard(), AgentSensor(agentID, "processes"))
	}
	if !subjectMatches(AgentWildcard(), AgentSensor(agentID, "processes")) {
		t.Errorf("AgentWildcard %q does not match AgentSensor %q", AgentWildcard(), AgentSensor(agentID, "processes"))
	}
	if !subjectMatches(AgentWildcard(), AgentHeartbeat(agentID)) {
		t.Errorf("AgentWildcard %q does not match AgentHeartbeat %q", AgentWildcard(), AgentHeartbeat(agentID))
	}
	// Load-bearing: action results are published through JetStream, whose
	// stream is defined as AgentWildcard(). A subject outside it would be
	// accepted by the publisher and then silently never delivered.
	if !subjectMatches(AgentActionResultWildcard(), AgentActionResult(agentID)) {
		t.Errorf("AgentActionResultWildcard %q does not match AgentActionResult %q", AgentActionResultWildcard(), AgentActionResult(agentID))
	}
	if !subjectMatches(AgentWildcard(), AgentActionResult(agentID)) {
		t.Errorf("AgentWildcard %q does not match AgentActionResult %q", AgentWildcard(), AgentActionResult(agentID))
	}
	if !subjectMatches(ResultWildcard(), Result("q-1")) {
		t.Errorf("ResultWildcard %q does not match Result %q", ResultWildcard(), Result("q-1"))
	}
}

// subjectMatches is a tiny NATS-subject matcher (supports '*' single-token
// and trailing '>' multi-token wildcards) good enough for this test.
func subjectMatches(pattern, subject string) bool {
	pt := splitSubject(pattern)
	st := splitSubject(subject)
	for i, p := range pt {
		if p == ">" {
			return len(st) > i // ">" needs at least one more token
		}
		if i >= len(st) {
			return false
		}
		if p != "*" && p != st[i] {
			return false
		}
	}
	return len(pt) == len(st)
}

func splitSubject(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
