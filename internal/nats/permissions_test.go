package nats

import (
	"os"
	"strings"
	"testing"
)

const (
	testAgentA = "agt-0123456789abcdef0123456789abcdef"
	testAgentB = "agt-fedcba9876543210fedcba9876543210"
)

func permits(patterns []string, subject string) bool {
	for _, p := range patterns {
		if subjectMatches(p, subject) {
			return true
		}
	}
	return false
}

// Every subject an enrolled agent publishes on must be granted, or the
// publish goes unacked and blocks the ordered outbox.
func TestAgentPermissionsCoverPublishedSubjects(t *testing.T) {
	p, err := AgentPermissions(testAgentA)
	if err != nil {
		t.Fatal(err)
	}
	for _, subj := range []string{
		RegisterAgent(testAgentA),
		AgentHeartbeat(testAgentA),
		AgentFacts(testAgentA),
		AgentSensor(testAgentA, "processes"),
		AgentSensor(testAgentA, "custom_abc"),
		AgentActionResult(testAgentA),
		AgentFileEvents(testAgentA),
		AgentProcessEvents(testAgentA),
		AgentRecorderEvents(testAgentA),
		ResultFrom("q-1", testAgentA),
		PatchListQuery(testAgentA),
		SelfService(testAgentA),
		CustomSensors(testAgentA),
		TelemetryMetrics(testAgentA),
	} {
		if !permits(p.PubAllow, subj) {
			t.Errorf("agent cannot publish its own %s", subj)
		}
	}
	for _, subj := range []string{Cmd(testAgentA), Shell(testAgentA), QAll(), QOS("linux"), QSite("default"), QAgent(testAgentA), AgentInboxPrefix(testAgentA) + ".x"} {
		if !permits(p.SubAllow, subj) {
			t.Errorf("agent cannot subscribe to its own %s", subj)
		}
	}
	if !p.AllowResponses {
		t.Error("agent cannot answer server requests")
	}
}

// The point of per-agent identity: nothing that names another agent.
func TestAgentPermissionsExcludeOtherAgents(t *testing.T) {
	p, _ := AgentPermissions(testAgentA)
	for _, subj := range []string{
		SubjectRegister, RegisterAgent(testAgentB),
		AgentHeartbeat(testAgentB), AgentFacts(testAgentB), AgentSensor(testAgentB, "processes"),
		AgentActionResult(testAgentB), AgentFileEvents(testAgentB), AgentProcessEvents(testAgentB),
		AgentRecorderEvents(testAgentB), Result("q-1"), ResultFrom("q-1", testAgentB),
		PatchListQuery(testAgentB), SelfService(testAgentB), CustomSensors(testAgentB), TelemetryMetrics(testAgentB),
		Cmd(testAgentB), Shell(testAgentB), "_INBOX.abc", AgentInboxPrefix(testAgentB) + ".x",
		EnrollToken(), EnrollLegacy(), "$JS.API.STREAM.DELETE.BEACON_AGENTS", AuthCalloutSubject,
	} {
		if permits(p.PubAllow, subj) {
			t.Errorf("agent A may publish %s", subj)
		}
	}
	for _, subj := range []string{
		Cmd(testAgentB), Shell(testAgentB), QAgent(testAgentB), "_INBOX.abc",
		ServerInboxPrefix + ".abc", AgentInboxPrefix(testAgentB) + ".x", "beacon.cmd.*", "beacon.agent.*.facts", AuthCalloutSubject,
	} {
		if permits(p.SubAllow, subj) {
			t.Errorf("agent A may subscribe to %s", subj)
		}
	}
}

func TestAgentPermissionsRejectBadIDs(t *testing.T) {
	for _, id := range []string{"", "agt-*", "agt->", "agt-123", "agt-0123456789abcdef0123456789abcdef.x", "../etc", "AGT-0123456789ABCDEF0123456789ABCDEF"} {
		if _, err := AgentPermissions(id); err == nil {
			t.Errorf("accepted agent id %q", id)
		}
	}
}

func TestEnrollPermissions(t *testing.T) {
	nonce := strings.Repeat("ab", 16)
	p, err := EnrollPermissions(nonce, false)
	if err != nil {
		t.Fatal(err)
	}
	if !permits(p.PubAllow, EnrollToken()) || permits(p.PubAllow, EnrollLegacy()) || len(p.PubAllow) != 1 {
		t.Errorf("token enrolment publish set wrong: %v", p.PubAllow)
	}
	if !permits(p.SubAllow, EnrollInboxPrefix(nonce)+".x") || permits(p.SubAllow, "_INBOX.x") || permits(p.SubAllow, EnrollInboxPrefix(strings.Repeat("cd", 16))+".x") {
		t.Errorf("enrolment subscribe set wrong: %v", p.SubAllow)
	}
	if p.AllowResponses {
		t.Error("an enrolment connection answers nothing")
	}
	lp, _ := EnrollPermissions(nonce, true)
	if !permits(lp.PubAllow, EnrollLegacy()) || permits(lp.PubAllow, EnrollToken()) {
		t.Errorf("legacy enrolment publish set wrong: %v", lp.PubAllow)
	}
	if _, err := EnrollPermissions("x.>", false); err == nil {
		t.Error("accepted a wildcard nonce")
	}
}

func TestParseEnrollUser(t *testing.T) {
	nonce := strings.Repeat("0f", 16)
	if n, legacy, ok := ParseEnrollUser(EnrollUser(nonce)); !ok || legacy || n != nonce {
		t.Errorf("EnrollUser round trip: %q %v %v", n, legacy, ok)
	}
	if n, legacy, ok := ParseEnrollUser(LegacyEnrollUser(nonce)); !ok || !legacy || n != nonce {
		t.Errorf("LegacyEnrollUser round trip: %q %v %v", n, legacy, ok)
	}
	for _, u := range []string{"mustra-enroll:", "mustra-enroll:*", "mustra-enroll:" + nonce + ".x", LegacyAgentUser, testAgentA} {
		if _, _, ok := ParseEnrollUser(u); ok {
			t.Errorf("parsed %q as an enrolment user", u)
		}
	}
}

// The legacy set must keep working for agents that predate enrolment,
// but no longer publishes into the shared inbox namespace.
func TestLegacyPermissions(t *testing.T) {
	p := LegacyAgentPermissions()
	for _, subj := range []string{SubjectRegister, AgentHeartbeat(testAgentA), AgentSensor(testAgentB, "disks"), Result("q-1"), SelfService(testAgentA)} {
		if !permits(p.PubAllow, subj) {
			t.Errorf("legacy agent cannot publish %s", subj)
		}
	}
	for _, subj := range []string{"_INBOX.x", ServerInboxPrefix + ".x", AgentInboxPrefix(testAgentA) + ".x", EnrollToken(), EnrollLegacy(), Cmd(testAgentA)} {
		if permits(p.PubAllow, subj) {
			t.Errorf("legacy agent may publish %s", subj)
		}
	}
	for _, subj := range []string{ServerInboxPrefix + ".x", AgentInboxPrefix(testAgentA) + ".x", EnrollInboxPrefix(strings.Repeat("ab", 16)) + ".x"} {
		if permits(p.SubAllow, subj) {
			t.Errorf("legacy agent may read %s", subj)
		}
	}
	if !p.AllowResponses {
		t.Error("legacy agent cannot answer server requests")
	}
}

func TestSubjectAttribution(t *testing.T) {
	if id, ok := AgentIDFromSubject(AgentSensor(testAgentA, "processes")); !ok || id != testAgentA {
		t.Errorf("AgentIDFromSubject: %q %v", id, ok)
	}
	for _, s := range []string{"beacon.agent.x.facts", "beacon.agent", "beacon.cmd." + testAgentA, "beacon.agent." + testAgentA} {
		if _, ok := AgentIDFromSubject(s); ok {
			t.Errorf("attributed %q", s)
		}
	}
	if id, ok := ResultAgentFromSubject(ResultFrom("q-1", testAgentB)); !ok || id != testAgentB {
		t.Errorf("ResultAgentFromSubject: %q %v", id, ok)
	}
	if _, ok := ResultAgentFromSubject(Result("q-1")); ok {
		t.Error("legacy result subject attributed")
	}
	if !subjectMatches(ResultWildcard(), Result("q-1")) || !subjectMatches(ResultWildcard(), ResultFrom("q-1", testAgentA)) {
		t.Error("server result subscription misses a result form")
	}
	if !subjectMatches(RegisterAgentWildcard(), RegisterAgent(testAgentA)) {
		t.Error("server register subscription misses the per-agent form")
	}
}

// While the shared credential is still accepted, its holder must not reach
// an agent that has already enrolled.
func TestLegacyPermissionsDenyEnrolledAgents(t *testing.T) {
	p := LegacyAgentPermissionsExcept([]string{testAgentA, "not-an-id"})
	effective := func(allow, deny []string, subj string) bool { return permits(allow, subj) && !permits(deny, subj) }
	for _, subj := range []string{AgentHeartbeat(testAgentA), AgentSensor(testAgentA, "processes"), AgentActionResult(testAgentA),
		SelfService(testAgentA), ResultFrom("q", testAgentA)} {
		if effective(p.PubAllow, p.PubDeny, subj) {
			t.Errorf("legacy holder may still publish %s for an enrolled agent", subj)
		}
	}
	for _, subj := range []string{Cmd(testAgentA), Shell(testAgentA), QAgent(testAgentA)} {
		if effective(p.SubAllow, p.SubDeny, subj) {
			t.Errorf("legacy holder may still subscribe to %s of an enrolled agent", subj)
		}
	}
	// An agent that has not enrolled keeps working.
	if !effective(p.PubAllow, p.PubDeny, AgentHeartbeat(testAgentB)) || !effective(p.SubAllow, p.SubDeny, Cmd(testAgentB)) {
		t.Error("legacy agents that have not enrolled lost their own subjects")
	}
	for _, d := range append(p.PubDeny, p.SubDeny...) {
		if strings.Contains(d, "not-an-id") {
			t.Error("a malformed ID reached the deny list")
		}
	}
}

// The broker refuses the server's own user every agent-only subject, so a
// reply the server publishes to a subject an agent chose cannot land on
// another agent's reports. The list lives in two places; keep them equal.
func TestNATSConfServerDeniesAgentSubjects(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/nats/nats.conf")
	if err != nil {
		t.Fatal(err)
	}
	conf := string(raw)
	start := strings.Index(conf, `user: "mustra-server"`)
	end := strings.Index(conf, "auth_callout")
	if start < 0 || end < start {
		t.Fatal("nats.conf: mustra-server user block not found")
	}
	block := conf[start:end]
	for _, subj := range ServerPublishDeny() {
		if !strings.Contains(block, `"`+subj+`"`) {
			t.Errorf("nats.conf does not deny the server publishing %q", subj)
		}
	}
	// Every agent-published subject is covered by some deny.
	id := "agt-0123456789abcdef0123456789abcdef"
	perms, err := AgentPermissions(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, pub := range perms.PubAllow {
		if strings.HasPrefix(pub, "$JS.API.") {
			continue
		}
		covered := false
		for _, d := range ServerPublishDeny() {
			if subjectCoveredBy(pub, d) {
				covered = true
			}
		}
		if !covered {
			t.Errorf("agent-published %q is not denied to the server's user", pub)
		}
	}
}

// subjectCoveredBy reports whether every subject matching pattern p also
// matches the deny pattern d.
func subjectCoveredBy(p, d string) bool {
	pt, dt := strings.Split(p, "."), strings.Split(d, ".")
	for i, tok := range dt {
		if tok == ">" {
			return len(pt) > i
		}
		if i >= len(pt) {
			return false
		}
		if tok != "*" && tok != pt[i] {
			return false
		}
	}
	return len(pt) == len(dt)
}
