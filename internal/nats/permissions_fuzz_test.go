package nats

import "testing"

// everyAgentSubject returns every subject that names a single agent, built
// from the real builders so a new per-agent subject is covered the moment
// it is added to the permission set.
func everyAgentSubject(id string) []string {
	return []string{
		RegisterAgent(id), AgentHeartbeat(id), AgentFacts(id),
		AgentSensor(id, "processes"), AgentSensor(id, "custom_x"),
		AgentActionResult(id), AgentFileEvents(id), AgentProcessEvents(id),
		AgentRecorderEvents(id), ResultFrom("q-1", id), PatchListQuery(id),
		SelfService(id), CustomSensors(id), Cmd(id), Shell(id), QAgent(id),
		AgentInboxPrefix(id) + ".reply",
	}
}

// FuzzAgentPermissionIsolation is the property the whole per-agent-identity
// design rests on: an enrolled agent's broker grants cover its own subjects
// and never another agent's. It fuzzes two agent-id strings. Whenever both
// parse as valid, distinct IDs, none of A's publish or subscribe patterns
// may match any subject that names B — if one did, a compromised endpoint
// could publish telemetry as another, or read another's commands and shell.
// It also checks AgentPermissions rejects every malformed ID rather than
// minting a grant with a wildcard or separator spliced into a subject.
func FuzzAgentPermissionIsolation(f *testing.F) {
	f.Add("agt-0123456789abcdef0123456789abcdef", "agt-fedcba9876543210fedcba9876543210")
	f.Add("agt-00000000000000000000000000000000", "agt-00000000000000000000000000000001")
	f.Add("agt-*", "agt-0123456789abcdef0123456789abcdef")
	f.Add("agt->", "beacon.agent.x")
	f.Add("", "")
	f.Add("agt-0123456789abcdef0123456789abcdef.x", "agt-0123456789abcdef0123456789abcdef")

	f.Fuzz(func(t *testing.T, a, b string) {
		permsA, errA := AgentPermissions(a)
		if errA != nil {
			// A malformed ID must never yield a permission set.
			if !ValidAgentID(a) {
				return
			}
			t.Fatalf("valid id %q rejected: %v", a, errA)
		}
		if !ValidAgentID(a) {
			t.Fatalf("AgentPermissions minted a grant for invalid id %q", a)
		}
		// Every granted pattern must name A and nothing but A: no pattern
		// may match any subject belonging to a different valid agent B.
		if !ValidAgentID(b) || a == b {
			return
		}
		for _, subj := range everyAgentSubject(b) {
			if permits(permsA.PubAllow, subj) {
				t.Fatalf("agent %q may PUBLISH %q belonging to %q", a, subj, b)
			}
			if permits(permsA.SubAllow, subj) {
				t.Fatalf("agent %q may SUBSCRIBE %q belonging to %q", a, subj, b)
			}
		}
		// A's own private inbox must not be reachable by B's prefix, and
		// vice versa.
		if permits(permsA.SubAllow, AgentInboxPrefix(b)+".secret") {
			t.Fatalf("agent %q may read %q's inbox", a, b)
		}
		_ = permsA
	})
}

// FuzzEnrollUser fuzzes the enrolment username parser and the permission
// set built from the nonce it returns. The nonce is spliced into the
// connection's private inbox subject, so a parse that accepted anything but
// 32 hex characters could put a wildcard or separator there. Properties:
// ParseEnrollUser only accepts a 32-hex nonce; a nonce it accepts yields a
// permission set whose single subscribe subject is that connection's own
// inbox and nothing with a wildcard in the nonce position.
func FuzzEnrollUser(f *testing.F) {
	f.Add("mustra-enroll:0123456789abcdef0123456789abcdef")
	f.Add("mustra-legacy-enroll:0123456789abcdef0123456789abcdef")
	f.Add("mustra-enroll:*")
	f.Add("mustra-enroll:")
	f.Add("agt-0123456789abcdef0123456789abcdef")
	f.Fuzz(func(t *testing.T, user string) {
		nonce, legacy, ok := ParseEnrollUser(user)
		if !ok {
			return
		}
		if !enrollNoncePattern.MatchString(nonce) {
			t.Fatalf("ParseEnrollUser accepted non-hex nonce %q from %q", nonce, user)
		}
		p, err := EnrollPermissions(nonce, legacy)
		if err != nil {
			t.Fatalf("EnrollPermissions rejected an accepted nonce %q: %v", nonce, err)
		}
		// Exactly one subscribe subject: this connection's own inbox.
		want := EnrollInboxPrefix(nonce) + ".>"
		if len(p.SubAllow) != 1 || p.SubAllow[0] != want {
			t.Fatalf("enrol sub grants not the private inbox: %v (want %q)", p.SubAllow, want)
		}
		// The only publish subject is a fixed enrol subject, no nonce in it.
		for _, s := range p.PubAllow {
			if s != EnrollToken() && s != EnrollLegacy() {
				t.Fatalf("unexpected enrol publish grant %q", s)
			}
		}
	})
}
