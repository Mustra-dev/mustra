package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestAgentSetUnionsGroups(t *testing.T) {
	members := map[string]map[string]bool{
		"g1": {"a": true, "b": true},
		"g2": {"b": true, "c": true},
		"g3": {},
	}
	got := agentSet(members, []string{"g1", "g2"})
	if len(got) != 3 || !got["a"] || !got["b"] || !got["c"] {
		t.Fatalf("union: %v", got)
	}
	if len(agentSet(members, []string{"g3"})) != 0 {
		t.Fatal("an empty group contributes nothing")
	}
	if len(agentSet(members, []string{"missing"})) != 0 {
		t.Fatal("an unknown group must not panic or invent members")
	}
	// The distinction the whole feature rests on: no groups is not the same
	// as a group that matches nothing. Callers read nil as unrestricted.
	if len(agentSet(members, nil)) != 0 {
		t.Fatal("no groups selects nothing here; unrestricted is signalled by a nil map from the caller")
	}
}

func TestPolicyTouchesAnyCoveredEndpoint(t *testing.T) {
	covered := map[string]bool{"dc01": true, "dc02": true}
	if !policyTouches([]string{"laptop1", "laptop2", "dc01"}, covered) {
		t.Fatal("one covered endpoint among many must trigger the policy")
	}
	if policyTouches([]string{"laptop1", "laptop2"}, covered) {
		t.Fatal("no covered endpoint must not trigger it")
	}
	if policyTouches(nil, covered) {
		t.Fatal("an empty target list touches nothing")
	}
}

func TestValidModule(t *testing.T) {
	for _, m := range []string{"deploy", "patches", "playbooks", "shell", "enforce", "reveal"} {
		if !validModule(m) {
			t.Errorf("%q should be a module", m)
		}
	}
	for _, m := range []string{"", "Deploy", "everything", "integrity"} {
		if validModule(m) {
			t.Errorf("%q should not be a module", m)
		}
	}
}

// A replay registry entry has to exist for every module an approval policy
// will accept, or approving would park work nobody can resume.
func TestEveryGateableModuleHasAReplayHandler(t *testing.T) {
	s := &Server{}
	reg := s.replayable()
	for handler, module := range map[string]string{
		"software.deploy": "deploy", "patches.deploy": "patches", "playbooks.run": "playbooks",
	} {
		if reg[handler] == nil {
			t.Errorf("module %q is gateable but %q has no replay handler", module, handler)
		}
	}
}

func TestCaptureWriterRecordsStatusAndBody(t *testing.T) {
	c := &captureWriter{header: nil}
	c.Write([]byte("hello"))
	if c.status != 200 || c.body.String() != "hello" {
		t.Fatalf("an unset status must default to 200: %d %q", c.status, c.body.String())
	}
	c2 := &captureWriter{}
	c2.WriteHeader(403)
	c2.Write([]byte("no"))
	if c2.status != 403 {
		t.Fatalf("explicit status must win: %d", c2.status)
	}
}

// Resolving group membership loads and decodes every endpoint's sensor data
// only when some group is matched by rules; static groups (and an install
// with no groups) must not pay for it on every endpoint action.
func TestAnyDynamicGroup(t *testing.T) {
	cases := []struct {
		groups []store.ComputerGroup
		want   bool
	}{
		{nil, false},
		{[]store.ComputerGroup{{Kind: "static"}}, false},
		{[]store.ComputerGroup{{Kind: "static"}, {Kind: "dynamic"}}, true},
		{[]store.ComputerGroup{{Kind: ""}}, true}, // anything not static is rule-matched, as accessSnapshot treats it
	}
	for _, c := range cases {
		if got := anyDynamicGroup(c.groups); got != c.want {
			t.Errorf("anyDynamicGroup(%+v) = %v, want %v", c.groups, got, c.want)
		}
	}
}
