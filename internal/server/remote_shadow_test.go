package server

import "testing"

func TestPickShadowSessionPrefersTheActiveConsole(t *testing.T) {
	sessions := []shadowSession{
		{SessionID: 2, User: "bob", Terminal: "", State: "Disc"},
		{SessionID: 3, User: "carol", Terminal: "rdp-tcp#4", State: "Active"},
		{SessionID: 1, User: "alex", Terminal: "console", State: "Active"},
	}
	if p, ok := pickShadowSession(sessions, 0); !ok || p.SessionID != 1 {
		t.Fatalf("picked %+v %v, want the console", p, ok)
	}
	if p, ok := pickShadowSession(sessions, 3); !ok || p.User != "carol" {
		t.Fatalf("named session: %+v %v", p, ok)
	}
	if _, ok := pickShadowSession(sessions, 9); ok {
		t.Fatal("an unreported session id was found")
	}
	// A disconnected session is not something to shadow; nobody is there.
	if _, ok := pickShadowSession(sessions[:1], 0); ok {
		t.Fatal("picked a disconnected session")
	}
	// Agents before session ids: nothing to pick.
	if _, ok := pickShadowSession([]shadowSession{{User: "alex", Terminal: "console"}}, 0); ok {
		t.Fatal("picked a session without an id")
	}
}

func TestShadowCommand(t *testing.T) {
	if got := shadowCommand("10.0.0.5", 1, false); got != "mstsc.exe /v:10.0.0.5 /shadow:1 /prompt" {
		t.Fatalf("view: %q", got)
	}
	if got := shadowCommand("pc-7.corp.example.com", 14, true); got != "mstsc.exe /v:pc-7.corp.example.com /shadow:14 /prompt /control" {
		t.Fatalf("control: %q", got)
	}
}
