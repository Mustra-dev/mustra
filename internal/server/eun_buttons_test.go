package server

import (
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func restartMsg(buttons ...proto.EUNButton) store.EUNMessage {
	return store.EUNMessage{Kind: store.EUNRestart, AllowPostpone: true, Buttons: buttons}
}

func TestNoButtonsMeansTheDefaults(t *testing.T) {
	got, err := cleanEUNButtons(store.EUNMessage{Kind: store.EUNNotice})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d buttons, want none", len(got))
	}
}

func TestLabelIsTrimmedAndKept(t *testing.T) {
	got, err := cleanEUNButtons(restartMsg(
		proto.EUNButton{Label: "  Understood, thanks  ", Action: proto.EUNActionAcknowledged},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].Label != "Understood, thanks" {
		t.Fatalf("label = %q, want it trimmed", got[0].Label)
	}
}

// The rule that matters: a message with nothing that dismisses it is a
// window the person at the endpoint cannot close.
func TestEveryMessageKeepsAWayOut(t *testing.T) {
	_, err := cleanEUNButtons(restartMsg(
		proto.EUNButton{Label: "Later", Action: proto.EUNActionPostponed, Minutes: 30},
		proto.EUNButton{Label: "Much later", Action: proto.EUNActionPostponed, Minutes: 120},
	))
	if err == nil || !strings.Contains(err.Error(), "dismiss") {
		t.Fatalf("error = %v, want it to refuse a message with no way out", err)
	}
}

func TestRestartOnlyButtonsAreRefusedOnANotice(t *testing.T) {
	for _, b := range []proto.EUNButton{
		{Label: "Reboot", Action: proto.EUNActionRestartNow},
		{Label: "Snooze", Action: proto.EUNActionPostponed, Minutes: 30},
	} {
		_, err := cleanEUNButtons(store.EUNMessage{Kind: store.EUNNotice, Buttons: []proto.EUNButton{b}})
		if err == nil {
			t.Fatalf("%q was accepted on a notice", b.Label)
		}
	}
}

func TestPostponeNeedsADuration(t *testing.T) {
	_, err := cleanEUNButtons(restartMsg(
		proto.EUNButton{Label: "Got it", Action: proto.EUNActionAcknowledged},
		proto.EUNButton{Label: "Later", Action: proto.EUNActionPostponed},
	))
	if err == nil || !strings.Contains(err.Error(), "how long") {
		t.Fatalf("error = %v, want a complaint about the missing duration", err)
	}
}

func TestPostponeNeedsPostponementAllowed(t *testing.T) {
	m := restartMsg(
		proto.EUNButton{Label: "Restart now", Action: proto.EUNActionRestartNow},
		proto.EUNButton{Label: "Later", Action: proto.EUNActionPostponed, Minutes: 30},
	)
	m.AllowPostpone = false
	if _, err := cleanEUNButtons(m); err == nil {
		t.Fatal("a postpone button was accepted with postponement switched off")
	}
}

func TestUnknownActionIsRefused(t *testing.T) {
	_, err := cleanEUNButtons(restartMsg(
		proto.EUNButton{Label: "Open the ticket", Action: "open_url"},
	))
	if err == nil || !strings.Contains(err.Error(), "unknown button action") {
		t.Fatalf("error = %v, want an unknown-action complaint", err)
	}
}

func TestOnlyOnePrimary(t *testing.T) {
	_, err := cleanEUNButtons(restartMsg(
		proto.EUNButton{Label: "Restart now", Action: proto.EUNActionRestartNow, Primary: true},
		proto.EUNButton{Label: "Got it", Action: proto.EUNActionAcknowledged, Primary: true},
	))
	if err == nil {
		t.Fatal("two primary buttons were accepted")
	}
}

func TestTooManyButtons(t *testing.T) {
	many := []proto.EUNButton{{Label: "Got it", Action: proto.EUNActionAcknowledged}}
	for i := 0; i < maxEUNButtons; i++ {
		many = append(many, proto.EUNButton{Label: "Later", Action: proto.EUNActionPostponed, Minutes: 30})
	}
	if _, err := cleanEUNButtons(restartMsg(many...)); err == nil {
		t.Fatal("a message with more than the limit was accepted")
	}
}

// Acknowledged carries no duration; a stray one would otherwise reach the
// agent and be silently ignored, which is worse than being dropped here.
func TestMinutesAreClearedOffNonPostponeButtons(t *testing.T) {
	got, err := cleanEUNButtons(restartMsg(
		proto.EUNButton{Label: "Got it", Action: proto.EUNActionAcknowledged, Minutes: 45},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].Minutes != 0 {
		t.Fatalf("minutes = %d, want 0", got[0].Minutes)
	}
}
