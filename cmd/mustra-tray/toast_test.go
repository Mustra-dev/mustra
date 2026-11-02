package main

import (
	"encoding/xml"
	"strings"
	"testing"
)

func notice(buttons ...button) *notification {
	return &notification{ID: "eun-1", Kind: "notice", Title: "Maintenance tonight",
		Body: "We are patching at 22:00.", Buttons: buttons}
}

func TestToastCarriesTitleAndBody(t *testing.T) {
	doc, err := buildToastXML(notice(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, "Maintenance tonight") || !strings.Contains(doc, "We are patching at 22:00.") {
		t.Fatalf("document lost its text:\n%s", doc)
	}
}

// A label is operator-written, so it reaches this document as text from a
// form. Pasted into XML by hand, one quote would produce a toast Windows
// silently refuses to render.
func TestOperatorTextIsEscaped(t *testing.T) {
	n := notice(button{Label: `He said "no" & left <now>`, Action: "acknowledged"})
	n.Title = `Title with "quotes" & <angles>`
	doc, err := buildToastXML(n, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc, `"no" &`) || strings.Contains(doc, "<angles>") {
		t.Fatalf("raw operator text reached the document:\n%s", doc)
	}
	var probe struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal([]byte(doc), &probe); err != nil {
		t.Fatalf("document is not well-formed XML: %v\n%s", err, doc)
	}
}

func TestCustomButtonsBecomeActions(t *testing.T) {
	doc, err := buildToastXML(notice(
		button{Label: "Understood", Action: "acknowledged", Primary: true},
		button{Label: "Remind me", Action: "postponed", Minutes: 90},
	), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`content="Understood"`,
		`content="Remind me"`,
		"action=acknowledged",
		"minutes=90",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("missing %q in:\n%s", want, doc)
		}
	}
}

// Windows drops a toast that declares more than five buttons -- the whole
// toast, not the extra buttons -- so the cap is what keeps a six-button
// message visible at all.
func TestMoreThanFiveButtonsIsCapped(t *testing.T) {
	var many []button
	for i := 0; i < 6; i++ {
		many = append(many, button{Label: "Choice", Action: "acknowledged"})
	}
	doc, err := buildToastXML(notice(many...), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(doc, "<action "); got > 5 {
		t.Fatalf("%d actions in the document, want at most 5", got)
	}
}

func TestDefaultsWhenTheOperatorDefinedNoButtons(t *testing.T) {
	n := &notification{ID: "eun-2", Kind: "restart", Title: "Restart needed",
		AllowPostpone: true, PostponeMinutes: []int{60, 240}}
	doc, err := buildToastXML(n, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Restart now", "Remind me in 1h", "Remind me in 4h"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("missing default %q in:\n%s", want, doc)
		}
	}
}

// A restart negotiation must not fade away while somebody is at lunch.
func TestRestartStaysOnScreen(t *testing.T) {
	n := &notification{ID: "eun-3", Kind: "restart", Title: "Restart needed"}
	doc, err := buildToastXML(n, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, `scenario="reminder"`) {
		t.Fatalf("a restart toast should use the reminder scenario:\n%s", doc)
	}
	notice, err := buildToastXML(notice(), "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(notice, `scenario="reminder"`) {
		t.Fatalf("a notice should fade like any other:\n%s", notice)
	}
}

func TestRestartButtonIsMarkedDestructive(t *testing.T) {
	doc, err := buildToastXML(&notification{ID: "eun-4", Kind: "restart", Title: "Restart"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, `hint-buttonStyle="Critical"`) {
		t.Fatalf("Restart now should not look like the safe default:\n%s", doc)
	}
}

func TestLogoIsReferencedAsAFileURI(t *testing.T) {
	doc, err := buildToastXML(notice(), `C:\Program Files\mustra-agent\mustra.ico`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, "appLogoOverride") || !strings.Contains(doc, "file:///C:/Program Files/mustra-agent/mustra.ico") {
		t.Fatalf("logo not referenced correctly:\n%s", doc)
	}
}

func TestActivationRoundTrips(t *testing.T) {
	for _, b := range []button{
		{Action: "acknowledged"},
		{Action: "restart_now"},
		{Action: "postponed", Minutes: 45},
	} {
		action, minutes, ok := parseActivation(b.activationURI())
		if !ok || action != b.Action {
			t.Fatalf("%s did not round-trip: %q %v", b.Action, action, ok)
		}
		if b.Action == "postponed" && minutes != 45 {
			t.Fatalf("minutes = %d, want 45", minutes)
		}
	}
}

// The URI arrives from the shell as a command-line argument. Acting on one
// we only half understand would mean answering a prompt on somebody's
// behalf.
func TestUnknownActivationIsRefused(t *testing.T) {
	for _, arg := range []string{
		"mustra://answer?action=rm-rf",
		"http://evil.example/answer?action=acknowledged",
		"mustra://somewhere-else?action=acknowledged",
		"not a uri at all",
		"",
	} {
		if _, _, ok := parseActivation(arg); ok {
			t.Fatalf("%q was accepted", arg)
		}
	}
}
