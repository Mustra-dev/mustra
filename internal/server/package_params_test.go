package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

func f(v float64) *float64 { return &v }

func TestValidateParameters(t *testing.T) {
	cases := []struct {
		name    string
		params  []store.SoftwareParameter
		wantErr bool
	}{
		{"a plain numeric", []store.SoftwareParameter{{Name: "delay", Type: "numeric"}}, false},
		{"bad name", []store.SoftwareParameter{{Name: "Delay Seconds", Type: "text"}}, true},
		{"unknown type", []store.SoftwareParameter{{Name: "delay", Type: "slider"}}, true},
		{"duplicate names", []store.SoftwareParameter{
			{Name: "delay", Type: "text"}, {Name: "delay", Type: "text"}}, true},
		{"select with no options", []store.SoftwareParameter{{Name: "mode", Type: "select"}}, true},
		{"min above max", []store.SoftwareParameter{
			{Name: "delay", Type: "numeric", Min: f(10), Max: f(5)}}, true},
		{"bad regex", []store.SoftwareParameter{{Name: "host", Type: "text", Validate: "("}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateParameters(tc.params)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateParameters = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestResolveParameters(t *testing.T) {
	params := []store.SoftwareParameter{
		{Name: "delay", Type: "numeric", Default: "60", Min: f(0), Max: f(3600)},
		{Name: "mode", Type: "select", Options: []string{"restart", "shutdown"}, Default: "restart"},
		{Name: "force", Type: "checkbox", Default: "false"},
		{Name: "note", Type: "text", Required: true, Default: "scheduled"},
	}

	// Defaults fill in for anything not supplied.
	got, err := resolveParameters(params, nil)
	if err != nil {
		t.Fatalf("resolveParameters with defaults: %v", err)
	}
	if got["delay"] != "60" || got["mode"] != "restart" || got["note"] != "scheduled" {
		t.Fatalf("defaults not applied: %v", got)
	}

	// Supplied values win.
	got, err = resolveParameters(params, map[string]string{"delay": "5", "mode": "shutdown"})
	if err != nil {
		t.Fatalf("resolveParameters: %v", err)
	}
	if got["delay"] != "5" || got["mode"] != "shutdown" {
		t.Fatalf("supplied values not used: %v", got)
	}

	for _, bad := range []struct {
		name string
		vals map[string]string
	}{
		{"out of range", map[string]string{"delay": "99999"}},
		{"not a number", map[string]string{"delay": "soon"}},
		{"not an option", map[string]string{"mode": "hibernate"}},
		{"not a boolean", map[string]string{"force": "yes"}},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if _, err := resolveParameters(params, bad.vals); err == nil {
				t.Fatalf("expected %s to be rejected", bad.name)
			}
		})
	}

	// A required parameter with no default and no value is refused rather
	// than silently substituting an empty string into the command.
	req := []store.SoftwareParameter{{Name: "target", Type: "text", Required: true}}
	if _, err := resolveParameters(req, nil); err == nil {
		t.Fatal("expected a missing required parameter to be refused")
	}
}

func TestSubstituteParameters(t *testing.T) {
	cmd := "shutdown.exe /r /t $(delay) /c \"$(note)\""
	got := substituteParameters(cmd, map[string]string{"delay": "60", "note": "by mustra"})
	want := "shutdown.exe /r /t 60 /c \"by mustra\""
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// A $(...) that isn't a declared parameter is left alone rather than
	// being blanked -- shell syntax shouldn't be mangled by the substituter.
	got = substituteParameters("echo $(hostname)", map[string]string{"delay": "60"})
	if got != "echo $(hostname)" {
		t.Fatalf("undeclared placeholder was rewritten: %q", got)
	}
}

// The label an operator sees for a deployment. An action package is already
// a verb, so prefixing it produced "Install Reboot Computer".
func TestDeploymentLabel(t *testing.T) {
	action := store.SoftwarePackage{Kind: store.KindAction, Name: "Reboot Computer"}
	software := store.SoftwarePackage{Kind: store.KindSoftware, Name: "Visual Studio Code"}

	cases := []struct {
		pkg  store.SoftwarePackage
		op   string
		want string
	}{
		{action, "install", "Reboot Computer"},
		{action, "remove", "Cancel Reboot Computer"},
		{software, "install", "Install Visual Studio Code"},
		{software, "update", "Update Visual Studio Code"},
		{software, "remove", "Remove Visual Studio Code"},
	}
	for _, tc := range cases {
		if got := deploymentLabel(tc.pkg, tc.op); got != tc.want {
			t.Errorf("deploymentLabel(%s, %s) = %q, want %q", tc.pkg.Name, tc.op, got, tc.want)
		}
	}
}
