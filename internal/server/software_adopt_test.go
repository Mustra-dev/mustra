package server

import "testing"

// An adopted package's commands are built from an agent-reported name. A
// name a shell would read as more than one word must produce no command.
func TestGuessCommandsRefusesNamesAShellWouldParse(t *testing.T) {
	for _, name := range []string{
		"curl; rm -rf /", "a && b", "$(id)", "`id`", "foo bar", "foo\nbar", "x|y", "-rf", "", "a\"b", "a'b", "..", "name>out", "name<in",
	} {
		for _, os := range []string{"linux", "darwin", "windows"} {
			if _, ok := guessCommands(os, name); ok {
				t.Errorf("%s: %q was turned into a command", os, name)
			}
		}
	}
}

func TestGuessCommandsAcceptsPackageIdentifiers(t *testing.T) {
	cases := map[string][]string{
		"linux":   {"curl", "libssl3", "g++", "python3.12", "fonts-noto-color-emoji"},
		"darwin":  {"wget", "node@20", "homebrew/cask/firefox", "openjdk@17", "python-3.12"},
		"windows": {"Mozilla.Firefox", "Microsoft.PowerShell", "7zip.7zip", "Git.Git"},
	}
	for os, names := range cases {
		for _, name := range names {
			ops, ok := guessCommands(os, name)
			if !ok {
				t.Errorf("%s: %q was refused", os, name)
				continue
			}
			if ops.Install == "" || ops.Update == "" || ops.Remove == "" {
				t.Errorf("%s: %q: incomplete commands %+v", os, name, ops)
			}
		}
	}
	if _, ok := guessCommands("plan9", "curl"); ok {
		t.Error("an unknown platform got a command")
	}
}
