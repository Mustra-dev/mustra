//go:build darwin

package agent

import "testing"

// The notification carries a filesystem path, and a stray quote would make
// the AppleScript a syntax error raised into a log nobody reads.
func TestAppleScriptStringQuotes(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:             `"plain"`,
		`say "hi"`:          `"say \"hi\""`,
		`back\slash`:        `"back\\slash"`,
		`/opt/mustra-agent`: `"/opt/mustra-agent"`,
	} {
		if got := appleScriptString(in); got != want {
			t.Fatalf("appleScriptString(%q) = %s, want %s", in, got, want)
		}
	}
}
