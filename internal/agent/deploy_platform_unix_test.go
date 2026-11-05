//go:build !windows

package agent

import "testing"

func TestParseDeployID(t *testing.T) {
	for s, want := range map[string]int{"0": 0, "501": 501, "2147483647": 2147483647} {
		if got, e := parseDeployID(s); e != nil || got != want {
			t.Errorf("parseDeployID(%q) = %d, %v; want %d", s, got, e, want)
		}
	}
	// 4294967296 wraps to 0, which is root, if it is ever narrowed unchecked.
	for _, s := range []string{"", "-2", "abc", "2147483648", "4294967295", "4294967296"} {
		if got, e := parseDeployID(s); e == nil {
			t.Errorf("parseDeployID(%q) = %d; want an error", s, got)
		}
	}
}
