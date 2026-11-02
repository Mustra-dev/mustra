package store

import (
	"strings"
	"testing"
)

// The two column lists must stay in step. They did not once: adding
// last_sign_in/previous_sign_in to userColumns while userColumnsPrefixed
// kept its own hand-written copy compiled fine and then broke every session
// lookup at runtime, logging out the whole console.
func TestUserColumnsPrefixedMatchesUserColumns(t *testing.T) {
	plain := strings.Split(userColumns, ",")
	prefixed := strings.Split(userColumnsPrefixed("u"), ",")

	if len(plain) != len(prefixed) {
		t.Fatalf("userColumns has %d columns, userColumnsPrefixed has %d — a scan will fail at runtime",
			len(plain), len(prefixed))
	}
	for i := range plain {
		want := "u." + strings.TrimSpace(plain[i])
		if got := strings.TrimSpace(prefixed[i]); got != want {
			t.Errorf("column %d: got %q, want %q", i, got, want)
		}
	}
}

// scanUser reads this many destinations; if the list shrinks below what the
// struct expects, that is the same runtime failure in the other direction.
func TestUserColumnsCoversSignInFields(t *testing.T) {
	for _, col := range []string{"last_sign_in", "previous_sign_in", "email", "is_admin"} {
		if !strings.Contains(userColumns, col) {
			t.Errorf("userColumns is missing %q, which scanUser reads", col)
		}
	}
}
