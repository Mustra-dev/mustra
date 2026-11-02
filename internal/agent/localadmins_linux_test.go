//go:build linux

package agent

import (
	"context"
	"testing"
)

// Runs against the host the tests run on. What it checks is the shape —
// root is always an administrator, every row is a user or a group, nothing
// is duplicated — rather than any particular machine's answer.
func TestLocalAdminsLinuxShape(t *testing.T) {
	rows, err := collectLocalAdmins(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	seen := map[string]bool{}
	root := false
	for _, r := range rows {
		if r.Kind != "user" && r.Kind != "group" {
			t.Errorf("row %+v has kind %q", r, r.Kind)
		}
		if r.Source != "local" || r.Via == "" || r.Name == "" {
			t.Errorf("row %+v is missing source, via or name", r)
		}
		key := r.Kind + ":" + r.Name
		if seen[key] {
			t.Errorf("row %+v is listed twice", r)
		}
		seen[key] = true
		if r.Name == "root" && r.Via == "uid 0" {
			root = true
		}
	}
	if !root {
		t.Errorf("root was not reported as uid 0 (rows: %+v)", rows)
	}
	t.Logf("%d administrators on this host: %+v", len(rows), rows)
}
