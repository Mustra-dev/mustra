package server

import "testing"

func TestDirectoryTargetRow(t *testing.T) {
	rows, err := directoryTargetRow([]byte(`[{"joined":true,"kind":"ad","domain":"corp.example","computer_ou":"OU=Servers,DC=corp,DC=example",
		"computer_groups":["Web Servers"],"users":[{"name":"alice","upn":"alice@corp.example","department":"Finance","groups":["Finance","Domain Users"]},
		{"name":"bob","groups":["Domain Users"]}]}]`))
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	r := rows[0]
	if r["ou"] != "OU=Servers,DC=corp,DC=example" || r["domain"] != "corp.example" {
		t.Fatalf("join facts: %v", r)
	}
	if g := r["user_groups"].([]any); len(g) != 2 {
		t.Fatalf("groups should be de-duplicated across users: %v", g)
	}
	if u := r["users"].([]any); len(u) != 3 {
		t.Fatalf("users by name and UPN: %v", u)
	}
	if rows, _ := directoryTargetRow([]byte(`[]`)); len(rows) != 0 {
		t.Fatal("an empty snapshot is reported with no rows")
	}
}
