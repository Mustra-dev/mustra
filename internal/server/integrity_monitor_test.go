package server

import (
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func TestWatchRevisionIsContentAddressed(t *testing.T) {
	a := proto.WatchConfig{Paths: []string{"/etc/a", "/etc/b"}, RegistryKeys: []string{`HKLM\X`}}
	b := proto.WatchConfig{Paths: []string{"/etc/a", "/etc/b"}, RegistryKeys: []string{`HKLM\X`}}
	if watchRevision(a) != watchRevision(b) || watchRevision(a) == "" {
		t.Fatal("same content must give the same revision")
	}
	b.FollowSymlinks = true
	if watchRevision(a) == watchRevision(b) {
		t.Fatal("follow-symlinks is part of the set")
	}
	if watchRevision(proto.WatchConfig{}) != "" {
		t.Fatal("an empty set has an empty revision, matching an unmonitored agent")
	}
	if got := uniqueSorted([]string{"/b", " /a ", "/b", ""}); len(got) != 2 || got[0] != "/a" {
		t.Fatalf("uniqueSorted: %v", got)
	}
}

func TestLabelMatchesPathKindAndTimeWindow(t *testing.T) {
	s := &Server{}
	at := time.Date(2026, 9, 14, 3, 30, 0, 0, time.UTC) // Monday 03:30 UTC
	mk := func(c labelCriteria) compiledLabel {
		return compiledLabel{IntegrityLabel: store.IntegrityLabel{Name: "x"}, crit: c}
	}
	if !s.labelMatches(nil, mk(labelCriteria{PathPrefix: "/etc/apt/", Kinds: []string{"modified"}}), "a", "/etc/apt/sources.list", "modified", at) {
		t.Fatal("prefix + kind should match")
	}
	if s.labelMatches(nil, mk(labelCriteria{PathPrefix: "/etc/apt/", Kinds: []string{"added"}}), "a", "/etc/apt/sources.list", "modified", at) {
		t.Fatal("kind mismatch should not match")
	}
	if !s.labelMatches(nil, mk(labelCriteria{PathSuffix: ".LIST"}), "a", "/etc/apt/sources.list", "modified", at) {
		t.Fatal("suffix is case-insensitive")
	}
	if !s.labelMatches(nil, mk(labelCriteria{Weekdays: []int{1}, Start: "02:00", End: "05:00"}), "a", "/x", "added", at) {
		t.Fatal("inside the Monday 02-05 window")
	}
	if s.labelMatches(nil, mk(labelCriteria{Weekdays: []int{1}, Start: "04:00", End: "05:00"}), "a", "/x", "added", at) {
		t.Fatal("outside the window")
	}
	if !s.labelMatches(nil, mk(labelCriteria{Start: "22:00", End: "04:00"}), "a", "/x", "added", at) {
		t.Fatal("a window crossing midnight covers 03:30")
	}
	if !s.labelMatches(nil, mk(labelCriteria{Start: "19:00", End: "21:00", Timezone: "America/Los_Angeles"}), "a", "/x", "added", at) {
		t.Fatal("03:30 UTC is 20:30 in Los Angeles")
	}
	members := compiledLabel{IntegrityLabel: store.IntegrityLabel{Name: "g"}, crit: labelCriteria{GroupIDs: []string{"g1"}}, members: map[string]bool{"a": true}}
	if !s.labelMatches(nil, members, "a", "/x", "added", at) || s.labelMatches(nil, members, "b", "/x", "added", at) {
		t.Fatal("group membership")
	}
	if s.labelMatches(nil, mk(labelCriteria{Process: "apt"}), "a", "/x", "added", at) {
		t.Fatal("process criteria never match until an agent reports one")
	}
}

func TestUnderAnyRoot(t *testing.T) {
	roots := []string{"/etc/nginx", `C:\inetpub\wwwroot\`, `HKLM\SOFTWARE\Policies`}
	for _, p := range []string{"/etc/nginx/nginx.conf", "/etc/nginx", `C:\inetpub\wwwroot\index.html`, `hklm\software\policies\x`} {
		if !underAnyRoot(p, roots) {
			t.Errorf("%q should be under a root", p)
		}
	}
	for _, p := range []string{"/etc/nginx2/x", "/etc/ssh/sshd_config", `C:\inetpub\other`} {
		if underAnyRoot(p, roots) {
			t.Errorf("%q should not be under a root", p)
		}
	}
}

// The seeded label must catch the churn it was written for and nothing
// else: a task Windows rewrites when it runs, not a task somebody added.
func TestSeededWindowsTaskLabelScope(t *testing.T) {
	s := &Server{}
	cl := compiledLabel{
		IntegrityLabel: store.IntegrityLabel{Name: "Windows scheduled-task housekeeping", Expected: true},
		crit:           labelCriteria{PathPrefix: `C:\Windows\System32\Tasks\Microsoft\Windows\`, Kinds: []string{"modified"}},
	}
	at := time.Now()
	match := []string{
		`C:\Windows\System32\Tasks\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask`,
		`C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Work`,
	}
	for _, p := range match {
		if !s.labelMatches(nil, cl, "a", p, "modified", at) {
			t.Errorf("should be labelled: %q", p)
		}
	}
	// A task an operator or an attacker adds is not housekeeping.
	if s.labelMatches(nil, cl, "a", `C:\Windows\System32\Tasks\EvilPersistence`, "added", at) {
		t.Error("a task outside the Microsoft tree must stay unexpected")
	}
	if s.labelMatches(nil, cl, "a", `C:\Windows\System32\Tasks\Microsoft\Windows\Defender\Scan`, "added", at) {
		t.Error("an added task file is not a rewrite; it must stay unexpected")
	}
}
