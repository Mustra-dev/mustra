package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The single most important property: a rule the engine does not
// understand must never make a check pass. A silent pass is a false
// assurance, which is the one failure mode compliance tooling cannot have.
func TestUnknownRuleNeverPasses(t *testing.T) {
	for _, rules := range [][]string{
		{"totally:unrecognized"},
		{"f:/nonexistent -> weird:matcher"},
		{"c:true -> r:([unclosed"}, // a malformed regex is unknown, not a pass
	} {
		got := evaluateCheck(context.Background(), proto.ComplianceCheck{
			ID: "x", Rules: rules,
		})
		if got.Pass {
			t.Errorf("rules %v produced a pass", rules)
		}
		if got.State != "unknown" {
			t.Errorf("rules %v gave state %q, want unknown", rules, got.State)
		}
	}
	// And a check with no rules at all is unknown, not vacuously passing.
	if got := evaluateCheck(context.Background(), proto.ComplianceCheck{ID: "empty"}); got.Pass {
		t.Error("a check with no rules must not pass")
	}
}

func TestFileRules(t *testing.T) {
	path := writeTemp(t, "sshd_config", "Port 22\nPermitRootLogin no\n")
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		rule string
		want bool
	}{
		{"file exists", "f:" + path, true},
		{"file absent", "f:" + path + ".missing", false},
		{"content matches", "f:" + path + " -> r:^PermitRootLogin\\s+no", true},
		{"content does not match", "f:" + path + " -> r:^PermitRootLogin\\s+yes", false},
		{"negated matcher", "f:" + path + " -> !r:^PermitRootLogin\\s+yes", true},
		{"not prefix", "not f:" + path + ".missing", true},
		{"directory", "d:" + filepath.Dir(path), true},
		{"directory is not a file", "d:" + path, false},
	} {
		got, known := evaluateRule(ctx, tc.rule)
		if !known {
			t.Errorf("%s: rule was not understood", tc.name)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The condition decides how rule outcomes combine, and getting it backwards
// would invert an entire benchmark's verdict.
func TestConditions(t *testing.T) {
	yes := "d:/"
	no := "f:/definitely/not/here"
	ctx := context.Background()

	for _, tc := range []struct {
		condition string
		rules     []string
		want      bool
	}{
		{"all", []string{yes, yes}, true},
		{"all", []string{yes, no}, false},
		{"any", []string{yes, no}, true},
		{"any", []string{no, no}, false},
		{"none", []string{no, no}, true},
		{"none", []string{yes, no}, false},
		{"", []string{yes, yes}, true}, // empty defaults to all
	} {
		got := evaluateCheck(ctx, proto.ComplianceCheck{
			ID: "c", Condition: tc.condition, Rules: tc.rules,
		})
		if got.Pass != tc.want {
			t.Errorf("condition %q over %v: got %v, want %v", tc.condition, tc.rules, got.Pass, tc.want)
		}
	}
}

// A bare literal and an unimplemented rule form are genuinely ambiguous,
// and erring permissive is the dangerous direction: an unknown form read
// as a literal would compare a value against the rule's own text and
// report a confident "fail" that looks like a real finding.
func TestLiteralVersusUnknownPrefix(t *testing.T) {
	for matcher, wantUnderstood := range map[string]bool{
		"0":                         true, // registry value
		"1":                         true,
		"EnableFirewall":            true,
		"C:\\Windows":               true, // a path, not a prefix — drive letters are uppercase
		"Some Value Here":           true,
		`r:^Windows Server`:         true,
		"n:x = (\\d+) compare >= 2": true,
		"weird:matcher":             false, // unimplemented form
		"q:something":               false,
		"":                          false,
	} {
		if got := matcherUnderstood(matcher); got != wantUnderstood {
			t.Errorf("matcherUnderstood(%q) = %v, want %v", matcher, got, wantUnderstood)
		}
	}
}

// The literal path is what makes Windows benchmarks work at all: nearly
// every registry assertion is "this value equals this number".
func TestBareLiteralMatching(t *testing.T) {
	for _, tc := range []struct {
		content, matcher string
		want             bool
	}{
		{"0", "0", true},
		{"1", "0", false},
		{" 1 ", "1", true},           // registry reads carry whitespace
		{"Enabled", "enabled", true}, // value comparisons are case-insensitive
	} {
		got, known := applyMatcher(tc.content, tc.matcher)
		if !known {
			t.Errorf("literal %q vs %q was not understood", tc.content, tc.matcher)
			continue
		}
		if got != tc.want {
			t.Errorf("literal %q vs %q = %v, want %v", tc.content, tc.matcher, got, tc.want)
		}
	}
}

// Numeric comparison backs every "at least N" setting in a CIS benchmark.
func TestNumericCompare(t *testing.T) {
	content := "PasswordHistorySize = 24\nMaximumPasswordAge = 365\n"
	for _, tc := range []struct {
		matcher string
		want    bool
	}{
		{`n:PasswordHistorySize = (\d+) compare >= 24`, true},
		{`n:PasswordHistorySize = (\d+) compare >= 25`, false},
		{`n:MaximumPasswordAge = (\d+) compare <= 365`, true},
		{`n:MaximumPasswordAge = (\d+) compare < 365`, false},
		{`n:MaximumPasswordAge = (\d+) compare > 0`, true},
	} {
		got, known := applyMatcher(content, tc.matcher)
		if !known {
			t.Errorf("%q was not understood", tc.matcher)
			continue
		}
		if got != tc.want {
			t.Errorf("%q = %v, want %v", tc.matcher, got, tc.want)
		}
	}
	// A setting that isn't present at all is a definite fail, not unknown —
	// an absent setting is not a passing setting.
	got, known := applyMatcher("", `n:NotPresent = (\d+) compare >= 1`)
	if !known || got {
		t.Errorf("absent setting: got=%v known=%v, want got=false known=true", got, known)
	}
}

// Wazuh's matchers hold per line, and " && " joins terms that must all hold
// on the same line. The CIS policies are written against that: reading
// "r:0 root 0 root && r:644|640" as one regex alternation matched "640"
// anywhere and nothing else.
func TestCompoundMatchersHoldOnOneLine(t *testing.T) {
	stat := "/etc/issue 644 0 root 0 root\n"
	sudoers := "# Defaults use_pty\nDefaults\tenv_reset\nDefaults use_pty\n"
	grace := "logingracetime 60\nmaxauthtries 4\n"
	for _, tc := range []struct {
		name, content, matcher string
		want                   bool
	}{
		{"both terms on the line", stat, `r:0 root 0 root && r:644|640|600|400`, true},
		{"one term missing", "/etc/issue 664 0 root 0 root\n", `r:0 root 0 root && r:644|640|600|400`, false},
		{"terms on different lines do not combine", "0 root 0 root\n644\n", `r:0 root 0 root && r:644`, false},
		{"negated term skips comments", sudoers, `!r:^# && r:Defaults\s*\t*use_pty`, true},
		{"only a commented-out line", "# Defaults use_pty\n", `!r:^# && r:Defaults\s*\t*use_pty`, false},
		{"two numeric terms", grace, `n:^logingracetime\s(\d+) compare <= 60 && n:LoginGraceTime\s(\d+) compare >= 1`, true},
		{"numeric term out of range", "logingracetime 120\n", `n:^logingracetime\s(\d+) compare <= 60 && n:LoginGraceTime\s(\d+) compare >= 1`, false},
		{"numeric on any line", "a = 1\nminlen = 14\n", `n:minlen\s*=\s*(\d+) compare >= 14`, true},
		{"lone negation: some line lacks it", "root:x:0:0\nbad::1:1\n", `!r:^[\w@-]+:x:`, true},
		{"lone negation: every line has it", "root:x:0:0\nbin:x:1:1\n", `!r:^[\w@-]+:x:`, false},
		{"no output has no lines", "", `!r:anything`, false},
		{"CRLF line ends", "Defaults use_pty\r\n", `r:use_pty$`, true},
	} {
		got, known := applyContentMatcher(tc.content, tc.matcher)
		if !known {
			t.Errorf("%s: not understood", tc.name)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if matcherUnderstood(`r:a && weird:b`) {
		t.Error("a compound with an unknown term must not be understood")
	}
}

// Wazuh's shadowed-passwords check reads "every line has x" as
// not (some line lacks x) — which only works with per-line negation.
func TestNotWithLineNegation(t *testing.T) {
	good := writeTemp(t, "passwd", "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1::/:/usr/sbin/nologin\n")
	bad := writeTemp(t, "passwd", "root:x:0:0:root:/root:/bin/bash\nold::2:2::/:/bin/sh\n")
	for path, want := range map[string]bool{good: true, bad: false} {
		got, known := evaluateRule(context.Background(), "not f:"+path+` -> !r:^[\w@-]+:x:`)
		if !known || got != want {
			t.Errorf("%s: got %v (known %v), want %v", path, got, known, want)
		}
	}
}

// d: rules walk the directory: a name pattern picks files, and a matcher
// then has to hold in one of them. Before, any d: rule with a matcher
// passed as soon as the directory existed — every auditd rule check
// passed on a host with an empty rules.d.
func TestDirectoryRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules.d", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(rel, content string) {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("rules.d/audit.rules", "-w /etc/sudoers -p wa -k scope\n")
	write("rules.d/notes.txt", "-w /etc/localtime -p wa -k time-change\n")
	write("rules.d/sub/deep.rules", "-a always,exit -F arch=b64 -S adjtimex -k time-change\n")
	ctx := context.Background()
	for _, tc := range []struct {
		name, rule string
		want       bool
	}{
		{"directory exists", "d:" + dir + "/rules.d", true},
		{"trailing glob", "d:" + dir + "/rules.d/*", true},
		{"a file name matches", "d:" + dir + `/rules.d -> r:.+\.rules$`, true},
		{"no file name matches", "d:" + dir + `/rules.d -> r:.+\.conf$`, false},
		{"content in a matching file", "d:" + dir + `/rules.d -> r:.+\.rules$ -> r:^-w && r:/etc/sudoers && r:-p wa`, true},
		{"content only in a file the name excludes", "d:" + dir + `/rules.d -> r:.+\.rules$ -> r:/etc/localtime`, false},
		{"content in a subdirectory", "d:" + dir + `/rules.d -> r:.+\.rules$ -> r:adjtimex && r:time-change`, true},
		{"absent directory", "d:" + dir + `/missing -> r:.* -> r:x`, false},
		{"glob and content", "d:" + dir + `/rules.d/* -> r:.+\.rules$ -> r:scope`, true},
	} {
		got, known := evaluateRule(ctx, tc.rule)
		if !known {
			t.Errorf("%s: not understood", tc.name)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if _, known := evaluateRule(ctx, "d:"+dir+" -> weird:x"); known {
		t.Error("a d: rule with an unknown name matcher must be unknown")
	}
}

func TestSameProcessName(t *testing.T) {
	for _, c := range []struct {
		running, rule string
		want          bool
	}{
		{"lsass.exe", "lsass", true},
		{"lsass.exe", "LSASS.EXE", true},
		{"sshd", "sshd", true},
		{"sshd", "sshd.exe", true},
		{"svchost.exe", "svc", false},
		{"chronyd", "chrony", false},
	} {
		if got := sameProcessName(c.running, c.rule); got != c.want {
			t.Errorf("sameProcessName(%q, %q) = %v, want %v", c.running, c.rule, got, c.want)
		}
	}
}
