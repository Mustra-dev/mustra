package agent

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Compliance checking, endpoint half.
//
// The rule syntax is deliberately Wazuh's SCA dialect rather than one
// invented here. That is not imitation — it is so mustra can read the CIS
// benchmark policies Wazuh already publishes as YAML, which are
// professionally maintained and cover far more ground than anything worth
// hand-authoring. Adopting the syntax means those policies are usable
// without running Wazuh's stack alongside this one, and without a second
// agent on every endpoint duplicating the file integrity and vulnerability
// work mustra already does.
//
// Supported rule forms, which cover the overwhelming majority of real CIS
// checks:
//
//	f:<path>                    the file exists
//	f:<path> -> <matcher>       a line of the file satisfies the matcher
//	d:<path>                    the directory exists (a trailing /* is ignored)
//	d:<path> -> r:<name>        it holds a file whose name matches
//	d:<path> -> r:<name> -> <matcher>
//	                            a line of such a file satisfies the matcher
//	c:<command> -> <matcher>    a line of the command's output satisfies it
//	p:<name>                    a process by that name is running
//	not <rule>                  negation of any of the above
//
// A matcher is r:<regex>, !r:<regex> (the line does not match), n:<regex
// with one capture> compare <op> <number>, or several of those joined with
// " && ", all of which must hold on the same line — Wazuh's semantics, and
// what the CIS policies are written against: "r:0 root 0 root &&
// r:644|640" means one line carrying both, not either anywhere.
//
// Anything unrecognized evaluates to "unknown" rather than to pass or
// fail. A check that silently passes because its syntax wasn't understood
// is worse than no check at all — it is a false assurance, which is the
// specific failure mode compliance tooling must not have.

const complianceCommandTimeout = 20 * time.Second

// evaluateCheck runs one check's rules and returns its state.
func evaluateCheck(ctx context.Context, check proto.ComplianceCheck) proto.ComplianceResult {
	result := proto.ComplianceResult{ID: check.ID, Title: check.Title}
	if len(check.Rules) == 0 {
		result.State = "unknown"
		result.Detail = "the check defines no rules"
		return result
	}

	passed, unknown := 0, 0
	var failedRules []string
	for _, rule := range check.Rules {
		ok, known := evaluateRule(ctx, rule)
		switch {
		case !known:
			unknown++
		case ok:
			passed++
		default:
			failedRules = append(failedRules, rule)
		}
	}

	// A check whose rules couldn't all be understood is not a pass. This
	// is the whole reason "unknown" exists as a state.
	if unknown > 0 && passed+len(failedRules) == 0 {
		result.State = "unknown"
		result.Detail = "none of this check's rules could be evaluated on this platform"
		if checkCommandsDisabled(ctx) {
			result.Detail = "this check needs commands, which this endpoint doesn't run in inventory-and-patching mode"
		}
		return result
	}

	condition := strings.ToLower(strings.TrimSpace(check.Condition))
	if condition == "" {
		condition = "all"
	}
	// A rule that wasn't evaluated could go either way, so the rest decide only
	// if it can't change the answer: one passing rule settles "any", and one
	// failing rule settles "all". Judging on the rest alone reported a failing
	// check as a pass.
	var settled bool
	switch condition {
	case "any":
		result.Pass = passed > 0
		settled = result.Pass || unknown == 0
	case "none":
		result.Pass = passed == 0
		settled = !result.Pass || unknown == 0
	default: // "all"
		result.Pass = len(failedRules) == 0
		settled = !result.Pass || unknown == 0
	}
	if !settled {
		result.Pass = false
		result.State = "unknown"
		result.Detail = "some of this check's rules could not be evaluated, and they decide the result"
		if checkCommandsDisabled(ctx) {
			result.Detail = "this check needs commands, which this endpoint doesn't run in inventory-and-patching mode"
		}
		return result
	}

	result.State = "fail"
	if result.Pass {
		result.State = "pass"
	}
	if !result.Pass && len(failedRules) > 0 {
		result.Detail = "failed: " + strings.Join(failedRules, "; ")
		if len(result.Detail) > 500 {
			result.Detail = result.Detail[:500] + "…"
		}
	}
	return result
}

// evaluateRule returns (satisfied, understood). The second value is what
// keeps an unparsed rule from counting as a pass.
func evaluateRule(ctx context.Context, rule string) (bool, bool) {
	rule = strings.TrimSpace(rule)
	if rest, negated := strings.CutPrefix(rule, "not "); negated {
		ok, known := evaluateRule(ctx, rest)
		return !ok, known
	}

	// A registry rule carries two arrows — r:KEY -> VALUE -> matcher — so
	// it is split before the generic one-arrow form, which would otherwise
	// swallow the value name into the matcher.
	if strings.HasPrefix(strings.TrimSpace(rule), "r:") {
		return evaluateRegistryRule(rule)
	}

	target, matcher, hasMatcher := strings.Cut(rule, " -> ")
	target = strings.TrimSpace(target)
	matcher = strings.TrimSpace(matcher)

	if strings.HasPrefix(target, "d:") {
		return evaluateDirRule(strings.TrimPrefix(target, "d:"), matcher, hasMatcher)
	}

	// Validate the matcher before anything else. Otherwise a rule whose
	// target is simply absent short-circuits to a definite "fail" without
	// the unparseable matcher ever being noticed — and a check the engine
	// did not actually understand would be reported as a real result.
	if hasMatcher && !matcherUnderstood(matcher) {
		return false, false
	}

	switch {
	case strings.HasPrefix(target, "f:"):
		path := strings.TrimPrefix(target, "f:")
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return false, true // absent is a definite answer, not an unknown
		}
		if !hasMatcher {
			return true, true
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return false, true
		}
		return applyContentMatcher(string(data), matcher)

	case strings.HasPrefix(target, "c:"):
		// Not evaluated is not a pass or a fail: it reads as unknown.
		if checkCommandsDisabled(ctx) {
			return false, false
		}
		out := runCheckCommand(ctx, strings.TrimPrefix(target, "c:"))
		if !hasMatcher {
			return out != "", true
		}
		return applyContentMatcher(out, matcher)

	case strings.HasPrefix(target, "p:"):
		name := strings.TrimPrefix(target, "p:")
		procs, err := collectProcesses(ctx)
		if err != nil {
			return false, false
		}
		for _, p := range procs {
			if sameProcessName(p.Name, name) {
				return true, true
			}
		}
		return false, true
	}
	return false, false // unrecognized: understood as "we don't know"
}

// sameProcessName compares process names the way people write them in a
// rule: case-insensitively, and on Windows with or without ".exe" — the
// processes sensor reports "lsass.exe", and "p:lsass" must still find it.
func sameProcessName(running, rule string) bool {
	trim := func(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".exe") }
	return trim(running) == trim(rule)
}

// numericCompare implements Wazuh's "n:<regex> compare <op> <value>"
// matcher: pull a number out of the output with a capture group, then
// compare it. CIS benchmarks lean on this for every "at least N" and "no
// more than N" setting, and without it those checks can only be unknown.
var compareRe = regexp.MustCompile(`^n:(.+?)\s+compare\s+(>=|<=|==|!=|>|<)\s*(-?\d+)$`)

func applyNumericCompare(content, matcher string) (bool, bool) {
	m := compareRe.FindStringSubmatch(strings.TrimSpace(matcher))
	if m == nil {
		return false, false
	}
	re, err := regexp.Compile("(?im)" + m[1])
	if err != nil {
		return false, false
	}
	found := re.FindStringSubmatch(content)
	if len(found) < 2 {
		// The setting isn't present at all. That is a definite answer —
		// an absent setting is not a passing setting — not an unknown.
		return false, true
	}
	actual, err := strconv.ParseInt(strings.TrimSpace(found[1]), 10, 64)
	if err != nil {
		return false, true
	}
	want, err := strconv.ParseInt(m[3], 10, 64)
	if err != nil {
		return false, false
	}
	switch m[2] {
	case ">=":
		return actual >= want, true
	case "<=":
		return actual <= want, true
	case ">":
		return actual > want, true
	case "<":
		return actual < want, true
	case "==":
		return actual == want, true
	case "!=":
		return actual != want, true
	}
	return false, false
}

// looksLikeUnknownPrefix distinguishes a bare literal value from a rule
// form this engine does not implement.
//
// The two are genuinely ambiguous: "0" and "EnableFirewall" are literal
// registry values to match, while "weird:matcher" is somebody's syntax we
// don't speak. The discriminator is a short lowercase prefix followed by a
// colon — the shape every form in this dialect uses. A Windows path like
// "C:\\Windows" is not caught by it, since drive letters are uppercase and
// the known forms are not.
//
// Getting this wrong in the permissive direction is the dangerous one: an
// unimplemented form silently read as a literal would compare a registry
// value against the literal text of a rule and confidently report "fail",
// which looks exactly like a real finding.
var unknownPrefixRe = regexp.MustCompile(`^[a-z]{1,6}:`)

func looksLikeUnknownPrefix(matcher string) bool {
	if strings.HasPrefix(matcher, "r:") || strings.HasPrefix(matcher, "n:") {
		return false
	}
	return unknownPrefixRe.MatchString(matcher)
}

// matcherUnderstood reports whether the right-hand side of a rule is
// syntax this engine implements. Separated from applyMatcher so it can be
// checked before the target is evaluated.
func matcherUnderstood(matcher string) bool {
	matcher = strings.TrimSpace(matcher)
	if strings.Contains(matcher, " && ") {
		_, ok := parseLineMatcher(matcher)
		return ok
	}
	if strings.HasPrefix(matcher, "n:") {
		return compareRe.MatchString(matcher)
	}
	matcher = strings.TrimPrefix(matcher, "!")
	if looksLikeUnknownPrefix(matcher) {
		return false
	}
	pattern, ok := strings.CutPrefix(matcher, "r:")
	if !ok {
		return matcher != "" // a bare literal to compare against
	}
	_, err := regexp.Compile("(?im)" + pattern)
	return err == nil
}

// applyMatcher handles the right-hand side of a rule against one value as
// a whole — how a registry value is compared. File and command content go
// through applyContentMatcher, which works line by line.
func applyMatcher(content, matcher string) (bool, bool) {
	matcher = strings.TrimSpace(matcher)
	if strings.Contains(matcher, " && ") {
		return applyContentMatcher(content, matcher)
	}
	if strings.HasPrefix(matcher, "n:") {
		return applyNumericCompare(content, matcher)
	}
	negate := false
	if rest, ok := strings.CutPrefix(matcher, "!"); ok {
		negate = true
		matcher = rest
	}
	if looksLikeUnknownPrefix(matcher) {
		return false, false
	}
	pattern, ok := strings.CutPrefix(matcher, "r:")
	if !ok {
		// A bare matcher is a literal value to equal, which is how the
		// Windows benchmarks express nearly every registry assertion:
		//   r:HKLM\...\Lsa -> CrashOnAuditFail -> 0
		// Reading that as "unrecognized" left 316 rules of the CIS Windows
		// Server 2025 policy unevaluable — most of the gap on that
		// platform.
		matched := strings.EqualFold(strings.TrimSpace(content), strings.TrimSpace(matcher))
		if negate {
			return !matched, true
		}
		return matched, true
	}
	// Wazuh's patterns are mostly plain regex; a malformed one is an
	// unknown rather than a silent pass.
	re, err := regexp.Compile("(?im)" + pattern)
	if err != nil {
		return false, false
	}
	matched := re.MatchString(content)
	if negate {
		return !matched, true
	}
	return matched, true
}

// linePart is one term of a matcher: r:, !r: or n: … compare.
type linePart struct {
	re     *regexp.Regexp
	negate bool
	op     string // set for n: terms
	want   int64
}

func (p linePart) holds(line string) bool {
	if p.op == "" {
		return p.re.MatchString(line) != p.negate
	}
	m := p.re.FindStringSubmatch(line)
	if len(m) < 2 {
		return false
	}
	got, err := strconv.ParseInt(strings.TrimSpace(m[1]), 10, 64)
	if err != nil {
		return false
	}
	switch p.op {
	case ">=":
		return got >= p.want
	case "<=":
		return got <= p.want
	case ">":
		return got > p.want
	case "<":
		return got < p.want
	case "==":
		return got == p.want
	case "!=":
		return got != p.want
	}
	return false
}

// parseLineMatcher reads a matcher of r:, !r: and n: terms joined by
// " && ". ok is false for anything else, including a bare literal.
func parseLineMatcher(matcher string) ([]linePart, bool) {
	var parts []linePart
	for _, term := range strings.Split(matcher, " && ") {
		term = strings.TrimSpace(term)
		var p linePart
		pattern := ""
		switch {
		case strings.HasPrefix(term, "n:"):
			m := compareRe.FindStringSubmatch(term)
			if m == nil {
				return nil, false
			}
			want, err := strconv.ParseInt(m[3], 10, 64)
			if err != nil {
				return nil, false
			}
			pattern, p.op, p.want = m[1], m[2], want
		case strings.HasPrefix(term, "!r:"):
			pattern, p.negate = strings.TrimPrefix(term, "!r:"), true
		case strings.HasPrefix(term, "r:"):
			pattern = strings.TrimPrefix(term, "r:")
		default:
			return nil, false
		}
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return nil, false
		}
		p.re = re
		parts = append(parts, p)
	}
	return parts, len(parts) > 0
}

// applyContentMatcher: true when one line satisfies every term. A bare
// literal keeps applyMatcher's whole-value comparison.
func applyContentMatcher(content, matcher string) (bool, bool) {
	parts, ok := parseLineMatcher(strings.TrimSpace(matcher))
	if !ok {
		return applyMatcher(content, matcher)
	}
	for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		if content == "" {
			break // no output has no lines; "!r:x" must not hold on nothing
		}
		line = strings.TrimSuffix(line, "\r")
		all := true
		for _, p := range parts {
			if !p.holds(line) {
				all = false
				break
			}
		}
		if all {
			return true, true
		}
	}
	return false, true
}

// Bounds on a d: scan, so a rule naming a large tree stays cheap.
const (
	dirRuleMaxDepth = 3
	dirRuleMaxFiles = 2000
)

// evaluateDirRule handles d:<dir>[/*] [-> r:<file name> [-> <matcher>]].
// The directory is walked a few levels down; the name pattern is matched
// against each file's base name.
func evaluateDirRule(dir, rest string, hasMatcher bool) (bool, bool) {
	dir = strings.TrimSpace(dir)
	dir = strings.TrimSuffix(dir, "/*")
	if len(dir) > 1 {
		dir = strings.TrimSuffix(dir, "/")
	}
	nameMatcher, contentMatcher, hasContent := strings.Cut(rest, " -> ")
	nameMatcher, contentMatcher = strings.TrimSpace(nameMatcher), strings.TrimSpace(contentMatcher)
	var nameParts []linePart
	if hasMatcher {
		var ok bool
		if nameParts, ok = parseLineMatcher(nameMatcher); !ok {
			return false, false
		}
		if hasContent && !matcherUnderstood(contentMatcher) {
			return false, false
		}
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false, true
	}
	if !hasMatcher {
		return true, true
	}
	found, seen := false, 0
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			if found || seen >= dirRuleMaxFiles {
				return
			}
			path := d + "/" + e.Name()
			if e.IsDir() {
				if depth < dirRuleMaxDepth {
					walk(path, depth+1)
				}
				continue
			}
			seen++
			nameOK := true
			for _, p := range nameParts {
				if !p.holds(e.Name()) {
					nameOK = false
					break
				}
			}
			if !nameOK {
				continue
			}
			if !hasContent {
				found = true
				return
			}
			if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if ok, _ := applyContentMatcher(string(data), contentMatcher); ok {
				found = true
				return
			}
		}
	}
	walk(dir, 1)
	return found, true
}

func runCheckCommand(ctx context.Context, command string) string {
	ctx, cancel := context.WithTimeout(ctx, complianceCommandTimeout)
	defer cancel()
	cmd := shellCommand(ctx, command)
	cmd.Env = append(childEnv(), "LC_ALL=C")
	out, _ := cmd.CombinedOutput() // a non-zero exit is itself an answer
	// PowerShell ends every line with CRLF, and a rule anchored with $
	// (r:^True$) would then fail on "True\r" — every typed Enforce policy
	// read as drifted on every Windows machine before this. Normalising
	// here keeps rules platform-neutral; nothing legitimately matches \r.
	return strings.ReplaceAll(string(out), "\r\n", "\n")
}

// collectCompliance runs whatever policy the server has assigned. The
// checks arrive from the control plane rather than being compiled in, so a
// new benchmark is a data change rather than a fleet-wide agent upgrade.
func collectCompliance(ctx context.Context, checks []proto.ComplianceCheck) []proto.ComplianceResult {
	out := make([]proto.ComplianceResult, 0, len(checks))
	for _, check := range checks {
		if ctx.Err() != nil {
			break
		}
		out = append(out, evaluateCheck(ctx, check))
	}
	return out
}

var _ = exec.Command
