package server

import "github.com/mustra-dev/mustra/internal/groups"
import "testing"
import "strings"

// A small fleet with the shapes that matter: two OSes, one device that
// never reported the software sensor, and one that reported an empty list.
func testFleet() []groups.Device {
	return []groups.Device{
		{AgentID: "a1", Hostname: "web-01", OS: "linux", Online: true,
			Sensors: map[string][]map[string]any{
				"installed_apps": {{"name": "curl"}, {"name": "jq"}},
			}},
		{AgentID: "a2", Hostname: "web-02", OS: "linux", Online: true,
			Sensors: map[string][]map[string]any{
				"installed_apps": {{"name": "curl"}},
			}},
		{AgentID: "a3", Hostname: "mac-01", OS: "darwin", Online: true,
			Sensors: map[string][]map[string]any{
				"installed_apps": {},
			}},
		{AgentID: "a4", Hostname: "new-01", OS: "linux", Online: false},
	}
}

// A single-field question collapses identical answers into one counted
// row. This is what keeps "get os from all machines" readable at any fleet
// size, and it's the behaviour the results grid is built around.
func TestSingleFieldQuestionCounts(t *testing.T) {
	got := answerQuestion(testFleet(), questionRequest{Get: []string{"os"}})
	if !got.Counting {
		t.Fatal("a single-field question must be counting")
	}
	if len(got.Rows) != 2 {
		t.Fatalf("want 2 distinct answers, got %d: %#v", len(got.Rows), got.Rows)
	}
	// Commonest first.
	if got.Rows[0].Values[0] != "linux" || got.Rows[0].Count != 3 {
		t.Errorf("want linux x3 first, got %v x%d", got.Rows[0].Values, got.Rows[0].Count)
	}
	if got.Rows[1].Values[0] != "darwin" || got.Rows[1].Count != 1 {
		t.Errorf("want darwin x1, got %v x%d", got.Rows[1].Values, got.Rows[1].Count)
	}
}

// Asking for more than one field means the combination is the answer, so
// each endpoint gets its own row.
func TestMultiFieldQuestionIsPerDevice(t *testing.T) {
	got := answerQuestion(testFleet(), questionRequest{Get: []string{"hostname", "os"}})
	if got.Counting {
		t.Fatal("a multi-field question must not be counting")
	}
	if len(got.Rows) != 4 {
		t.Fatalf("want one row per endpoint, got %d", len(got.Rows))
	}
}

// A device answering several values contributes to each of them — that is
// what turns one question into a software census rather than a list of
// machines.
func TestCountingSpreadsMultiValuedAnswers(t *testing.T) {
	got := answerQuestion(testFleet(), questionRequest{Get: []string{"installed_apps.name"}})
	counts := map[string]int{}
	for _, row := range got.Rows {
		counts[row.Values[0]] = row.Count
	}
	if counts["curl"] != 2 {
		t.Errorf("curl is on two devices, got %d", counts["curl"])
	}
	if counts["jq"] != 1 {
		t.Errorf("jq is on one device, got %d", counts["jq"])
	}
	// a4 never reported the sensor: it is unmeasured, not "has no software".
	if counts[noResult] != 1 {
		t.Errorf("the device that never reported should answer %q once, got %d", noResult, counts[noResult])
	}
	// a3 reported an empty list: it genuinely has none, which is a real
	// answer and must not be lumped in with the unmeasured one.
	if counts[""] != 1 {
		t.Errorf("the device reporting an empty list should answer empty once, got %d", counts[""])
	}
	// Only the three that actually answered count as reporting.
	if got.Reporting != 3 {
		t.Errorf("want 3 reporting, got %d", got.Reporting)
	}
}

// The from clause is evaluated first and narrows everything downstream.
func TestWhereClauseNarrowsBeforeCounting(t *testing.T) {
	got := answerQuestion(testFleet(), questionRequest{
		Get:      []string{"hostname"},
		Where:    []groups.Rule{{Field: "os", Op: groups.OpEquals, Value: "linux"}},
		MatchAll: true,
	})
	if got.Matched != 3 {
		t.Fatalf("want 3 linux endpoints matched, got %d", got.Matched)
	}
	if got.Total != 4 {
		t.Errorf("total should stay the whole fleet, got %d", got.Total)
	}
	for _, row := range got.Rows {
		if row.Values[0] == "mac-01" {
			t.Error("a filtered-out endpoint leaked into the answer")
		}
	}
}

func TestDescribeQuestionReadsAsASentence(t *testing.T) {
	got := describeQuestion(questionRequest{
		Get:      []string{"hostname", "os"},
		Where:    []groups.Rule{{Field: "os", Op: groups.OpEquals, Value: "linux"}},
		MatchAll: true,
	})
	want := "get hostname and os from all machines with os equals linux"
	if got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// A grouped where clause: (os is darwin or hostname starts with web) and
// online. new-01 is linux but offline and not web-*, so three match; the
// history text keeps the brackets.
func TestGroupedWhereClause(t *testing.T) {
	either := groups.Rule{Field: groups.GroupField, Op: groups.OpGroup,
		Value: `{"all":false,"rules":[{"field":"os","op":"equals","value":"darwin"},{"field":"hostname","op":"starts_with","value":"web"}]}`}
	req := questionRequest{Get: []string{"hostname"}, MatchAll: true,
		Where: []groups.Rule{either, {Field: "online", Op: "equals", Value: "true"}}}
	got := answerQuestion(testFleet(), req)
	if got.Matched != 3 {
		t.Fatalf("matched %d, want 3", got.Matched)
	}
	want := "get hostname from all machines with (os equals darwin or hostname starts with web) and online equals true"
	if d := describeQuestion(req); d != want {
		t.Errorf("described as %q, want %q", d, want)
	}
}

// A value filter trims the sensor's answer to matching rows and drops
// machines with none: jq is on web-01 only, curl on web-01 and web-02.
func TestValueFilterTrimsAnswers(t *testing.T) {
	got := answerQuestion(testFleet(), questionRequest{Get: []string{"installed_apps.name[contains j]"}})
	if got.Matched != 1 || len(got.Rows) != 1 || got.Rows[0].Values[0] != "jq" {
		t.Fatalf("want only jq on one machine, got matched=%d rows=%#v", got.Matched, got.Rows)
	}
	if got.Get[0] != "installed_apps.name[contains j]" {
		t.Errorf("the heading keeps the filter: %q", got.Get[0])
	}
	got = answerQuestion(testFleet(), questionRequest{Get: []string{"hostname", "installed_apps.name[equals curl]"}})
	if got.Matched != 2 {
		t.Fatalf("curl is on two machines, matched %d", got.Matched)
	}
	for _, r := range got.Rows {
		if r.Values[1] != "curl" {
			t.Errorf("%s: want only curl, got %q", r.Hostname, r.Values[1])
		}
	}
	// Two filters on one sensor both apply to each row; an inventory
	// filter narrows the machines.
	got = answerQuestion(testFleet(), questionRequest{Get: []string{"installed_apps.name[contains u][not_contains j]", "hostname[equals web-02]"}})
	if got.Matched != 1 || got.Rows[0].Values[0] != "curl" {
		t.Fatalf("want curl on web-02, got matched=%d %#v", got.Matched, got.Rows)
	}
}

func TestSplitGetFilter(t *testing.T) {
	f, rules, err := splitGetFilter(`installed_apps.name[contains "Google Chrome"][greater_than 3]`)
	if err != nil || f != "installed_apps.name" || len(rules) != 2 || rules[0].Value != "Google Chrome" || rules[1].Op != "gt" {
		t.Fatalf("got %q %#v %v", f, rules, err)
	}
	for _, bad := range []string{"installed_apps.name[contains x", "installed_apps.name[bogus x]", "[contains x]", "installed_apps.count[equals 3]"} {
		if _, _, err := parseGetFilters([]string{bad}); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestLiveSensorsFor(t *testing.T) {
	where := []groups.Rule{
		{Field: "disks.used_percent", Op: "gt", Value: "80"},
		{Field: groups.GroupField, Op: groups.OpGroup, Value: `{"all":false,"rules":[{"field":"services.name","op":"equals","value":"sshd"}]}`},
	}
	got := liveSensorsFor([]string{"hostname", "installed_apps.name[contains curl]", "installed_apps.version"}, where)
	if strings.Join(got, ",") != "installed_apps,services" {
		t.Errorf("want installed_apps,services (disks has no live query), got %v", got)
	}
}

func TestOverlayLiveReplacesOnlyAnsweredSensors(t *testing.T) {
	fleet := testFleet()
	fresh := map[string]map[string][]map[string]any{"a2": {"installed_apps": {{"name": "htop"}}}}
	got := overlayLive(fleet, fresh)
	if v := groups.Values(got[1], "installed_apps.name"); len(v) != 1 || v[0] != "htop" {
		t.Errorf("a2 should answer live: %v", v)
	}
	if v := groups.Values(got[0], "installed_apps.name"); len(v) != 2 {
		t.Errorf("a1 did not answer and keeps its cache: %v", v)
	}
	if v := groups.Values(fleet[1], "installed_apps.name"); v[0] != "curl" {
		t.Errorf("the cached fleet must not be modified: %v", v)
	}
}
