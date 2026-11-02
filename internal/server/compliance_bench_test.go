package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestPickBenchmark(t *testing.T) {
	policies := []store.CompliancePolicy{
		{ID: "d12", Name: "CIS Debian 12"}, {ID: "d13", Name: "CIS Debian 13"}, {ID: "u2404", Name: "CIS Ubuntu 24.04"},
		{ID: "ws25", Name: "CIS Windows Server 2025"}, {ID: "ws22", Name: "CIS Windows Server 2022"}, {ID: "w11", Name: "CIS Windows 11"},
		{ID: "m26", Name: "CIS macOS 26"}, {ID: "base", Name: "Linux baseline (built in)"},
	}
	cases := []struct {
		a     store.AgentRecord
		want  string
		exact bool
	}{
		{store.AgentRecord{OS: "linux", Platform: "debian", PlatformVersion: "12.15"}, "d12", true},
		{store.AgentRecord{OS: "linux", Platform: "raspbian", PlatformVersion: "13.7"}, "d13", true},
		{store.AgentRecord{OS: "linux", Platform: "ubuntu", PlatformVersion: "25.10"}, "u2404", false},
		{store.AgentRecord{OS: "windows", Platform: "Microsoft Windows Server 2025 Standard"}, "ws25", true},
		{store.AgentRecord{OS: "windows", Platform: "Microsoft Windows Server 2019 Datacenter"}, "ws22", false},
		{store.AgentRecord{OS: "windows", Platform: "Microsoft Windows 11 Pro"}, "w11", true},
		{store.AgentRecord{OS: "darwin", Platform: "darwin", PlatformVersion: "27.0.1"}, "m26", false},
		{store.AgentRecord{OS: "linux", Platform: "haos", PlatformVersion: "18.3"}, "", false},
	}
	for _, c := range cases {
		p, exact, ok := pickBenchmark(c.a, policies)
		if c.want == "" {
			if ok {
				t.Errorf("%s: no benchmark expected, got %s", c.a.Platform, p.ID)
			}
			continue
		}
		if !ok || p.ID != c.want || exact != c.exact {
			t.Errorf("%s %s: got %s exact=%v ok=%v", c.a.Platform, c.a.PlatformVersion, p.ID, exact, ok)
		}
	}
}

func TestHardeningScore(t *testing.T) {
	score, pass, fail, unknown := hardeningScore([]store.ComplianceResult{
		{State: "pass", Severity: "high"}, {State: "fail", Severity: "low"}, {State: "unknown", Severity: "critical"}, {State: "pass"},
	})
	// passed weight 3+1 of evaluated 3+1+1; unknown is left out
	if score != 80 || pass != 2 || fail != 1 || unknown != 1 {
		t.Fatalf("score %v pass %d fail %d unknown %d", score, pass, fail, unknown)
	}
	if s, _, _, _ := hardeningScore(nil); s != 0 {
		t.Fatal("no evaluated checks scores 0 (and is not shown)")
	}
	if csvSafe("=HYPERLINK(1)") != "'=HYPERLINK(1)" || csvSafe("ok") != "ok" {
		t.Fatal("CSV cells from endpoints must not become formulas")
	}
}

// An endpoint never scanned has no policy, benchmark or score, and no
// checked_at either, rather than year 1 (#102).
func TestUnscannedEndpointScoreLeavesOutCheckedAt(t *testing.T) {
	b, err := json.Marshal(endpointScore{AgentID: "agt-1", Hostname: "FIN-LT-0142", OS: "windows", Trend: []float64{}})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"checked_at", "policy_id", "benchmark", "score"} {
		if v, ok := got[k]; ok {
			t.Errorf("%s sent as %v for an endpoint never scanned", k, v)
		}
	}
	b, _ = json.Marshal(endpointScore{CheckedAt: time.Date(2026, 10, 20, 2, 14, 37, 0, time.UTC)})
	if !strings.Contains(string(b), `"checked_at":"2026-10-20T02:14:37Z"`) {
		t.Errorf("a scanned endpoint's checked_at is missing: %s", b)
	}
}
