package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Deploy pending patches, on the Risk page's remediation table, patches
// the endpoints a row names in patch_pending_agent_ids. Those are exactly
// the endpoints whose patches sensor offers the update, and endpoints and
// agent_ids name the same machine at each index, whatever order the
// database's collation lists the hostnames in (#99).
//
// The case that went wrong: db-01 and FIN-LT-… share a vulnerable package
// and only FIN-LT-… offers the update. A case-insensitive collation lists
// db-01 first, a bytewise sort puts FIN-LT-… first, and the console's
// pairing by index picked db-01. A second FIN-LT-… without the update
// matched by hostname as well. The pairing check bites only on a database
// with a case-insensitive collation; TestSortEndpointPairsKeepsEachIDWithItsHostname
// covers it on any.
func TestRemediationTargetsTheEndpointsThatOfferThePatch(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}}
	s.live.setAgent(time.Hour, 0, "")

	suffix := idgen.New("")
	pkg := "risk-pkg-" + suffix
	hostOf := map[string]string{}
	register := func(hostname string, offersPatch bool) string {
		id := idgen.New("agt-")
		hostOf[id] = hostname
		if err := st.UpsertOnRegister(ctx, id, proto.AgentInfo{Hostname: hostname, OS: "linux", Arch: "amd64", Version: "0.57.42"}); err != nil {
			t.Fatal(err)
		}
		if err := st.ReplaceAgentVulnerabilities(ctx, id, []store.AgentVulnerability{{
			AgentID: id, PackageName: pkg, PackageVersion: "1.0", VulnID: "CVE-2026-" + suffix[:8], Severity: "high",
		}}); err != nil {
			t.Fatal(err)
		}
		if offersPatch {
			data, _ := json.Marshal([]proto.PatchInfo{{Name: pkg, CurrentVersion: "1.0", NewVersion: "1.1"}})
			if err := st.UpsertSensorData(ctx, id, string(proto.SensorPatches), time.Now(), data); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	register("db-01-"+suffix, false)
	offers := register("FIN-LT-"+suffix, true)
	register("FIN-LT-"+suffix, false)

	w := httptest.NewRecorder()
	s.handleRemediation(w, httptest.NewRequest(http.MethodGet, "/api/risk/remediation", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp struct {
		Packages []struct {
			Package              string   `json:"package"`
			Endpoints            []string `json:"endpoints"`
			AgentIDs             []string `json:"agent_ids"`
			PatchPending         []string `json:"patch_pending"`
			PatchPendingAgentIDs []string `json:"patch_pending_agent_ids"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, row := range resp.Packages {
		if row.Package != pkg {
			continue
		}
		if len(row.Endpoints) != 3 || len(row.AgentIDs) != 3 {
			t.Fatalf("want three endpoints, got %v / %v", row.Endpoints, row.AgentIDs)
		}
		for k, id := range row.AgentIDs {
			if hostOf[id] != row.Endpoints[k] {
				t.Errorf("index %d pairs %s with %s, which is %s", k, row.Endpoints[k], id, hostOf[id])
			}
		}
		if len(row.PatchPendingAgentIDs) != 1 || row.PatchPendingAgentIDs[0] != offers {
			t.Errorf("patch_pending_agent_ids %v, want only %s", row.PatchPendingAgentIDs, offers)
		}
		if len(row.PatchPending) != 1 || row.PatchPending[0] != "FIN-LT-"+suffix {
			t.Errorf("patch_pending %v, want only FIN-LT-%s", row.PatchPending, suffix)
		}
		return
	}
	t.Fatalf("no remediation row for %s", pkg)
}
