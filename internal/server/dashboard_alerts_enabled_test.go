package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// A new alert was always enabled, whatever the body or the console's
// Enabled select said (#108). A create now keeps the enabled it is sent,
// and only one that leaves it out starts enabled.
func TestDashboardAlertCreateKeepsEnabled(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()

	dash, panel := idgen.New("db-"), idgen.New("pn-")
	if err := st.UpsertDashboard(ctx, store.Dashboard{ID: dash, Name: "alerts enabled",
		Panels: json.RawMessage(`[{"id":"` + panel + `","title":"Endpoints","source":"endpoints","chart":"number"}]`)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteDashboard(context.Background(), dash) })

	body := func(enabled string) string {
		b := `{"name":"enabled test","dashboard_id":"` + dash + `","panel_id":"` + panel + `","condition":{"op":"nonzero"},"severity":"low"`
		if enabled != "" {
			b += `,"enabled":` + enabled
		}
		return b + `}`
	}
	save := func(method, id, b string) store.DashboardAlert {
		t.Helper()
		path := "/api/dashboard-alerts"
		if id != "" {
			path += "/" + id
		}
		w := callSave(s.handleSaveDashboardAlert, method, path, id, b)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, b, w.Code, w.Body)
		}
		var a store.DashboardAlert
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteDashboardAlert(context.Background(), a.ID) })
		stored, err := st.GetDashboardAlert(ctx, a.ID)
		if err != nil || stored == nil {
			t.Fatalf("stored alert %s: %v, %v", a.ID, stored, err)
		}
		if stored.Enabled != a.Enabled {
			t.Errorf("answered enabled %v, stored %v", a.Enabled, stored.Enabled)
		}
		return a
	}

	if a := save("POST", "", body("false")); a.Enabled {
		t.Error("created with enabled false: enabled, want disabled")
	}
	if a := save("POST", "", body("true")); !a.Enabled {
		t.Error("created with enabled true: disabled, want enabled")
	}
	on := save("POST", "", body(""))
	if !on.Enabled {
		t.Error("created without enabled: disabled, want enabled")
	}
	// An update replaces the whole alert, as it always has.
	if a := save("PUT", on.ID, body("")); a.Enabled {
		t.Error("updated without enabled: still enabled, want the full replace to switch it off")
	}
	if a := save("PUT", on.ID, body("true")); !a.Enabled {
		t.Error("updated with enabled true: disabled, want enabled")
	}
}
