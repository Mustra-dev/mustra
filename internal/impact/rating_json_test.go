package impact

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

// rowKeys is the set of keys a row is sent with.
func rowKeys(t *testing.T, r Rating) map[string]any {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A row says only what applies to its kind: an endpoint is neither enabled
// nor disabled, and a user reaches no endpoints through sessions.
func TestRowsCarryOnlyTheirKindsFields(t *testing.T) {
	in := fixture()
	lx := in.Endpoints["lx1"]
	lx.Online = false
	in.Endpoints["lx1"] = lx
	a := Analyze(in)

	principalOnly := []string{"controls", "direct_controls", "controls_critical", "sessions", "member_users", "enabled", "admin_count"}
	endpointOnly := []string{"hostname", "admins", "outbound", "inbound", "online"}

	ep := rowKeys(t, rating(t, a, "lx1"))
	for _, k := range principalOnly {
		if _, ok := ep[k]; ok {
			t.Errorf("endpoint row carries %q: %v", k, ep)
		}
	}
	if v, ok := ep["online"]; !ok || v != false {
		t.Errorf("an offline endpoint should say online: false, got %v", ep)
	}
	if v, ok := ep["admins"]; !ok || v != float64(0) {
		t.Errorf("an endpoint with no administrators should say admins: 0, got %v", ep)
	}

	for _, id := range []string{"S-carol", "S-IT"} {
		p := rowKeys(t, rating(t, a, id))
		for _, k := range endpointOnly {
			if _, ok := p[k]; ok {
				t.Errorf("%s row carries %q: %v", id, k, p)
			}
		}
		for _, k := range principalOnly {
			if _, ok := p[k]; !ok {
				t.Errorf("%s row leaves out %q: %v", id, k, p)
			}
		}
	}
	if v := rowKeys(t, rating(t, a, "S-carol"))["enabled"]; v != false {
		t.Errorf("carol is disabled, row says enabled: %v", v)
	}
}

func TestComputedAtIsUTC(t *testing.T) {
	if loc := Analyze(fixture()).ComputedAt.Location(); loc != time.UTC {
		t.Fatalf("computed_at in %v, want UTC", loc)
	}
}

// Rows with the same score and name come back in the same order on every
// analysis, so the overview's top rows do not change between recomputes.
func TestEqualRowsHaveAStableOrder(t *testing.T) {
	in := Input{Principals: map[string]Principal{}, Endpoints: map[string]Endpoint{}}
	var want []string
	for _, id := range []string{"local:web1:a", "local:web2:a", "local:web3:a", "local:web4:a", "local:web5:a", "local:web6:a"} {
		in.Principals[id] = Principal{ID: id, Kind: "local_group", Name: "admin", Enabled: true}
		want = append(want, id)
	}
	for range 20 {
		var got []string
		for _, g := range Analyze(in).Groups {
			got = append(got, g.ID)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("groups in order %v, want %v", got, want)
		}
	}
}
