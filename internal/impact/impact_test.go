package impact

import "testing"

// A small domain with the shapes that matter: a privileged group that
// administers everything Windows, a user in it who is signed in on a
// workstation, a plain user who is a local admin on one machine, a
// disabled account that still holds a grant, and a domain controller.
func fixture() Input {
	in := Input{
		Principals: map[string]Principal{
			"S-DA":        {ID: "S-DA", Kind: "group", Name: "Domain Admins", Enabled: true, AdminCount: true},
			"S-IT":        {ID: "S-IT", Kind: "group", Name: "IT Staff", Enabled: true},
			"S-alice":     {ID: "S-alice", Kind: "user", Name: "alice", Enabled: true, AdminCount: true},
			"S-bob":       {ID: "S-bob", Kind: "user", Name: "bob", Enabled: true},
			"S-carol":     {ID: "S-carol", Kind: "user", Name: "carol", Enabled: false},
			"local:ws2:x": {ID: "local:ws2:x", Kind: "local", Name: "svc", Enabled: true},
		},
		Members: map[string][]string{
			"S-DA": {"S-alice"},
			"S-IT": {"S-bob", "S-DA"}, // Domain Admins nested inside IT Staff
		},
		Admins: map[string][]Grant{
			"dc01": {{"S-DA", "Administrators"}},
			"ws1":  {{"S-DA", "Administrators"}, {"S-bob", "Administrators"}, {"S-carol", "Administrators"}},
			"ws2":  {{"S-IT", "Administrators"}, {"local:ws2:x", "Administrators"}},
			"lx1":  {},
		},
		Sessions: map[string][]string{
			"ws1": {"S-alice"}, // a domain admin signed in on a workstation
			"ws2": {"S-bob"},
		},
		Endpoints: map[string]Endpoint{
			"dc01": {AgentID: "dc01", Hostname: "dc01", OS: "windows", DomainController: true, Online: true},
			"ws1":  {AgentID: "ws1", Hostname: "ws1", OS: "windows", Online: true},
			"ws2":  {AgentID: "ws2", Hostname: "ws2", OS: "windows", Online: true, Criticality: "high"},
			"lx1":  {AgentID: "lx1", Hostname: "lx1", OS: "linux", Online: true},
		},
	}
	return in
}

func rating(t *testing.T, a *Analysis, id string) Rating {
	t.Helper()
	r, ok := a.ratingOf(id)
	if !ok {
		t.Fatalf("no rating for %s", id)
	}
	return r
}

func TestNestedGroupsGrantControl(t *testing.T) {
	a := Analyze(fixture())
	alice := rating(t, a, "S-alice")
	// Domain Admins administers dc01 and ws1 by name, and ws2 through IT
	// Staff (Domain Admins is nested in it). alice inherits all three.
	if alice.Controls != 3 || alice.DirectControls != 0 {
		t.Fatalf("alice controls=%d direct=%d, want 3 nested", alice.Controls, alice.DirectControls)
	}
	if alice.ControlsCritical != 1 || alice.Level != "critical" {
		t.Fatalf("alice critical=%d level=%s, want a domain controller in reach and critical", alice.ControlsCritical, alice.Level)
	}
	bob := rating(t, a, "S-bob")
	if bob.Controls != 2 || bob.DirectControls != 1 {
		t.Fatalf("bob controls=%d direct=%d, want ws1 by name and ws2 via IT Staff", bob.Controls, bob.DirectControls)
	}
	it := rating(t, a, "S-IT")
	if it.MemberUsers != 2 {
		t.Fatalf("IT Staff member users=%d, want bob and alice (nested)", it.MemberUsers)
	}
}

func TestOutboundFollowsSessionsThenRights(t *testing.T) {
	a := Analyze(fixture())
	// ws1 has alice signed in; alice administers dc01, ws1, ws2. So ws1
	// reaches dc01 and ws2 in one hop. ws2 has bob, who reaches ws1 (and
	// ws2 itself, excluded) -- already counted.
	ws1 := rating(t, a, "ws1")
	if ws1.Outbound != 2 {
		t.Fatalf("ws1 outbound=%d, want dc01 and ws2", ws1.Outbound)
	}
	d, _ := a.Detail("ws1")
	hops := map[string]int{}
	for _, r := range d.Outbound {
		hops[r.Hostname] = r.Hops
	}
	if hops["dc01"] != 1 || hops["ws2"] != 1 {
		t.Fatalf("ws1 hops=%v, want dc01 and ws2 at 1", hops)
	}
	// ws2 has bob signed in; bob administers ws1 (hop 1); ws1 exposes
	// alice, who reaches dc01 (hop 2).
	d2, _ := a.Detail("ws2")
	hops = map[string]int{}
	for _, r := range d2.Outbound {
		hops[r.Hostname] = r.Hops
	}
	if hops["ws1"] != 1 || hops["dc01"] != 2 {
		t.Fatalf("ws2 hops=%v, want ws1 at 1 and dc01 at 2", hops)
	}
	dc := rating(t, a, "dc01")
	if dc.Inbound != 2 || dc.Outbound != 0 {
		t.Fatalf("dc01 inbound=%d outbound=%d, want reachable from ws1 and ws2, reaching nothing (no sessions)", dc.Inbound, dc.Outbound)
	}
	lx := rating(t, a, "lx1")
	if lx.Level != "none" || lx.Admins != 0 {
		t.Fatalf("lx1 with no grants and no sessions should be none, got %s / %d admins", lx.Level, lx.Admins)
	}
}

func TestFindings(t *testing.T) {
	a := Analyze(fixture())
	got := map[string]Finding{}
	for _, f := range a.Findings {
		got[f.Category+"|"+f.SubjectName] = f
	}
	if f, ok := got["Privileged account signed in outside the domain controllers|alice"]; !ok || f.Severity != "critical" || f.Count != 1 {
		t.Errorf("expected a critical finding for alice's session on ws1, got %+v", f)
	}
	if f, ok := got["Disabled account still administers endpoints|carol"]; !ok || f.Count != 1 {
		t.Errorf("expected carol's stale grant to be found, got %+v", f)
	}
	if _, ok := got["Account administers a large share of the fleet|alice"]; !ok {
		t.Errorf("alice administers 3 of 4 endpoints and should be flagged")
	}
	if _, ok := got["Group grants administration broadly|Domain Admins"]; !ok {
		t.Errorf("Domain Admins administers 3 of 4 endpoints and should be flagged")
	}
	if a.Findings[0].Severity != "critical" {
		t.Errorf("findings should be ordered most severe first, got %s", a.Findings[0].Severity)
	}
}

func TestShortestPath(t *testing.T) {
	a := Analyze(fixture())
	// From ws2 to the domain controller: ws2 -> bob (signed in) -> ws1
	// (bob administers) -> alice (signed in) -> Domain Admins (member of)
	// -> dc01 (administers).
	path := a.ShortestPath("ws2", "dc01")
	var names []string
	for _, s := range path {
		names = append(names, s.Name)
	}
	want := []string{"ws2", "bob", "ws1", "alice", "Domain Admins", "dc01"}
	if len(names) != len(want) {
		t.Fatalf("path %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("path %v, want %v", names, want)
		}
	}
	if path[1].Edge != "signed in on" || path[2].Edge != "administers" || path[4].Edge != "member of" {
		t.Errorf("edges wrong: %+v", path)
	}
	if a.ShortestPath("lx1", "dc01") != nil {
		t.Errorf("lx1 has no sessions and should reach nothing")
	}
}

func TestEndpointDetailShowsGroupsHoldingTheGrant(t *testing.T) {
	a := Analyze(fixture())
	d, ok := a.Detail("ws2")
	if !ok {
		t.Fatal("no detail for ws2")
	}
	var direct, indirect []string
	for _, r := range d.DirectControl {
		direct = append(direct, r.Name)
	}
	for _, r := range d.IndirectControl {
		indirect = append(indirect, r.Name)
	}
	// By name: IT Staff (the group) and the local svc account. Through
	// the group: bob and alice.
	if len(direct) != 2 || len(indirect) != 2 {
		t.Fatalf("direct=%v indirect=%v", direct, indirect)
	}
}

// A local group that administers many endpoints (sudo on every Linux box)
// is not a shared account, and an account that administers two domain
// controllers but little else is reported for that, not for "share".
func TestLocalGroupsAndCriticalCategory(t *testing.T) {
	in := Input{Principals: map[string]Principal{}, Members: map[string][]string{}, Admins: map[string][]Grant{}, Sessions: map[string][]string{}, Endpoints: map[string]Endpoint{}}
	for i := 0; i < 10; i++ {
		id := "lx" + string(rune('a'+i))
		in.Endpoints[id] = Endpoint{AgentID: id, Hostname: id, OS: "linux", Online: true}
		g := "local_group:" + id + ":sudo"
		in.Principals[g] = Principal{ID: g, Kind: "local_group", Name: "sudo", Enabled: true}
		in.Admins[id] = []Grant{{g, "sudoers"}}
	}
	in.Endpoints["dc1"] = Endpoint{AgentID: "dc1", Hostname: "dc1", OS: "windows", DomainController: true}
	in.Endpoints["dc2"] = Endpoint{AgentID: "dc2", Hostname: "dc2", OS: "windows", DomainController: true}
	in.Principals["S-adm"] = Principal{ID: "S-adm", Kind: "user", Name: "adm", Enabled: true}
	in.Admins["dc1"] = []Grant{{"S-adm", "Administrators"}}
	in.Admins["dc2"] = []Grant{{"S-adm", "Administrators"}}
	a := Analyze(in)
	for _, f := range a.Findings {
		if f.Category == "Local administrator name repeated across endpoints" {
			t.Errorf("a local group was reported as a repeated account: %+v", f)
		}
		if f.SubjectName == "adm" && f.Category != "Account administers more than one critical endpoint" {
			t.Errorf("adm administers 2 of 12 endpoints, both DCs; got category %q", f.Category)
		}
	}
	found := false
	for _, g := range a.Groups {
		if g.Kind == "local_group" {
			found = true
			if g.Level != "none" {
				t.Errorf("an empty local group should rate none, got %s", g.Level)
			}
		}
	}
	if !found {
		t.Error("local groups should be listed with the groups")
	}
}
