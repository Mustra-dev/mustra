package store

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// A site-and-platform assignment matches only hosts at that site on that
// platform, and the most specific match wins: endpoint, then site and
// platform, then site, then platform (#53). Before, a site-and-platform
// assignment matched on the site alone, so an apt list for "hq, debian"
// was served to the RHEL hosts at hq too and hid their own dnf list.
func TestResolvePatchListForAgentPrecedence(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Sites and platforms unique to this run, so assignments other tests
	// (or earlier runs) left behind cannot match.
	run := idgen.New("")[:12]
	hq, branch := "hq-"+run, "branch-"+run
	debian, rhel, ubuntu := "debian-"+run, "rhel-"+run, "ubuntu-"+run
	agent := "agt-plist-" + run

	list := func(name, family string) string {
		t.Helper()
		pl, err := s.CreatePatchList(ctx, PatchList{ID: idgen.New("plist-"), Name: name + " " + run, OSFamily: family})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.DeletePatchList(ctx, pl.ID) })
		return pl.ID
	}
	assign := func(listID, platform, site, agentID string) string {
		t.Helper()
		a, err := s.CreatePatchListAssignment(ctx, PatchListAssignment{ID: idgen.New("plassign-"), PatchListID: listID,
			TargetPlatform: platform, TargetSite: site, TargetAgent: agentID})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	resolve := func(agentID, platform, site string) string {
		t.Helper()
		pl, err := s.ResolvePatchListForAgent(ctx, agentID, platform, site)
		if err != nil {
			t.Fatal(err)
		}
		if pl == nil {
			return ""
		}
		return pl.ID
	}
	want := func(what, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("%s: resolved %q, want %q", what, got, want)
		}
	}

	hqDebian := list("hq debian", "apt")
	hqOnly := list("hq", "apt")
	rhelOnly := list("rhel", "dnf")
	ubuntuOnly := list("ubuntu", "apt")
	pinned := list("pinned", "apt")

	// Created most specific first, so recency cannot be what decides.
	assign(hqDebian, debian, hq, "")
	assign(hqOnly, "", hq, "")
	assign(rhelOnly, rhel, "", "")
	assign(ubuntuOnly, ubuntu, "", "")

	want("debian host at hq", resolve("agt-a-"+run, debian, hq), hqDebian)
	want("rhel host at hq", resolve("agt-b-"+run, rhel, hq), hqOnly)
	want("debian host elsewhere", resolve("agt-c-"+run, debian, branch), "")
	want("rhel host elsewhere", resolve("agt-d-"+run, rhel, branch), rhelOnly)
	want("host with no site", resolve("agt-e-"+run, rhel, ""), rhelOnly)

	// Without a site-only rule, a host at the site on another platform
	// falls back to its own platform's list rather than getting nothing
	// or the other platform's list.
	branchDebian := list("branch debian", "apt")
	assign(branchDebian, debian, branch, "")
	want("debian host at branch", resolve("agt-f-"+run, debian, branch), branchDebian)
	want("ubuntu host at branch", resolve("agt-g-"+run, ubuntu, branch), ubuntuOnly)

	// Site-only beats platform-only, whichever was created later.
	want("ubuntu host at hq", resolve("agt-h-"+run, ubuntu, hq), hqOnly)

	// The endpoint's own assignment beats everything, including a
	// site-and-platform rule that also matches it.
	assign(pinned, "", "", agent)
	want("pinned debian host at hq", resolve(agent, debian, hq), pinned)

	// An endpoint assignment that also names a site and platform still
	// applies to the endpoint after it moves: only site and platform
	// combine.
	moved := idgen.New("agt-plist-moved-")
	assign(pinned, debian, branch, moved)
	want("endpoint rule at its site", resolve(moved, debian, branch), pinned)
	want("endpoint rule after the host moved", resolve(moved, rhel, hq), pinned)

	// Ties at the same specificity go to the most recent assignment, and
	// rows created at the same instant to the lower ID, so the reply
	// never depends on the plan Postgres picks.
	tieSite := "tie-" + run
	older, newer := list("older", "apt"), list("newer", "apt")
	assign(older, "", tieSite, "")
	assign(newer, "", tieSite, "")
	want("most recent site rule", resolve("agt-i-"+run, debian, tieSite), newer)

	sameSite := "same-" + run
	first, second := list("first", "apt"), list("second", "apt")
	idA := assign(first, "", sameSite, "")
	idB := assign(second, "", sameSite, "")
	if _, err := s.pool.Exec(ctx, `UPDATE patch_list_assignments SET created_at = '2026-01-01T00:00:00Z' WHERE id = ANY($1)`, []string{idA, idB}); err != nil {
		t.Fatal(err)
	}
	wantTie := first
	if idB < idA {
		wantTie = second
	}
	for range 5 {
		want("simultaneous site rules", resolve("agt-j-"+run, debian, sameSite), wantTie)
	}
}

// A new assignment answers with its list's name, as the list of
// assignments shows it, and the records are sent under snake_case names
// (#115).
func TestPatchListAssignmentCreateNamesItsList(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	run := idgen.New("")[:12]
	pl, err := s.CreatePatchList(ctx, PatchList{ID: idgen.New("plist-"), Name: "Mirror " + run, OSFamily: "apt"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeletePatchList(context.Background(), pl.ID) })
	a, err := s.CreatePatchListAssignment(ctx, PatchListAssignment{ID: idgen.New("plassign-"), PatchListID: pl.ID, TargetSite: "site-" + run, CreatedBy: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if a.PatchListName != pl.Name || a.CreatedAt.IsZero() {
		t.Fatalf("created assignment %+v, want list name %q and a created_at", a, pl.Name)
	}
	b, _ := json.Marshal(a)
	for _, k := range []string{`"patch_list_id"`, `"patch_list_name"`, `"target_site"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("assignment JSON %s lacks %s", b, k)
		}
	}
}
