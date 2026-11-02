package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// A repository list's lines are what endpoints install from as root, so
// they are checked before any endpoint is pointed at them.
func TestValidateRepoLines(t *testing.T) {
	for _, c := range []struct {
		family, repos string
		ok            bool
	}{
		{"apt", "deb https://mirror.example.com/debian bookworm main\n\ndeb-src https://mirror.example.com/debian bookworm main", true},
		{"apt", "deb [signed-by=/usr/share/keyrings/x.gpg] https://m.example.com/ubuntu noble main", true},
		{"apt", "https://mirror.example.com/debian bookworm main", false},
		{"apt", "  \n ", false},
		{"dnf", "baseos\nappstream\nepel-9:testing", true},
		{"dnf", "baseos --setopt=x", false},
		{"dnf", "-x", false},
	} {
		if err := validateRepoLines(c.family, c.repos); (err == nil) != c.ok {
			t.Errorf("%s %q: err %v, want ok=%v", c.family, c.repos, err, c.ok)
		}
	}
}

func TestPatchListAssignmentMatches(t *testing.T) {
	web := store.AgentRecord{AgentID: "a1", Site: "hq", Platform: "debian"}
	for _, c := range []struct {
		b    createPatchListAssignmentRequest
		want bool
	}{
		{createPatchListAssignmentRequest{TargetAgent: "a1"}, true},
		{createPatchListAssignmentRequest{TargetAgent: "a2", TargetSite: "hq"}, false},
		{createPatchListAssignmentRequest{TargetSite: "hq"}, true},
		{createPatchListAssignmentRequest{TargetSite: "hq", TargetPlatform: "rhel"}, false},
		{createPatchListAssignmentRequest{TargetPlatform: "debian"}, true},
		{createPatchListAssignmentRequest{}, false},
	} {
		if got := patchListAssignmentMatches(c.b, web); got != c.want {
			t.Errorf("%+v: %v, want %v", c.b, got, c.want)
		}
	}
}

// Scan Management answers a caller's mistakes as such: an unknown list or
// endpoint is a 400, not a database error; deleting what is not there is
// a 404; a Windows endpoint cannot be given a repository list.
func TestScanManagementRefusals(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()
	run := idgen.New("")[:12]
	win := "agt-win-" + run
	if err := st.UpsertOnRegister(ctx, win, proto.AgentInfo{Hostname: "win-" + run, OS: "windows", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	w := callSave(s.handleCreatePatchList, "POST", "/api/patches/lists", "", `{"name":"empty","os_family":"apt","repos":"  "}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("list with no repos: %d, want 400", w.Code)
	}
	w = callSave(s.handleCreatePatchList, "POST", "/api/patches/lists", "", `{"name":" Mirror `+run+` ","os_family":"apt","repos":"deb https://m.example.com/debian bookworm main\n"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("create list: %d %s", w.Code, w.Body.String())
	}
	id := idOf(t, w)
	t.Cleanup(func() { _ = st.DeletePatchList(context.Background(), id) })
	if !strings.Contains(w.Body.String(), `"name":"Mirror `+run+`"`) {
		t.Errorf("name not trimmed: %s", w.Body.String())
	}

	for _, c := range []struct{ body, want string }{
		{`{"patch_list_id":"plist-nope","target_site":"hq"}`, "no such repository list"},
		{`{"patch_list_id":"` + id + `","target_agent":"agt-nope-` + run + `"}`, "no such endpoint"},
		{`{"patch_list_id":"` + id + `","target_agent":"` + win + `"}`, "not a Linux endpoint"},
	} {
		w := callSave(s.handleCreatePatchListAssignment, "POST", "/api/patches/list-assignments", "", c.body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d %q, want 400 %q", c.body, w.Code, w.Body.String(), c.want)
		}
	}
	w = callSave(s.handleCreatePatchListAssignment, "POST", "/api/patches/list-assignments", "", `{"patch_list_id":"`+id+`","target_site":"site-`+run+`"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"patch_list_name":"Mirror `+run+`"`) {
		t.Fatalf("assign: %d %s", w.Code, w.Body.String())
	}
	aid := idOf(t, w)
	if w := callSave(s.handleDeletePatchListAssignment, "DELETE", "/x", aid, ""); w.Code != http.StatusNoContent {
		t.Errorf("delete assignment: %d", w.Code)
	}
	if w := callSave(s.handleDeletePatchListAssignment, "DELETE", "/x", aid, ""); w.Code != http.StatusNotFound {
		t.Errorf("delete it again: %d, want 404", w.Code)
	}
	if w := callSave(s.handleDeletePatchList, "DELETE", "/x", "plist-nope-"+run, ""); w.Code != http.StatusNotFound {
		t.Errorf("delete unknown list: %d, want 404", w.Code)
	}
}
