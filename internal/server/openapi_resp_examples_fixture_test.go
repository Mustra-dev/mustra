package server

import (
	"strings"
	"testing"
	"time"
)

type respExampleFixtureItem struct {
	Name string `json:"name"`
	Size int    `json:"size,omitempty"`
}

type respExampleFixture struct {
	ID      string                   `json:"id" api:"readonly"`
	Items   []respExampleFixtureItem `json:"items"`
	Note    string                   `json:"note,omitempty"`
	Secret  string                   `json:"secret" api:"writeonly"`
	Created time.Time                `json:"created_at"`
	Next    *time.Time               `json:"next_at"`
}

// A token the server shows once, and a command that carries it: neither
// is write-only, since the response is how the caller gets it.
type respExampleFixtureToken struct {
	Prefix  string            `json:"prefix"`
	Token   string            `json:"token"`
	Command map[string]string `json:"commands"`
}

type respExampleFixtureAlt struct {
	Started bool `json:"started"`
}

// The response example checker passes an example the route could answer
// with as it is, and names what is wrong with one it could not.
func TestResponseExampleChecker(t *testing.T) {
	doc := routeDoc{Resp: respExampleFixture{}}
	good := `{"id": "fx-1", "items": [{"name": "a", "size": 2}, {"name": "b"}], "note": "kept", "secret": "", "created_at": "2026-10-14T09:12:03Z", "next_at": null}`
	if p := respExampleProblems(doc, good, nil); p != nil {
		t.Errorf("a good example: %v", p)
	}
	// The main shape of a route that answers in two.
	alt := routeDoc{Resp: respExampleFixture{}, RespAlt: []any{respExampleFixtureAlt{}}}
	if p := respExampleProblems(alt, good, nil); p != nil {
		t.Errorf("the main shape of two: %v", p)
	}
	if p := respExampleProblems(routeDoc{Resp: []respExampleFixtureItem{}}, `[{"name": "a"}]`, nil); p != nil {
		t.Errorf("a list: %v", p)
	}
	if p := respExampleProblems(routeDoc{Resp: map[string]any{}}, `{"anything": [1, "two"]}`, nil); p != nil {
		t.Errorf("a map: %v", p)
	}
	for _, c := range []struct{ example, want string }{
		{`{"id": `, "not JSON"},
		{`{"id": "fx-1", "items": null, "secret": "", "created_at": "2026-10-14T09:12:03Z", "next_at": null, "colour": "red"}`, "colour"},
		{`{"id": "fx-1", "items": [{"name": "a", "weight": 1}], "secret": "", "created_at": "2026-10-14T09:12:03Z", "next_at": null}`, "weight"},
		{`{"id": 7, "items": null, "secret": "", "created_at": "2026-10-14T09:12:03Z", "next_at": null}`, "id"},
		{`{"items": null, "secret": "", "created_at": "2026-10-14T09:12:03Z", "next_at": null}`, "response.id is missing"},
		{`{"id": "fx-1", "items": [{"name": "a", "size": 0}], "secret": "", "created_at": "2026-10-14T09:12:03Z", "next_at": null}`, "response.items[0].size"},
		{`{"id": "fx-1", "items": null, "note": "", "secret": "", "created_at": "2026-10-14T09:12:03Z", "next_at": null}`, "response.note"},
		{`{"ID": "fx-1", "items": null, "secret": "", "created_at": "2026-10-14T09:12:03Z", "next_at": null}`, "response.ID"},
		{`{"id": "fx-1", "items": null, "secret": "", "created_at": "14 October 2026", "next_at": null}`, "parsing time"},
		{`{"id": "fx-1", "items": null, "secret": "", "created_at": "2026-10-14T09:12:03.000Z", "next_at": null}`, "response.created_at is written as"},
		{`{"id": "fx-1", "items": null, "secret": "hunter2", "created_at": "2026-10-14T09:12:03Z", "next_at": null}`, "response.secret is a secret"},
		{`{"started": true}`, "started"},
		{`[]`, "response"},
	} {
		problems := respExampleProblems(alt, c.example, nil)
		if !strings.Contains(strings.Join(problems, "\n"), c.want) {
			t.Errorf("%s: want a problem naming %q, got %v", c.example, c.want, problems)
		}
	}

	// A secret the server shows once is a placeholder after its prefix;
	// the prefix alone, which the server keeps to find the token by, is
	// not a secret.
	token := routeDoc{Resp: respExampleFixtureToken{}}
	if p := respExampleProblems(token, `{"prefix": "mstr_q7Xc2LpA", "token": "mstr_<token, shown once>", "commands": {"unix": "curl -H 'Authorization: Bearer mte_<token, shown once>' https://mustra.example.com/install.sh"}}`, nil); p != nil {
		t.Errorf("a token shown once: %v", p)
	}
	for _, c := range []struct{ example, want string }{
		{`{"prefix": "", "token": "mstr_q7Xc2LpAa9Kd0Zr4", "commands": null}`, "response.token holds a secret"},
		{`{"prefix": "", "token": "", "commands": {"unix": "curl -H 'Authorization: Bearer mte_q7Xc2LpA' https://mustra.example.com/install.sh"}}`, "response.commands.unix carries a bearer credential"},
	} {
		problems := respExampleProblems(token, c.example, nil)
		if !strings.Contains(strings.Join(problems, "\n"), c.want) {
			t.Errorf("%s: want a problem naming %q, got %v", c.example, c.want, problems)
		}
	}

	// A property cleared for its route (notSecretsIn) is not taken for a
	// secret there, in any entry of a list.
	labels := routeDoc{Resp: map[string]any{}}
	const named = `{"items": [{"token": "the sign-in label"}]}`
	if p := respExampleProblems(labels, named, map[string]string{"response.items[].token": "a label"}); p != nil {
		t.Errorf("a cleared property: %v", p)
	}
	if p := strings.Join(respExampleProblems(labels, named, nil), "\n"); !strings.Contains(p, "response.items[0].token holds a secret") {
		t.Errorf("the same property, not cleared: want it named as a secret, got %q", p)
	}
}
