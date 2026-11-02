package server

import (
	"strings"
	"testing"
)

type exampleFixtureItem struct {
	Name string `json:"name" api:"required"`
}

type exampleFixture struct {
	ID       string               `json:"id" api:"readonly"`
	Title    string               `json:"title" api:"required"`
	Count    int                  `json:"count"`
	Secret   string               `json:"secret" api:"writeonly"`
	Items    []exampleFixtureItem `json:"items"`
	ByName   map[string]int       `json:"by_name"`
	Optional *string              `json:"optional"`
}

// The example checker passes a body the route takes as it is, and names
// what is wrong with one it would not, or should not, take.
func TestBodyExampleChecker(t *testing.T) {
	doc := routeDoc{Body: exampleFixture{}, Required: []string{"count"}}
	if p := exampleProblems(doc, `{"title": "Nightly", "count": 2, "secret": "<API key>", "items": [{"name": "a"}], "by_name": {"a": 1}, "optional": null}`); p != nil {
		t.Errorf("a good example: %v", p)
	}
	for _, c := range []struct{ example, want string }{
		{`{"title": `, "not JSON"},
		{`{"title": "x", "count": 1, "colour": "red"}`, "colour"},
		{`{"title": "x", "count": 1, "items": [{"name": "a", "size": 2}]}`, "size"},
		{`{"title": 3, "count": 1}`, "title"},
		{`{"title": null, "count": 1}`, "title"},
		{`{"title": "x", "count": 1, "by_name": {"a": "one"}}`, "by_name.a"},
		{`{"count": 1}`, "title"},
		{`{"title": "x"}`, "count"},
		{`{"title": "x", "count": 1, "items": [{}]}`, "items[0].name"},
		{`{"id": "x", "title": "x", "count": 1}`, "id"},
		{`{"title": "x", "count": 1, "secret": "hunter2"}`, "secret"},
		{`[]`, "body"},
	} {
		problems := exampleProblems(doc, c.example)
		if !strings.Contains(strings.Join(problems, "\n"), c.want) {
			t.Errorf("%s: want a problem naming %q, got %v", c.example, c.want, problems)
		}
	}
	if p := exampleProblems(routeDoc{Body: map[string]string{}}, `{"owner": "Platform team"}`); p != nil {
		t.Errorf("a map body: %v", p)
	}
}
