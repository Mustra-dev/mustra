package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
)

func TestCheckClientID(t *testing.T) {
	for _, id := range []string{"", idgen.New("enf-"), idgen.New("pb-"), "rep-weekly", "sec-1", "a", "x.y:z_w-1"} {
		if err := checkClientID("thing", id); err != nil {
			t.Errorf("%q refused: %v", id, err)
		}
	}
	for _, id := range []string{
		`x"><img src=x onerror=alert(1)>`, "a b", "a/b", "-lead", ".lead", "a'b", "a<b", "a\\b", "a\nb",
		strings.Repeat("a", 129), "é",
	} {
		if checkClientID("thing", id) == nil {
			t.Errorf("%q accepted", id)
		}
	}
}

// The save handlers refuse a client-chosen ID that could carry markup
// before they touch the store, whether it comes in the path or the body.
func TestSaveHandlersRefuseMarkupIDs(t *testing.T) {
	s := &Server{}
	bad := `x"><img src=x onerror=alert(1)>`
	cases := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		body    string
	}{
		{"enforce", s.handleSaveEnforcePolicy, `{"name":"p"}`},
		{"playbook", s.handleSavePlaybook, `{"name":"p"}`},
		{"report", s.handleSaveReport, `{"name":"p"}`},
	}
	for _, c := range cases {
		// In the path, as PUT /api/…/{id} carries it.
		r := httptest.NewRequest("PUT", "/x", strings.NewReader(c.body))
		r.SetPathValue("id", bad)
		w := httptest.NewRecorder()
		c.handler(w, r)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "id may use only") {
			t.Errorf("%s path id: HTTP %d %q", c.name, w.Code, w.Body.String())
		}
		// In the body of a create.
		body := `{"id":` + strings.ReplaceAll(`"`+strings.ReplaceAll(bad, `"`, `\"`)+`"`, "\n", "") + `,` + c.body[1:]
		r = httptest.NewRequest("POST", "/x", strings.NewReader(body))
		w = httptest.NewRecorder()
		c.handler(w, r)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "id may use only") {
			t.Errorf("%s body id: HTTP %d %q", c.name, w.Code, w.Body.String())
		}
	}
}

func TestPlaybookStepAndReportSectionIDs(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("POST", "/x", nil)
	if _, err := s.validatePlaybookSteps(r, []playbookStep{{ID: `s"><b>`, Kind: "wait"}}); err == nil || !strings.Contains(err.Error(), "id may use only") {
		t.Errorf("step id with markup: %v", err)
	}
	if _, err := s.validateReportSections(r, []reportSection{{ID: `s"><b>`}}); err == nil || !strings.Contains(err.Error(), "id may use only") {
		t.Errorf("section id with markup: %v", err)
	}
}
