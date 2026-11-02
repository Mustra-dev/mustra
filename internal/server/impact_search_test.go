package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/impact"
)

// The path finder's search answers an empty list, not null, when nothing
// matches, like every other list in the analysis.
func TestImpactSearchWithNoMatchAnswersAnEmptyList(t *testing.T) {
	s := &Server{}
	s.impact.a = impact.Analyze(impact.Input{
		Principals: map[string]impact.Principal{"S-1": {ID: "S-1", Kind: "user", Name: "alice", Enabled: true}},
	})
	s.impact.at = time.Now()

	w := httptest.NewRecorder()
	s.handleImpactSearch(w, httptest.NewRequest(http.MethodGet, "/api/impact/search?q=nobody", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if string(resp["hits"]) != "[]" {
		t.Fatalf("hits = %s, want []", resp["hits"])
	}
}
