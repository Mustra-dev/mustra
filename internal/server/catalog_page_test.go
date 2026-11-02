package server

import (
	"log/slog"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// Self Service reads software packages. The catalog item routes edited a
// table it no longer reads, so they are gone rather than left to mislead.
func TestCatalogItemRoutesAreRetired(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	for _, e := range s.routeLog.entries {
		if strings.Contains(e.Pattern, "/api/catalog/items") {
			t.Errorf("%s is still registered", e.Pattern)
		}
	}
	for route := range routeDocs {
		if strings.Contains(route, "/api/catalog/items") {
			t.Errorf("%s is still declared in the OpenAPI routes", route)
		}
	}
}

// The Self Service page lists what Self Service offers, which is packages,
// and sends the operator to the package editor to change one.
func TestSelfServicePageListsOfferedPackages(t *testing.T) {
	w := httptest.NewRecorder()
	catalogPageHandler().ServeHTTP(w, httptest.NewRequest("GET", "/catalog", nil))
	if w.Code != 200 {
		t.Fatalf("Self Service page: HTTP %d", w.Code)
	}
	page := w.Body.String()
	if strings.Contains(page, "/api/catalog/items") {
		t.Error("the page still calls the retired catalog item routes")
	}
	for _, want := range []string{`fetch("/api/software")`, `/software?package=`} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %s", want)
		}
	}
	// No browser runs in the tests, so check the page's script asks only
	// for elements the page has: a lookup of a removed id throws and stops
	// the rest of the page (Requests, Appearance) from loading.
	for _, m := range regexp.MustCompile(`getElementById\("([^"]+)"\)`).FindAllStringSubmatch(page, -1) {
		if !strings.Contains(page, `id="`+m[1]+`"`) {
			t.Errorf("the script looks up #%s, which the page does not have", m[1])
		}
	}
}
