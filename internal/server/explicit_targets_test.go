package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// A package that removes the agent is one mis-click from a fleet nobody can
// manage remotely any more, so "run against everything" has to be refused by
// the server rather than merely hidden in the console.
func TestFleetWideRunIsRefusedForAMarkedPackage(t *testing.T) {
	pkg := &store.SoftwarePackage{Name: "Uninstall mustra agent", RequireExplicitTargets: true}
	w := httptest.NewRecorder()

	if !explicitTargetsRequired(w, pkg, nil) {
		t.Fatal("a fleet-wide run of a marked package was allowed")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	// The refusal has to name the package, because an operator who sees it
	// is mid-dispatch and needs to know which one stopped.
	if !strings.Contains(w.Body.String(), "Uninstall mustra agent") {
		t.Fatalf("refusal does not name the package: %q", w.Body.String())
	}
}

func TestSelectedEndpointsAreAllowed(t *testing.T) {
	pkg := &store.SoftwarePackage{Name: "Uninstall mustra agent", RequireExplicitTargets: true}
	w := httptest.NewRecorder()

	if explicitTargetsRequired(w, pkg, []string{"agt-1", "agt-2"}) {
		t.Fatalf("a run against named endpoints was refused: %q", w.Body.String())
	}
}

// Every other package keeps working exactly as before; this must not become
// a tax on ordinary deployments.
func TestOrdinaryPackagesAreUnaffected(t *testing.T) {
	pkg := &store.SoftwarePackage{Name: "htop"}
	w := httptest.NewRecorder()

	if explicitTargetsRequired(w, pkg, nil) {
		t.Fatal("an ordinary package was refused a fleet-wide run")
	}
}

// One endpoint is a selection. The guard is about "did the operator choose",
// not about how many they chose.
func TestASingleEndpointCounts(t *testing.T) {
	pkg := &store.SoftwarePackage{Name: "Uninstall mustra agent", RequireExplicitTargets: true}
	w := httptest.NewRecorder()

	if explicitTargetsRequired(w, pkg, []string{"agt-1"}) {
		t.Fatalf("a single named endpoint was refused: %q", w.Body.String())
	}
}
