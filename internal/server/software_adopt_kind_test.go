package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// An adopted package was saved with kind "", which every server path read
// as software but a client filtering on "software" missed (#119).
func TestAdoptedSoftwareIsKindSoftware(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()

	name := strings.ToLower(idgen.New("adopt-kind-"))
	w := callSave(s.handleAdoptSoftware, "POST", "/api/software/adopt", "",
		`{"name":"`+name+`","version":"1.0","platforms":["linux"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("adopt: %d %s", w.Code, w.Body)
	}
	var out store.SoftwarePackage
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteSoftwarePackage(context.Background(), out.ID) })
	if out.Kind != store.KindSoftware {
		t.Errorf("answered kind %q, want %q", out.Kind, store.KindSoftware)
	}
	stored, err := st.GetSoftwarePackage(ctx, out.ID)
	if err != nil || stored == nil {
		t.Fatalf("stored package %s: %v, %v", out.ID, stored, err)
	}
	if stored.Kind != store.KindSoftware {
		t.Errorf("stored kind %q, want %q", stored.Kind, store.KindSoftware)
	}
}
