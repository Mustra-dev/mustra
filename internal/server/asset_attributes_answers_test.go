package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// GET /api/asset-attributes sent purge_after_days as the raw setting, a
// string that was "" when never set and "0" when set to never, where
// POST /api/assets/purge-after answers a number (#107). Both now answer
// the number of days, 0 for never.
func TestAssetAttributesAnswerPurgeAfterAsANumber(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()

	was, err := st.GetSetting(ctx, assetPurgeAfterSetting)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.SetSetting(context.Background(), assetPurgeAfterSetting, was, "tester") })

	for _, c := range []struct {
		stored string
		want   float64
	}{
		{"", 0},
		{"0", 0},
		{"365", 365},
		{"not a number", 0},
	} {
		if err := st.SetSetting(ctx, assetPurgeAfterSetting, c.stored, "tester"); err != nil {
			t.Fatal(err)
		}
		w := callSave(s.handleListAssetAttributes, "GET", "/api/asset-attributes", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("list: %d %s", w.Code, w.Body)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if got, ok := out["purge_after_days"].(float64); !ok || got != c.want {
			t.Errorf("setting %q: purge_after_days %#v, want the number %v", c.stored, out["purge_after_days"], c.want)
		}
	}
}

// The lifecycle preset answered "created": null when every lifecycle
// attribute existed already (#107). It now answers an empty list.
func TestLifecyclePresetThatCreatesNothingAnswersAnEmptyList(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()

	had := map[string]bool{}
	attrs, err := st.ListAssetAttributes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range attrs {
		had[a.Name] = true
	}
	// Leave the database with the attributes it had.
	t.Cleanup(func() {
		attrs, _ := st.ListAssetAttributes(context.Background())
		for _, a := range attrs {
			if !had[a.Name] {
				_ = st.DeleteAssetAttribute(context.Background(), a.ID)
			}
		}
	})

	preset := func() json.RawMessage {
		t.Helper()
		w := callSave(s.handleLifecyclePreset, "POST", "/api/asset-attributes/lifecycle-preset", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("preset: %d %s", w.Code, w.Body)
		}
		var out map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out["created"]
	}
	// The first call creates whichever are missing; the second has none
	// left to create.
	preset()
	if got := string(preset()); got != "[]" {
		t.Errorf("preset with every attribute there: created %s, want []", got)
	}
}
