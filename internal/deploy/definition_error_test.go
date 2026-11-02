package deploy

import (
	"errors"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// A publish failure that belongs to one platform and operation says which,
// in words, and carries the place so the console can open and highlight it.
// The message used to be "s_4906d5f0e0014670/remove needs validation before
// publishing": an internal variant ID and an operation key.
func TestDefinitionErrorsNameThePlace(t *testing.T) {
	app := &proto.DeployCheck{Kind: "app", Name: "Dock Firmware"}
	step := []proto.DeployStep{{ID: "s1", Name: "Run", Script: &proto.DeployScript{Language: "powershell", Source: "exit 0", TimeoutSeconds: 60}}}
	d := proto.DeployDefinition{Version: 1, Variants: []proto.DeployVariant{{
		ID: "s_4906d5f0e0014670", OS: "windows", Detection: app,
		Actions: map[string]proto.DeployAction{
			"install": {Identity: "administrator", Steps: step, Validation: app},
			"remove":  {Identity: "administrator", Steps: step},
		},
	}}}
	e := ValidateDefinition(d, true)
	var de *DefinitionError
	if !errors.As(e, &de) {
		t.Fatalf("want a located error, got %v", e)
	}
	if de.OS != "windows" || de.Operation != "remove" || de.Section != "validation" || de.VariantID != "s_4906d5f0e0014670" {
		t.Fatalf("wrong place: %+v", de)
	}
	if msg := e.Error(); !strings.HasPrefix(msg, "Windows · Uninstall: ") || strings.Contains(msg, "s_4906") {
		t.Fatalf("message should name the platform and operation, not the variant ID: %q", msg)
	}
	// A draft is saved without the publish-only checks.
	if e := ValidateDefinition(d, false); e != nil {
		t.Fatalf("draft refused: %v", e)
	}

	d.Variants[0].Detection = nil
	if e := ValidateDefinition(d, true); !errors.As(e, &de) || de.Section != "detection" || de.Operation != "" {
		t.Fatalf("missing detection not located at the platform: %v", e)
	}
}
