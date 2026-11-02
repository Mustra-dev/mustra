package deploy

import (
	"github.com/mustra-dev/mustra/internal/proto"
	"strings"
	"testing"
)

func actionDefinition() proto.DeployDefinition {
	return proto.DeployDefinition{Version: 2, Kind: "action", Variants: []proto.DeployVariant{{ID: "linux", OS: "linux", Actions: map[string]proto.DeployAction{"run": {Steps: []proto.DeployStep{{ID: "run", Script: &proto.DeployScript{Language: "shell", Source: "exit 0"}}}}}}}}
}
func TestActionDefinitionContract(t *testing.T) {
	if e := ValidateDefinition(actionDefinition(), true); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name string
		edit func(*proto.DeployDefinition)
	}{
		{"old wire", func(d *proto.DeployDefinition) { d.Version = 1 }},
		{"detection", func(d *proto.DeployDefinition) { d.Variants[0].Detection = &proto.DeployCheck{Kind: "os"} }},
		{"requirements", func(d *proto.DeployDefinition) { d.Variants[0].Requirements = &proto.DeployCheck{Kind: "os"} }},
		{"review", func(d *proto.DeployDefinition) { d.ReviewRequired = true }},
		{"install", func(d *proto.DeployDefinition) { v := &d.Variants[0]; v.Actions["install"] = v.Actions["run"] }},
		{"retries", func(d *proto.DeployDefinition) {
			a := d.Variants[0].Actions["run"]
			a.Steps[0].RetrySafe = true
			d.Variants[0].Actions["run"] = a
		}},
		{"sensor missing", func(d *proto.DeployDefinition) {
			a := d.Variants[0].Actions["run"]
			a.SuccessMode = "sensor"
			d.Variants[0].Actions["run"] = a
		}},
		{"unlimited download", func(d *proto.DeployDefinition) {
			a := d.Variants[0].Actions["run"]
			a.DownloadSeconds = -1
			d.Variants[0].Actions["run"] = a
		}},
		{"type mismatch", func(d *proto.DeployDefinition) {
			d.Parameters = []proto.DeployParameter{{Name: "input", Type: "text"}}
			d.Variants[0].Parameters = []proto.DeployParameter{{Name: "input", Type: "numeric"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := actionDefinition()
			tc.edit(&d)
			if e := ValidateDefinition(d, true); e == nil {
				t.Fatal("invalid action accepted")
			}
		})
	}
	d := actionDefinition()
	d.Kind = ""
	d.Version = 1
	if e := ValidateDefinition(d, true); e == nil || !strings.Contains(e.Error(), "detection") {
		t.Fatal("software detection requirement weakened", e)
	}
}
func TestActionCapabilityDoesNotRequireSoftwareAgentUpgrade(t *testing.T) {
	for _, tc := range []struct {
		op   string
		want int
	}{{"install", 1}, {"run", 2}} {
		if got := RequiredVersion(proto.DeployJob{Packages: []proto.DeployPackagePlan{{Operation: tc.op}}}); got != tc.want {
			t.Fatalf("%s requires %d", tc.op, got)
		}
	}
}
