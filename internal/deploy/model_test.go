package deploy

import (
	"github.com/mustra-dev/mustra/internal/proto"
	"testing"
)

func TestRowsKeepPredicatesOnSameRow(t *testing.T) {
	rows := []map[string]any{{"name": "Firefox", "version": "100"}, {"name": "Other", "version": "150"}}
	c := proto.DeployCheck{Quantifier: "any", Rows: []proto.DeployPredicate{{Field: "name", Value: "Firefox"}, {Field: "version", Operator: "version", Value: ">=150"}}}
	if ok, e := Rows(rows, c, nil); e != nil || ok {
		t.Fatalf("cross-row match: %v %v", ok, e)
	}
	c.Rows[1].Value = ">=100"
	if ok, e := Rows(rows, c, nil); e != nil || !ok {
		t.Fatalf("expected row match: %v %v", ok, e)
	}
	c.Quantifier = "all"
	if ok, _ := Rows(nil, c, nil); ok {
		t.Fatal("empty ALL must not pass")
	}
	c.Quantifier = "none"
	if ok, e := Rows(nil, c, nil); e != nil || !ok {
		t.Fatal("successful empty collection should satisfy NONE")
	}
	rows[0]["version"] = nil
	if _, e := Rows(rows, c, nil); e == nil {
		t.Fatal("unknown value must not satisfy NONE")
	}
}
func TestParametersAreDataAndValidated(t *testing.T) {
	defs := []proto.DeployParameter{{Name: "path", Type: "text", Required: true}, {Name: "retry", Type: "numeric"}}
	value := "$(touch /tmp/mustra-should-not-exist); 'quoted'"
	out, e := Parameters(defs, map[string]string{"path": value})
	if e != nil || out["path"] != value {
		t.Fatalf("parameter changed: %v %v", out, e)
	}
	if _, e = Parameters(defs, map[string]string{"path": "x", "unknown": "x"}); e == nil {
		t.Fatal("unknown parameter accepted")
	}
	if _, e = Parameters(defs, map[string]string{"path": "x", "retry": "NaN"}); e == nil {
		t.Fatal("NaN accepted")
	}
}
func TestVariantSelectionFailsAmbiguityAndUnsupported(t *testing.T) {
	d := proto.DeployDefinition{Variants: []proto.DeployVariant{{ID: "deb", OS: "linux", Distribution: []string{"ubuntu"}, Arch: []string{"arm64"}}}}
	if _, e := SelectVariant(d, "linux", "amd64", "ubuntu", "24.04"); e == nil {
		t.Fatal("wrong architecture accepted")
	}
	d.Variants = append(d.Variants, d.Variants[0])
	if _, e := SelectVariant(d, "linux", "arm64", "ubuntu", "24.04"); e == nil {
		t.Fatal("ambiguous variants accepted")
	}
}
