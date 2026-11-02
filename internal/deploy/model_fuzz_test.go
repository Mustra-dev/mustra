package deploy

import (
	"encoding/json"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// FuzzValidateDefinition drives the Deploy definition validator with
// arbitrary definitions decoded from fuzzed JSON. A definition is
// operator-authored and drives commands that run with administrative rights
// on endpoints, so the validator is a gate that must be total: it may accept
// or reject, but it must never panic or recurse without bound (ValidateCheck
// and validateSteps both nest).
func FuzzValidateDefinition(f *testing.F) {
	for _, raw := range []string{
		`{"version":1,"variants":[{"os":"linux"}]}`,
		`{"version":2,"kind":"action","variants":[{"os":"linux","actions":{"run":{"steps":[{"run":"echo hi"}]}}}]}`,
		`{"version":2,"kind":"action","files":[{"id":"f1"}],"variants":[{"os":"linux"}]}`,
		`{"version":1,"parameters":[{"name":"x","type":"text"}],"variants":[{"os":"linux"}]}`,
		`{}`, `{"version":99,"variants":[]}`,
		`{"version":2,"kind":"action","variants":[{"os":"linux","actions":{"run":{"steps":[{"check":{"any":[{"all":[{}]}]}}]}}}]}`,
	} {
		f.Add(raw, true)
		f.Add(raw, false)
	}
	f.Fuzz(func(t *testing.T, raw string, published bool) {
		if len(raw) > 1<<16 {
			return
		}
		var d proto.DeployDefinition
		if json.Unmarshal([]byte(raw), &d) != nil {
			return
		}
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("ValidateDefinition panicked on %q (published=%v): %v", raw, published, p)
			}
		}()
		_ = ValidateDefinition(d, published)
	})
}

// FuzzVersionMatches checks the deploy version matcher and comparator never
// panic and agree on reflexivity: a version always matches "=itself", and
// CompareVersion(a,a)==0.
func FuzzVersionMatches(f *testing.F) {
	for _, s := range []string{"1.2.3", "v1.0", "1.0.0-rc", "2026.1", "", "a.b.c",
		"1.2.3,>=1.0.0", ">=2.0", "99999999999999999999999"} {
		f.Add(s, ">=1.0.0")
	}
	f.Fuzz(func(t *testing.T, actual, constraint string) {
		if len(actual)+len(constraint) > 4096 {
			return
		}
		_, _ = VersionMatches(actual, constraint)
		if CompareVersion(actual, actual) != 0 {
			t.Fatalf("CompareVersion(%q,%q) != 0", actual, actual)
		}
		if a, b := CompareVersion(actual, constraint), CompareVersion(constraint, actual); a != -b {
			t.Fatalf("CompareVersion not antisymmetric for %q/%q: %d vs %d", actual, constraint, a, b)
		}
	})
}
