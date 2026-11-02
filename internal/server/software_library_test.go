package server

import (
	"regexp"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/deploy"
)

// Every library entry must be publishable as it stands (after an operator
// reviews it) and keep the library's rules.
func TestLibraryEntriesArePublishable(t *testing.T) {
	ids := map[string]bool{}
	for _, e := range softwareLibrary {
		if ids[e.ID] || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(e.ID) {
			t.Errorf("%s: library IDs must be unique lower-case slugs", e)
		}
		ids[e.ID] = true
		if len(e.platforms()) == 0 {
			t.Errorf("%s has no platform", e)
		}
		for _, os := range e.platforms() {
			if _, err := regexp.Compile(e.Detect[os]); err != nil || e.Detect[os] == "" {
				t.Errorf("%s: %s detection %q: %v", e, os, e.Detect[os], err)
			}
		}
		d := e.definition()
		if err := deploy.ValidateDefinition(d, true); err != nil {
			t.Errorf("%s does not validate for publishing: %v", e, err)
		}
		for _, v := range d.Variants {
			if v.Requirements == nil {
				t.Errorf("%s %s: no applicability check", e, v.OS)
			}
			for op, a := range v.Actions {
				src := a.Steps[0].Script.Source
				if v.OS == "windows" && !strings.Contains(src, "-1978335189") {
					t.Errorf("%s %s %s: winget's 'nothing to do' code must count as success", e, v.OS, op)
				}
				if v.OS == "darwin" && !strings.Contains(src, `sudo -u "$OWNER"`) {
					t.Errorf("%s %s: Homebrew must not run as root", e, op)
				}
				if v.OS == "linux" && !strings.Contains(src, "DEBIAN_FRONTEND=noninteractive") {
					t.Errorf("%s %s: apt must not prompt", e, op)
				}
				if (op == "remove") != (a.Validation.Quantifier == "none") {
					t.Errorf("%s %s %s: validation quantifier %q", e, v.OS, op, a.Validation.Quantifier)
				}
			}
		}
	}
	// The origin marker round-trips, so an entry is never added twice.
	for id := range ids {
		if m := libraryOriginRe.FindStringSubmatch("Web browser. " + libraryOrigin(id)); m == nil || m[1] != id {
			t.Errorf("origin marker for %s does not parse back", id)
		}
	}
}
