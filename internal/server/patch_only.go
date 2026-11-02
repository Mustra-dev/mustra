package server

import (
	"slices"
	"strings"
)

// A remediation from a threat briefing can patch only the packages the
// briefing found vulnerable on each endpoint, rather than everything
// pending there. The narrowing reuses apply_patches' selective form
// (AgentCommand.Patches), which agents have honoured since
// patchPolicyAgentVersion, so it needs no new agent.
//
// Names are matched, not guessed: an endpoint's pending update counts when
// it is the same package the vulnerability scan read from its installed
// software. Both come from the same package manager (dpkg and apt, rpm and
// dnf), so the names agree once dnf's ".arch" suffix and dpkg's ":arch"
// qualifier are set aside. Windows Update titles and macOS update labels
// never name an application, so those endpoints have nothing to narrow to
// and the run says so rather than patching something else.

// patchArchSuffixes are the architecture qualifiers package managers add.
var patchArchSuffixes = []string{"x86_64", "aarch64", "noarch", "i686", "i386", "amd64", "arm64", "armhf", "ppc64le", "s390x", "all"}

// basePackageName lower-cases a package name and drops an architecture
// qualifier: "openssl-libs.x86_64" and "libssl3t64:amd64" become
// "openssl-libs" and "libssl3t64".
func basePackageName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, sep := range []string{".", ":"} {
		if i := strings.LastIndex(n, sep); i > 0 && slices.Contains(patchArchSuffixes, n[i+1:]) {
			n = n[:i]
		}
	}
	return n
}

// onlyPatches returns the pending patches in allowed that update one of the
// named packages, in allowed's order.
func onlyPatches(allowed, packages []string) []string {
	want := map[string]bool{}
	for _, p := range packages {
		if b := basePackageName(p); b != "" {
			want[b] = true
		}
	}
	var out []string
	for _, name := range allowed {
		if want[basePackageName(name)] {
			out = append(out, name)
		}
	}
	return out
}
