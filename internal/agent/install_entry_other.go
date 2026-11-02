//go:build !windows

package agent

// syncInstallEntry: only Windows has an installed-programs entry carrying
// the agent's version.
func syncInstallEntry(string) {}
