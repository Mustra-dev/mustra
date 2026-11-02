//go:build !windows

package agent

// evaluateRegistryRule exists so registry rules parse on every platform.
// It reports "not understood" rather than "false" on purpose: a Windows
// benchmark accidentally aimed at a Linux host must produce unknowns, not
// a page of confident failures that look like real findings.
func evaluateRegistryRule(rule string) (bool, bool) { return false, false }
