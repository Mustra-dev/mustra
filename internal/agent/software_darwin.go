//go:build darwin

package agent

import (
	"os"
	"strings"
)

// rewriteForPlatform redirects Homebrew through the account that owns the
// prefix. The agent is root — a LaunchDaemon, which is what gives it the
// rights to manage the machine — and Homebrew flatly refuses to run as
// root. Without this, the obvious `brew install x` in a package fails on
// every Mac with advice rather than an install, which would make Homebrew
// packages effectively unusable.
func rewriteForPlatform(command string) string {
	if !strings.Contains(command, "brew ") || os.Geteuid() != 0 {
		return command
	}
	path, err := lookBrew()
	if err != nil {
		return command
	}
	owner, err := brewPrefixOwner(path)
	if err != nil {
		return command // let it fail with brew's own message rather than ours
	}
	// -H so HOME is the target account's: brew keys its prefix detection,
	// caches and taps off it.
	return "sudo -u " + owner + " -H " + strings.Replace(command, "brew ", path+" ", 1)
}
