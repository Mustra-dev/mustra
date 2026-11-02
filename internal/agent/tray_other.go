//go:build !windows

package agent

// The tray helper is Windows-only, because the problem it solves is
// Windows-only: a macOS LaunchDaemon reaches the console user's session
// through launchctl asuser, which is why notifications there are already
// native. A macOS menu-bar item is not built yet.
func (a *Agent) superviseTray(stop <-chan struct{}) {}
