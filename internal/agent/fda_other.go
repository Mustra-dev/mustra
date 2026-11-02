//go:build !darwin

package agent

// Full Disk Access is a macOS concept: TCC has no equivalent on Linux or
// Windows, where root and LocalSystem mean what they say.
func (a *Agent) promptFullDiskAccess() {}
