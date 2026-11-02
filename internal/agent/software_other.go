//go:build !darwin

package agent

// rewriteForPlatform is a no-op everywhere but macOS, where Homebrew's
// refusal to run as root needs handling. See software_darwin.go.
func rewriteForPlatform(command string) string { return command }
