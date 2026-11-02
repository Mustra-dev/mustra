//go:build windows

package agent

import (
	"context"
	"os/exec"
	"strconv"
)

// scheduleRestart is Windows' own restart countdown: shutdown.exe shows its
// "you're about to be signed out" warning with the message, and records the
// reason as planned operating-system maintenance (hotfix installation).
func scheduleRestart(ctx context.Context, minutes int, msg string) error {
	return exec.CommandContext(ctx, "shutdown.exe", "/r", "/t", strconv.Itoa(minutes*60), "/c", msg, "/d", "p:2:17").Run()
}
