//go:build !windows

package agent

import (
	"context"
	"os/exec"
	"strconv"
)

// scheduleRestart is shutdown(8)'s own countdown on Linux and macOS; the
// message goes to every signed-in terminal.
func scheduleRestart(ctx context.Context, minutes int, msg string) error {
	return exec.CommandContext(ctx, "/sbin/shutdown", "-r", "+"+strconv.Itoa(minutes), msg).Run()
}
