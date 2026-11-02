//go:build darwin

package agent

import (
	"context"
	"log/slog"
	"os/exec"
	"time"
)

// openSoftwareUpdate opens System Settings → General → Software Update in
// the logged-in user's session (run as root it would open nowhere).
func openSoftwareUpdate(ctx context.Context, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c",
		`launchctl asuser "$(stat -f %u /dev/console)" /usr/bin/open "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"`)
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Warn("could not open Software Update for the user", "error", err, "output", string(out))
	}
}
