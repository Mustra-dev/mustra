//go:build !darwin

package agent

import (
	"context"
	"log/slog"
)

// openSoftwareUpdate exists only on macOS.
func openSoftwareUpdate(context.Context, *slog.Logger) {}
