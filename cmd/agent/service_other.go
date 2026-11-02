//go:build !windows

package main

import (
	"context"
	"log/slog"
)

// isService is always false off Windows: systemd and launchd run the agent
// as an ordinary foreground process and expect it to stay in the
// foreground, so there is no separate service handshake to perform.
func isService() bool { return false }

func runService(_ func(context.Context) error, _ *slog.Logger) (bool, error) {
	return false, nil
}
