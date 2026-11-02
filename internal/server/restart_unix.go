//go:build !windows

package server

import (
	"os"
	"syscall"
)

// restartSelf stops this process the way the deployment expects to be told:
// SIGTERM to ourselves, which is exactly what cmd/server's
// signal.NotifyContext is already listening for. The root context is
// cancelled, every background loop winds down, and the container's
// restart policy brings the server back clean. A bare exit code would
// leave somebody to interpret it; after a restore, coming back is not
// optional.
func restartSelf() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
}
