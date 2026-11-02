//go:build windows

package server

import "os"

// restartSelf on Windows, where there is no SIGTERM to deliver to yourself:
// os.Process.Signal accepts only Kill here, so the graceful path the Unix
// build takes does not exist and the process exits instead. Whatever
// supervises it — a service manager or a container restart policy — brings
// it back, which is the same contract, just without the wind-down.
//
// The control plane is deployed on Linux. This file exists because CI
// compiles every package for Windows, where the agent does run as a
// service, and `syscall.Kill` is undefined there — a package that only
// builds on the maintainer's OS is precisely what that job is for.
func restartSelf() {
	os.Exit(0)
}
