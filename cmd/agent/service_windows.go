//go:build windows

package main

import (
	"context"
	"log/slog"

	"golang.org/x/sys/windows/svc"
)

// serviceName must match the name install.ps1 passes to New-Service.
const serviceName = "mustra-agent"

// isService reports whether this process was launched by the Windows
// Service Control Manager rather than from a console.
func isService() bool {
	is, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return is
}

// agentService adapts the agent's run loop to the SCM handshake. Windows
// kills any service that does not report Running within ~30s of launch,
// which is why a plain console binary registered with New-Service fails
// with error 1053 no matter how healthy the program itself is.
type agentService struct {
	run    func(context.Context) error
	logger *slog.Logger
}

func (s *agentService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			// The agent returned on its own. Report Stopped with a
			// non-zero exit code so the SCM's restart policy (configured
			// by install.ps1) kicks in.
			if err != nil {
				s.logger.Error("agent exited with error", "error", err)
				changes <- svc.Status{State: svc.Stopped}
				return false, 1
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done // let the agent close NATS and flush its outbox
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}

// runService runs under the SCM when launched as a service. The bool
// reports whether it handled execution; false means "run normally".
func runService(run func(context.Context) error, logger *slog.Logger) (bool, error) {
	if !isService() {
		return false, nil
	}
	return true, svc.Run(serviceName, &agentService{run: run, logger: logger})
}
