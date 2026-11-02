package agent

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// startInNewSession has no meaning on Windows, which detaches through
// Start-Process in spawnDetachedUpdater and never reaches here.
func startInNewSession(string) error {
	return fmt.Errorf("no session detachment on windows")
}

const windowsServiceName = "mustra-agent"

func hasSystemd() bool { return false }

// stopAgentService stops the service and waits for it to report Stopped:
// Windows will not let the image be renamed over while it is still mapped.
func stopAgentService(string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
	}
	for i := 0; i < 60; i++ {
		if status, err = s.Query(); err == nil && status.State == svc.Stopped {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("the service did not stop within a minute")
}

func startAgentService(string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}
