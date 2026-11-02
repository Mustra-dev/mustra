//go:build darwin

package agent

import (
	"os/exec"
	"strings"
)

// interactiveUser is who owns the Mac's display. The agent runs as root,
// so its own account says nothing about the person looking at the window.
func interactiveUser() string {
	out, err := exec.Command("/usr/bin/stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(string(out))
	switch name {
	case "", "root", "_mbsetupuser", "loginwindow":
		return "" // nobody signed in, or Setup Assistant
	}
	return name
}
