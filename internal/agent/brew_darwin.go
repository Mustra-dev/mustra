//go:build darwin

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// brewInstall installs via Homebrew. The agent runs as root (a launchd
// daemon, which is what gives it the rights to manage this machine at
// all), and Homebrew flatly refuses to run as root. So drop to whoever
// owns the brew prefix — that's the account Homebrew was set up under and
// the only one it will accept.
func brewInstall(ctx context.Context, pkg string) (string, error) {
	path, err := lookBrew()
	if err != nil {
		return "", fmt.Errorf("Homebrew isn't installed on this Mac — install it from https://brew.sh first")
	}
	if os.Geteuid() != 0 {
		out, err := exec.CommandContext(ctx, path, "install", pkg).CombinedOutput()
		return string(out), err
	}

	owner, err := brewPrefixOwner(path)
	if err != nil {
		return "", fmt.Errorf("finding the account Homebrew belongs to: %w", err)
	}
	// sudo -u rather than dropping credentials ourselves: it sets up the
	// target account's environment, which Homebrew needs (HOME, PATH, and
	// its own prefix detection all key off it).
	cmd := exec.CommandContext(ctx, "sudo", "-u", owner, "-H", path, "install", pkg)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// lookBrew finds brew even when PATH is launchd's minimal one, which is
// what a system daemon inherits — /usr/local/bin and /opt/homebrew/bin are
// not on it.
func lookBrew() (string, error) {
	if path, err := exec.LookPath("brew"); err == nil {
		return path, nil
	}
	for _, candidate := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("brew not found")
}

// brewPrefixOwner returns the username that owns the brew binary — the
// account Homebrew was installed under.
func brewPrefixOwner(brewPath string) (string, error) {
	st, err := os.Stat(brewPath)
	if err != nil {
		return "", err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("cannot read ownership of %s", brewPath)
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(sys.Uid), 10))
	if err != nil {
		return "", err
	}
	if u.Username == "root" {
		return "", fmt.Errorf("Homebrew at %s is owned by root, which it refuses to run as", brewPath)
	}
	return u.Username, nil
}
