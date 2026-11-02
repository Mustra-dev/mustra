//go:build darwin

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// macOS: checking is all the agent can do. Marking a root trusted needs
// a person's authorization even for root, so installing (and removing a
// profile-installed root) is the server's job through MDM.
func trustRootOS(ctx context.Context, root rootCert, remove bool) (string, error) {
	dir, err := os.MkdirTemp("", "mustra-root-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, root.file)
	if err := os.WriteFile(file, root.pem, 0o600); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	trusted := exec.CommandContext(cctx, "security", "verify-cert", "-c", file, "-p", "basic", "-L").Run() == nil
	switch {
	case remove && !trusted:
		return "not installed", nil
	case !remove && trusted:
		return "already trusted", nil
	}
	return "", errMDM(remove)
}

type mdmRequired string

func (m mdmRequired) Error() string { return string(m) }

func errMDM(remove bool) error {
	if remove {
		return mdmRequired(errMDMRequiredPrefix + "macOS removes a profile-installed root only through MDM")
	}
	return mdmRequired(errMDMRequiredPrefix + "macOS trusts a new root only through an MDM profile")
}
