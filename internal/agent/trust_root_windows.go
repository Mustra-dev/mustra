//go:build windows

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// The machine's Trusted Root Certification Authorities store, which every
// account and service on the machine trusts.
func trustRootOS(ctx context.Context, root rootCert, remove bool) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	present := exec.CommandContext(cctx, "certutil.exe", "-store", "Root", root.sha1).Run() == nil
	if remove {
		if !present {
			return "not installed", nil
		}
		out, err := exec.CommandContext(cctx, "certutil.exe", "-delstore", "Root", root.sha1).CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("certutil -delstore: %v %s", err, lastLine(string(out), err))
		}
		return "removed from LocalMachine\\Root", nil
	}
	if present {
		return "already in LocalMachine\\Root", nil
	}
	dir, err := os.MkdirTemp("", "mustra-root-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, root.file)
	if err := os.WriteFile(file, root.pem, 0o600); err != nil {
		return "", err
	}
	out, err := exec.CommandContext(cctx, "certutil.exe", "-addstore", "-f", "Root", file).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("certutil -addstore: %v %s", err, lastLine(string(out), err))
	}
	return "installed in LocalMachine\\Root", nil
}
