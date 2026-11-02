//go:build linux

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Each distribution family keeps extra anchors in its own directory and
// rebuilds the bundle with its own tool.
var linuxTrustStores = []struct {
	tool, dir string
	args      []string
}{
	{"update-ca-certificates", "/usr/local/share/ca-certificates", nil},                // Debian, Ubuntu, Alpine, Proxmox
	{"update-ca-trust", "/etc/pki/ca-trust/source/anchors", []string{"extract"}},       // RHEL, Fedora, Amazon
	{"trust", "/etc/ca-certificates/trust-source/anchors", []string{"extract-compat"}}, // Arch
}

func trustRootOS(ctx context.Context, root rootCert, remove bool) (string, error) {
	for _, st := range linuxTrustStores {
		tool, err := exec.LookPath(st.tool)
		if err != nil {
			continue
		}
		path := filepath.Join(st.dir, root.file)
		existing, readErr := os.ReadFile(path)
		if remove {
			if readErr != nil {
				return "not installed", nil
			}
			if err := os.Remove(path); err != nil {
				return "", err
			}
		} else {
			if readErr == nil && bytes.Equal(existing, root.pem) {
				return "already installed in " + path, nil
			}
			if err := os.MkdirAll(st.dir, 0o755); err != nil {
				return "", err
			}
			if err := os.WriteFile(path, root.pem, 0o644); err != nil {
				return "", err
			}
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(cctx, tool, st.args...).CombinedOutput()
		if err != nil {
			if !remove {
				_ = os.Remove(path)
			}
			return string(out), fmt.Errorf("%s: %v %s", st.tool, err, lastLine(string(out), err))
		}
		if remove {
			return "removed " + path, nil
		}
		return "installed " + path + " (" + st.tool + ")", nil
	}
	return "", errors.New("unsupported: no system trust store tool (update-ca-certificates, update-ca-trust or trust) is installed")
}
