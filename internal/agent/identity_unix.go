//go:build !windows

package agent

import (
	"log/slog"
	"os"
	"path/filepath"
)

// writeSecretFile writes data readable by its owner (root) only, through a
// temporary file in the same directory so a crash never leaves half a
// credential behind.
func writeSecretFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// scrubMachineCredential has nothing to do outside Windows: the installers
// there never put the password anywhere but agent.env and the plist.
func scrubMachineCredential(*slog.Logger) {}
