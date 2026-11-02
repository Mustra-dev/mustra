//go:build windows

package agent

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// secretFileSDDL admits SYSTEM and the Administrators group, full control,
// and nobody else; "P" protects the DACL from inheriting the parent's
// (ProgramData grants Users read by default).
const secretFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// writeSecretFile creates the file with its restrictive security
// descriptor from the first instant — not created and then restricted,
// which leaves a window — and renames it into place. A rename within a
// volume keeps the file's own DACL.
func writeSecretFile(path string, data []byte) error {
	sd, err := windows.SecurityDescriptorFromString(secretFileSDDL)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	tmp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.%d", filepath.Base(path), time.Now().UnixNano()))
	name, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), tmp)
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Belt and braces for a file that already existed with a looser DACL:
	// a rename over it replaces it, but set the descriptor explicitly too.
	dacl, _, err := sd.DACL()
	if err == nil {
		_ = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}
	return nil
}

// scrubMachineCredential removes the shared password older installers put
// in Machine environment variables, which any local user could read.
func scrubMachineCredential(logger *slog.Logger) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	for _, name := range []string{"MUSTRA_NATS_PASSWORD", "MUSTRA_NATS_USER", "BEACON_NATS_PASSWORD", "BEACON_NATS_USER"} {
		if _, _, err := k.GetStringValue(name); err == nil {
			if err := k.DeleteValue(name); err != nil {
				logger.Warn("could not remove a legacy credential from the Machine environment", "name", name, "error", err)
			} else {
				logger.Info("removed a legacy credential from the Machine environment", "name", name)
			}
		}
	}
}
