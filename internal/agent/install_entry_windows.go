package agent

import (
	"log/slog"

	"golang.org/x/sys/windows/registry"
)

// installEntryKey is the Add/Remove Programs entry install.ps1 writes.
const installEntryKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MustraAgent`

// syncInstallEntry keeps that entry's version equal to the running build.
// install.ps1 sets it once, and a self-update replaces the binary without
// running the installer, so Installed Apps (and the agent's own installed
// software sensor) kept showing the version first installed. An entry that
// does not exist is left alone: this agent was installed some other way.
func syncInstallEntry(version string) {
	if version == "" || version == "dev" {
		return
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, installEntryKey, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return
	}
	defer k.Close()
	if cur, _, err := k.GetStringValue("DisplayVersion"); err == nil && cur == version {
		return
	}
	if err := k.SetStringValue("DisplayVersion", version); err != nil {
		slog.Warn("could not update the Installed Apps version", "err", err)
	}
}
