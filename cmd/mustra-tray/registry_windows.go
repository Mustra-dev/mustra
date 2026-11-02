//go:build windows

package main

import (
	"os"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// Identity and activation, both per-user in HKCU.
//
// appUserModelID is what makes a toast ours. Without an AUMID that Windows
// recognises, a notification shows under whatever process raised it -- which
// would be "Windows PowerShell", with PowerShell's icon, on an endpoint
// being told its machine is about to restart.
//
// The usual way to own an AUMID is a Start Menu shortcut carrying the
// property, which means COM and IPropertyStore. Registering it directly is
// documented, does the same job for notifications, and is three registry
// values.
// registerIdentity is idempotent and cheap, so it runs at every start
// rather than being something an installer has to remember. A profile that
// has never seen this helper before -- a new user on a shared machine --
// gets it on first login instead of getting PowerShell's icon forever.
func registerIdentity(logoPath string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		`SOFTWARE\Classes\AppUserModelId\`+appUserModelID, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("DisplayName", displayName); err != nil {
		return err
	}
	if logoPath != "" {
		if err := k.SetStringValue("IconUri", logoPath); err != nil {
			return err
		}
	}
	// Without this, Windows may collapse our toasts into the generic
	// "Settings" group in the notification centre.
	return k.SetDWordValue("ShowInSettings", 1)
}

// registerProtocol points the mustra: scheme at this executable, which is
// how a toast button's click reaches us. The shell starts a fresh copy with
// the URI as its only argument; see main.
func registerProtocol() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	root, _, err := registry.CreateKey(registry.CURRENT_USER,
		`SOFTWARE\Classes\`+protocolScheme, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.SetStringValue("", "URL:mustra"); err != nil {
		return err
	}
	// The empty "URL Protocol" value is the flag that tells the shell this
	// key describes a protocol rather than a file type. Its presence is
	// what matters, not its content.
	if err := root.SetStringValue("URL Protocol", ""); err != nil {
		return err
	}
	cmd, _, err := registry.CreateKey(registry.CURRENT_USER,
		`SOFTWARE\Classes\`+protocolScheme+`\shell\open\command`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer cmd.Close()
	return cmd.SetStringValue("", strconv.Quote(exe)+" %1")
}

// registerAutostart asks Windows to start this helper when the person logs
// in. Per-user (HKCU) rather than machine-wide on purpose: it draws in a
// specific desktop session, and a machine-wide entry would start a copy in
// every session including ones nobody is looking at.
func registerAutostart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("mustra-tray", strconv.Quote(exe))
}

// unregister removes every trace of the above. It exists so uninstalling
// the agent can leave a user's profile as it found it, rather than leaving
// a dead protocol handler and an autostart entry pointing at a file that is
// no longer there.
func unregister() {
	registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Classes\`+protocolScheme+`\shell\open\command`)
	registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Classes\`+protocolScheme+`\shell\open`)
	registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Classes\`+protocolScheme+`\shell`)
	registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Classes\`+protocolScheme)
	registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Classes\AppUserModelId\`+appUserModelID)
	if k, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE); err == nil {
		k.DeleteValue("mustra-tray")
		k.Close()
	}
}
