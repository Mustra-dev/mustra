//go:build windows && amd64

package agent

import _ "embed"

//go:embed trayembed/mustra-tray-windows-amd64.bin
var embeddedTray []byte
