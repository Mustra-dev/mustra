//go:build windows && arm64

package agent

import _ "embed"

//go:embed trayembed/mustra-tray-windows-arm64.bin
var embeddedTray []byte
