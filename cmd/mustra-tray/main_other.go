//go:build !windows

package main

import (
	"fmt"
	"os"
)

// The tray helper is Windows-only for now. macOS gets a genuine native
// notification from the agent already (osascript reaches the console user's
// session, which has no equivalent on Windows), so the gap this closes is
// much smaller there -- and a menu-bar item needs Cocoa, which would mean
// cgo and a separate darwin build path.
//
// This file exists so `go build ./...` and `go vet ./...` stay honest on
// Linux and macOS rather than silently skipping the package.
func main() {
	fmt.Fprintln(os.Stderr, "mustra-tray runs on Windows only")
	os.Exit(1)
}
