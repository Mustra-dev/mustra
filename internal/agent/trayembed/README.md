The Windows tray helper (cmd/mustra-tray) is built into these files by
deploy/Dockerfile.server just before the agent, so every Windows agent build
carries the matching tray inside its signed binary and installs it on start
(internal/agent/trayinstall_windows.go). The committed files are empty
placeholders; a build with an empty one simply skips the tray install.
