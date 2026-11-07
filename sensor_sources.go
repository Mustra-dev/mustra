package mustra

import "embed"

// SensorSources ships the collector source from this server build so inspection
// works offline and cannot silently drift to a newer repository revision.
// Only collector files are exposed; this is not a general filesystem endpoint.
//
//go:embed internal/agent/sensors.go internal/agent/inventory.go internal/agent/patches.go internal/agent/patchlist.go internal/agent/privileges_*.go internal/agent/neighbors.go internal/agent/certificates.go internal/agent/certificates_sources.go internal/agent/performance.go internal/agent/integrity.go internal/agent/integrity_unix.go internal/agent/integrity_windows.go internal/agent/localadmins_*.go internal/agent/directory.go internal/agent/backups.go internal/agent/containers.go internal/agent/container_updates.go internal/agent/sensor_loop.go internal/agent/action_logs.go
//go:embed internal/agent/sensors.go internal/agent/inventory.go internal/agent/patches.go internal/agent/patchlist.go internal/agent/privileges_*.go internal/agent/neighbors.go internal/agent/certificates.go internal/agent/performance.go internal/agent/integrity.go internal/agent/integrity_unix.go internal/agent/integrity_windows.go internal/agent/posture.go internal/agent/posture_*.go internal/agent/sensor_loop.go internal/agent/action_logs.go
var SensorSources embed.FS
