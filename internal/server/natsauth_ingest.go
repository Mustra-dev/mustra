package server

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// What an agent publishes is input, not data.
//
// Two rules for everything arriving on beacon.agent.<id>.*:
//
//  1. It is attributed to <id> from the subject. The broker only lets the
//     agent authenticated as <id> publish there (internal/nats
//     AgentPermissions), whereas the agent_id inside the body is whatever
//     the sender typed. A body that names someone else is dropped.
//  2. Sensor snapshots are decoded into their proto types and re-encoded
//     before they are stored, so what the console later reads back has the
//     shape the Go types promise. A snapshot used to be stored verbatim and
//     served verbatim, and a process list whose "pid" was a string of HTML
//     ran script in an operator's browser.

// attributeFromSubject returns the agent the broker vouches for, and
// whether a body's own claim (empty is fine) agrees with it.
func attributeFromSubject(subject, claimed string) (string, error) {
	id, ok := bnats.AgentIDFromSubject(subject)
	if !ok {
		return "", fmt.Errorf("subject %q does not name a valid agent", subject)
	}
	if claimed != "" && claimed != id {
		return "", fmt.Errorf("body claims agent %q but arrived on %q's subject", claimed, id)
	}
	return id, nil
}

// Custom sensor kinds are "custom_" + the sensor's ID, and those IDs are
// "csn-<hex>", so the hyphen has to be allowed or every custom sensor's
// results are discarded.
var sensorKindPattern = regexp.MustCompile(`^[a-z0-9_-]{1,80}$`)

// normalizeTyped decodes raw into a fresh T and re-encodes it. Unknown
// fields are dropped; a value of the wrong type is an error.
func normalizeTyped[T any](raw json.RawMessage) (json.RawMessage, error) {
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// normalizeSnapshotData returns the snapshot's data re-encoded through its
// type. A kind this server does not know is refused: it would have no
// renderer here anyway, and storing shapes nobody validated is the bug.
func normalizeSnapshotData(kind proto.SensorKind, raw json.RawMessage) (json.RawMessage, error) {
	if !sensorKindPattern.MatchString(string(kind)) {
		return nil, fmt.Errorf("malformed sensor kind %q", kind)
	}
	if strings.HasPrefix(string(kind), "custom_") {
		// The agent publishes the script's output (lines, exit code), not
		// rows: RecordCustomSensor parses the rows itself from that output
		// and the stored definition, discarding any the agent supplied.
		return normalizeTyped[proto.CustomSensorResult](raw)
	}
	switch kind {
	case proto.SensorProcesses:
		return normalizeTyped[[]proto.ProcessInfo](raw)
	case proto.SensorServices:
		return normalizeTyped[[]proto.ServiceInfo](raw)
	case proto.SensorInstalledApps:
		return normalizeTyped[[]proto.InstalledApp](raw)
	case proto.SensorPatches:
		return normalizeTyped[[]proto.PatchInfo](raw)
	case proto.SensorDisks:
		return normalizeTyped[[]proto.DiskInfo](raw)
	case proto.SensorNetwork:
		return normalizeTyped[[]proto.NetworkInterfaceInfo](raw)
	case proto.SensorUsers:
		return normalizeTyped[[]proto.LoggedInUser](raw)
	case proto.SensorHardware:
		return normalizeTyped[[]proto.HardwareInfo](raw)
	case proto.SensorPrivileges:
		out, err := normalizeTyped[[]proto.PrivilegeInfo](raw)
		if err != nil {
			// Agents before the slice wrapping published the lone object.
			var one proto.PrivilegeInfo
			if json.Unmarshal(raw, &one) != nil {
				return nil, err
			}
			return json.Marshal([]proto.PrivilegeInfo{one})
		}
		return out, nil
	case proto.SensorNeighbors:
		return normalizeTyped[[]proto.NeighborInfo](raw)
	case proto.SensorCertificates:
		return normalizeTyped[[]proto.CertificateInfo](raw)
	case proto.SensorPerformance:
		return normalizeTyped[[]proto.PerformanceInfo](raw)
	case proto.SensorIntegrity:
		return normalizeTyped[[]proto.IntegrityFile](raw)
	case proto.SensorLocalAdmins:
		return normalizeTyped[[]proto.LocalAdmin](raw)
	case proto.SensorDirectory:
		return normalizeTyped[[]proto.DirectoryInfo](raw)
	case proto.SensorBackups:
		return normalizeTyped[[]proto.BackupGuest](raw)
	case proto.SensorPatchStatus:
		return normalizeTyped[proto.PatchStatus](raw)
	case proto.SensorSecurityPosture:
		return normalizeTyped[[]proto.SecurityPosture](raw)
	case proto.SensorReveal:
		return normalizeTyped[proto.RevealReport](raw)
	}
	return nil, fmt.Errorf("unknown sensor kind %q", kind)
}

var validLogLevels = map[string]bool{"": true, "debug": true, "info": true, "warn": true, "error": true}

// normalizeFacts bounds the agent-reported runtime settings to the values
// a client profile can actually set, so a forged "settings" cannot carry
// markup or nonsense into the drift view.
func normalizeFacts(f *proto.Facts) {
	if f.Site != "" {
		f.Site = sanitizeSite(f.Site)
	}
	if f.Settings == nil {
		return
	}
	st := f.Settings
	if !validLogLevels[st.LogLevel] {
		st.LogLevel = ""
	}
	if st.SensorIntervalSeconds < 0 || st.SensorIntervalSeconds > 7*24*3600 {
		st.SensorIntervalSeconds = 0
	}
	if st.RandomDelaySeconds < 0 || st.RandomDelaySeconds > 24*3600 {
		st.RandomDelaySeconds = 0
	}
	if len(st.Profile) > 200 {
		st.Profile = st.Profile[:200]
	}
}
