package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mustra-dev/mustra/internal/proto"
)

// A software package is one piece of software mustra knows how to install,
// update, or remove. It is the single catalog: pushing software to a
// thousand endpoints and letting one person install it from Self Service
// are the same object with a different publishing flag, so there is exactly
// one place to define each piece of software.

// SoftwareOps is what a package can do on one platform. An empty command
// means that operation isn't supported — a package with only Install is an
// install-only package, which is a normal thing to want.
type SoftwareOps struct {
	Install string `json:"install,omitempty"`
	Update  string `json:"update,omitempty"`
	Remove  string `json:"remove,omitempty"`
}

// SoftwareDetect says how to recognize the software on an endpoint. It
// matches against the installed_apps sensor mustra already collects, so
// detection costs nothing extra on the endpoint — no extra scan, no extra
// command run per package per device.
type SoftwareDetect struct {
	AppName string `json:"app_name,omitempty"`
	Match   string `json:"match,omitempty"` // "exact" (default) or "contains"
	// Fact detects against something mustra already knows about the
	// endpoint rather than against its installed-applications list.
	//
	// There is exactly one of these and it is deliberately not a general
	// escape hatch: "agent_version" compares the running agent against the
	// build the control plane is serving. mustra is the only software whose
	// installed version it knows without a sensor, and the agent-update
	// package is otherwise an action package — never "installed", so
	// eligible on every endpoint for ever, including the ones that just
	// updated.
	Fact string `json:"fact,omitempty"`
}

// FactAgentVersion is the only value SoftwareDetect.Fact takes today.
const FactAgentVersion = "agent_version"

// SoftwareRequirements gate applicability. A package that needs 4 GB of RAM
// is Not Applicable on a device with 2, rather than a deployment that fails
// halfway through.
type SoftwareRequirements struct {
	Arch      []string `json:"arch,omitempty"`
	MinDiskGB float64  `json:"min_disk_gb,omitempty"`
	MinRAMMB  uint64   `json:"min_ram_mb,omitempty"`
}

// PackageKind separates the two things a package can be. Drawing the
// same line, and it is not cosmetic: a software package is verified by
// finding the software installed afterwards, while an action package runs a
// command and has nothing to detect. Conflating them meant a reboot needed
// a fake detection name and deployed under the label "Install Reboot
// Computer".
const (
	KindSoftware = "software"
	KindAction   = "action"
)

// SoftwareParameter is one typed input substituted into a package's command
// before it runs: parameterized packages. The command
// refers to it as $(name), so "restart in N seconds" is one package rather
// than one package per value of N.
type SoftwareParameter struct {
	Name  string `json:"name"`            // substituted as $(name)
	Label string `json:"label,omitempty"` // what the operator is asked
	// Type is "text", "numeric", "select" or "checkbox".
	Type     string   `json:"type"`
	Default  string   `json:"default,omitempty"`
	Options  []string `json:"options,omitempty"` // "select" only
	Min      *float64 `json:"min,omitempty"`     // "numeric" only
	Max      *float64 `json:"max,omitempty"`     // "numeric" only
	Validate string   `json:"validate,omitempty"`
	Required bool     `json:"required,omitempty"`
	Help     string   `json:"help,omitempty"`
}

type SoftwarePackage struct {
	PreparedDeployJobs      map[string]proto.DeployJob `json:"-"`
	SelfServiceRevision     string                     `json:"self_service_revision,omitempty"`
	SelfServiceFollowLatest bool                       `json:"self_service_follow_latest"`
	DeployDefinition        *proto.DeployDefinition    `json:"deploy_definition,omitempty"`
	DeployParameters        map[string]string          `json:"-"`
	DeployRevision          string                     `json:"deploy_revision,omitempty"`
	ID                      string                     `json:"id"`
	Kind                    string                     `json:"kind"`
	Name                    string                     `json:"name" api:"required"`
	Vendor                  string                     `json:"vendor"`
	Version                 string                     `json:"version"`
	Description             string                     `json:"description"`
	Category                string                     `json:"category"`
	Icon                    string                     `json:"icon"`
	Commands                map[string]SoftwareOps     `json:"commands" api:"required"`
	Detect                  SoftwareDetect             `json:"detect"`
	Requirements            SoftwareRequirements       `json:"requirements"`
	GroupIDs                []string                   `json:"group_ids"`
	SelfService             bool                       `json:"self_service"`
	AllowRequests           bool                       `json:"allow_requests"`
	// RequireExplicitTargets refuses a fleet-wide run. The operator has to
	// name the endpoints. For a package that removes the agent, "all online
	// endpoints" is one mis-click away from a fleet nobody can manage
	// remotely any more -- including to put the agent back.
	RequireExplicitTargets bool   `json:"require_explicit_targets"`
	Enabled                bool   `json:"enabled"`
	Source                 string `json:"source"`
	// CommandTimeoutSeconds caps this package's command; 0 uses the
	// agent's default. ExpireSeconds stops the deployment being worth
	// attempting after that long; 0 never expires.
	CommandTimeoutSeconds int                 `json:"command_timeout_seconds"`
	ExpireSeconds         int                 `json:"expire_seconds"`
	Parameters            []SoftwareParameter `json:"parameters,omitempty"`
	CreatedAt             time.Time           `json:"created_at" api:"readonly"`
	UpdatedAt             time.Time           `json:"updated_at" api:"readonly"`
	CreatedBy             string              `json:"created_by" api:"readonly"`
	// UpdatedBy: who last changed the package's details. Empty for rows
	// last changed before it was recorded.
	UpdatedBy string `json:"updated_by" api:"readonly"`
	// VersionSource makes Version follow an upstream project's latest
	// release: "github:<owner>/<repo>". Empty: Version is set by hand.
	VersionSource string `json:"version_source,omitempty"`
}

const softwareColumns = `id, kind, name, vendor, version, description, category, icon,
       commands, detect, requirements, group_ids, self_service, allow_requests,
       require_explicit_targets,
       enabled, source, command_timeout_seconds, expire_seconds, parameters,
       created_at, updated_at, created_by, deploy_revision, (SELECT definition FROM deploy_revisions WHERE id=software_packages.deploy_revision), self_service_revision, self_service_follow_latest, updated_by, version_source`

func scanSoftwarePackage(row pgx.Row) (*SoftwarePackage, error) {
	var p SoftwarePackage
	var commands, detect, requirements, parameters, definition []byte
	if err := row.Scan(&p.ID, &p.Kind, &p.Name, &p.Vendor, &p.Version, &p.Description, &p.Category,
		&p.Icon, &commands, &detect, &requirements, &p.GroupIDs, &p.SelfService,
		&p.AllowRequests, &p.RequireExplicitTargets, &p.Enabled, &p.Source,
		&p.CommandTimeoutSeconds, &p.ExpireSeconds,
		&parameters, &p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &p.DeployRevision, &definition, &p.SelfServiceRevision, &p.SelfServiceFollowLatest, &p.UpdatedBy, &p.VersionSource); err != nil {
		return nil, err
	}
	// A row whose JSON we can't parse is still a usable package row — the
	// name and scope survive — so decode failures leave the field zero
	// rather than dropping the package out of the catalog entirely.
	_ = json.Unmarshal(commands, &p.Commands)
	_ = json.Unmarshal(detect, &p.Detect)
	_ = json.Unmarshal(requirements, &p.Requirements)
	_ = json.Unmarshal(parameters, &p.Parameters)
	if len(definition) > 0 {
		if err := json.Unmarshal(definition, &p.DeployDefinition); err != nil {
			return nil, err
		}
	}
	if p.Commands == nil {
		p.Commands = map[string]SoftwareOps{}
	}
	if p.GroupIDs == nil {
		p.GroupIDs = []string{}
	}
	return &p, nil
}

func (s *Store) ListSoftwarePackages(ctx context.Context) ([]SoftwarePackage, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+softwareColumns+` FROM software_packages ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list software packages: %w", err)
	}
	defer rows.Close()
	var out []SoftwarePackage
	for rows.Next() {
		p, err := scanSoftwarePackage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan software package: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *Store) GetSoftwarePackage(ctx context.Context, id string) (*SoftwarePackage, error) {
	p, err := scanSoftwarePackage(s.pool.QueryRow(ctx,
		`SELECT `+softwareColumns+` FROM software_packages WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get software package: %w", err)
	}
	return p, nil
}

func (s *Store) UpsertSoftwarePackage(ctx context.Context, p SoftwarePackage) (*SoftwarePackage, error) {
	commands, err := json.Marshal(p.Commands)
	if err != nil {
		return nil, fmt.Errorf("encode commands: %w", err)
	}
	detect, err := json.Marshal(p.Detect)
	if err != nil {
		return nil, fmt.Errorf("encode detect: %w", err)
	}
	requirements, err := json.Marshal(p.Requirements)
	if err != nil {
		return nil, fmt.Errorf("encode requirements: %w", err)
	}
	if p.GroupIDs == nil {
		p.GroupIDs = []string{}
	}
	// The insert passes the kind, so the column default never applies:
	// left out, it is software, as every reader takes it (#119).
	if p.Kind == "" {
		p.Kind = KindSoftware
	}
	if p.Source == "" {
		p.Source = "manual"
	}

	const q = `
INSERT INTO software_packages (id, kind, name, vendor, version, description, category, icon,
                               commands, detect, requirements, group_ids, self_service,
                               allow_requests, require_explicit_targets, enabled, source, created_by,
                               command_timeout_seconds, expire_seconds, parameters, self_service_revision, self_service_follow_latest, updated_by, version_source)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
ON CONFLICT (id) DO UPDATE SET
  kind = EXCLUDED.kind,
  name = EXCLUDED.name, vendor = EXCLUDED.vendor, version = EXCLUDED.version,
  description = EXCLUDED.description, category = EXCLUDED.category, icon = EXCLUDED.icon,
  commands = EXCLUDED.commands, detect = EXCLUDED.detect, requirements = EXCLUDED.requirements,
  group_ids = EXCLUDED.group_ids, self_service = EXCLUDED.self_service,
  allow_requests = EXCLUDED.allow_requests,
  require_explicit_targets = EXCLUDED.require_explicit_targets, enabled = EXCLUDED.enabled,
  command_timeout_seconds = EXCLUDED.command_timeout_seconds,
  expire_seconds = EXCLUDED.expire_seconds, parameters = EXCLUDED.parameters,
 self_service_revision=CASE WHEN EXCLUDED.self_service_revision='' THEN software_packages.self_service_revision ELSE EXCLUDED.self_service_revision END, self_service_follow_latest=EXCLUDED.self_service_follow_latest,
  updated_by = CASE WHEN EXCLUDED.updated_by='' THEN software_packages.updated_by ELSE EXCLUDED.updated_by END,
  version_source = EXCLUDED.version_source,
  updated_at = now()
RETURNING ` + softwareColumns
	params, err := json.Marshal(p.Parameters)
	if err != nil {
		return nil, fmt.Errorf("encode package parameters: %w", err)
	}
	out, err := scanSoftwarePackage(s.pool.QueryRow(ctx, q,
		p.ID, p.Kind, p.Name, p.Vendor, p.Version, p.Description, p.Category, p.Icon,
		commands, detect, requirements, p.GroupIDs, p.SelfService, p.AllowRequests,
		p.RequireExplicitTargets, p.Enabled, p.Source, p.CreatedBy,
		p.CommandTimeoutSeconds, p.ExpireSeconds, params, p.SelfServiceRevision, p.SelfServiceFollowLatest, p.UpdatedBy, p.VersionSource))
	if err != nil {
		return nil, fmt.Errorf("upsert software package: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteSoftwarePackage(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM software_packages WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete software package: %w", err)
	}
	return nil
}

// DiscoveredSoftware is one distinct application the fleet already has
// installed, with how widely it's deployed and which platforms it appears
// on. This is the seed for a catalog: rather than starting from an empty
// page, an operator publishes what the fleet demonstrably already runs.
type DiscoveredSoftware struct {
	Name        string   `json:"name"`
	Vendor      string   `json:"vendor"`
	Versions    []string `json:"versions"`
	DeviceCount int      `json:"device_count"`
	Platforms   []string `json:"platforms"`
	InCatalog   bool     `json:"in_catalog"`
}

// DiscoverInstalledSoftware aggregates the installed_apps sensor across the
// fleet. It reads the snapshots mustra already holds — no new collection,
// no endpoint work — and answers "what is actually out there".
func (s *Store) DiscoverInstalledSoftware(ctx context.Context, minDevices int) ([]DiscoveredSoftware, error) {
	const q = `
WITH apps AS (
  SELECT sd.agent_id,
         a.os                                    AS os,
         app->>'name'                            AS name,
         -- Agents report the publisher as "publisher" (Windows, macOS); "vendor"
         -- was never sent, so every row came back without one.
         coalesce(nullif(app->>'publisher', ''), app->>'vendor', '') AS vendor,
         coalesce(app->>'version', '')           AS version
  FROM agent_sensor_data sd
  JOIN agents a ON a.agent_id = sd.agent_id
  CROSS JOIN LATERAL jsonb_array_elements(sd.data) AS app
  WHERE sd.sensor = 'installed_apps'
    AND jsonb_typeof(sd.data) = 'array'
    AND coalesce(app->>'name', '') <> ''
)
SELECT name,
       (array_agg(vendor ORDER BY vendor DESC))[1]              AS vendor,
       array_agg(DISTINCT version) FILTER (WHERE version <> '') AS versions,
       count(DISTINCT agent_id)                                 AS device_count,
       array_agg(DISTINCT os)                                   AS platforms
FROM apps
GROUP BY name
HAVING count(DISTINCT agent_id) >= $1
ORDER BY count(DISTINCT agent_id) DESC, lower(name)
LIMIT 10000`
	rows, err := s.pool.Query(ctx, q, minDevices)
	if err != nil {
		return nil, fmt.Errorf("discover installed software: %w", err)
	}
	defer rows.Close()

	var out []DiscoveredSoftware
	for rows.Next() {
		var d DiscoveredSoftware
		if err := rows.Scan(&d.Name, &d.Vendor, &d.Versions, &d.DeviceCount, &d.Platforms); err != nil {
			return nil, fmt.Errorf("scan discovered software: %w", err)
		}
		if d.Versions == nil {
			d.Versions = []string{}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetFollowedVersion records the version a package's upstream released,
// leaving the rest of the package as it is. It reports whether the version
// changed.
func (s *Store) SetFollowedVersion(ctx context.Context, id, version string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE software_packages SET version = $2, updated_at = now()
WHERE id = $1 AND version_source <> '' AND version IS DISTINCT FROM $2`, id, version)
	if err != nil {
		return false, fmt.Errorf("set followed version: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
