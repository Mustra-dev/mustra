package proto

import "time"

// DeployVersion is negotiated before dispatch. Older agents must never receive
// a flattened command that silently drops requirements or validation.
const DeployVersion = 2

type DeployParameter struct {
	Name     string   `json:"name"`
	Label    string   `json:"label,omitempty"`
	Type     string   `json:"type"`
	Default  string   `json:"default,omitempty"`
	Required bool     `json:"required,omitempty"`
	Secret   bool     `json:"secret,omitempty"`
	Options  []string `json:"options,omitempty"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
}

// Bindings are data, never executable source. Exactly one of Parameter or Value
// supplies an input; an empty literal value is valid.
type DeployBinding struct {
	Parameter string `json:"parameter,omitempty"`
	Value     string `json:"value,omitempty"`
}

type DeployDefinition struct {
	ReviewRequired bool              `json:"review_required,omitempty"` // converted drafts require explicit source/file review
	Kind           string            `json:"kind,omitempty"`            // omitted means software for existing revisions
	Files          []DeployFile      `json:"files,omitempty"`           // shared action payloads
	Version        int               `json:"version"`
	Parameters     []DeployParameter `json:"parameters,omitempty"`
	Variants       []DeployVariant   `json:"variants"`
}

type DeployVariant struct {
	ID           string                  `json:"id"`
	OS           string                  `json:"os"`
	Arch         []string                `json:"arch,omitempty"`
	Distribution []string                `json:"distribution,omitempty"`
	OSVersion    string                  `json:"os_version,omitempty"`
	Version      string                  `json:"version"`
	Parameters   []DeployParameter       `json:"parameters,omitempty"`
	Requirements *DeployCheck            `json:"requirements,omitempty"`
	Detection    *DeployCheck            `json:"detection,omitempty"`
	Actions      map[string]DeployAction `json:"actions"`
}

type DeployAction struct {
	SuccessMode         string             `json:"success_mode,omitempty"`     // exit_code (default), sensor, both
	DownloadSeconds     int                `json:"download_seconds,omitempty"` // zero selects the bounded default
	Parameters          []DeployParameter  `json:"parameters,omitempty"`
	Requirements        *DeployCheck       `json:"requirements,omitempty"`
	Validation          *DeployCheck       `json:"validation,omitempty"`
	ValidationSeconds   int                `json:"validation_seconds,omitempty"`
	RequireFiles        bool               `json:"require_files"`
	Files               []DeployFile       `json:"files,omitempty"`
	Dependencies        []DeployDependency `json:"dependencies,omitempty"`
	Steps               []DeployStep       `json:"steps"`
	Identity            string             `json:"identity,omitempty"` // administrator | user
	Username            string             `json:"username,omitempty"`
	ValidateAfterReboot bool               `json:"validate_after_reboot,omitempty"`
}

type DeployFile struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	SHA256       string   `json:"sha256"`
	Size         int64    `json:"size,omitempty"`
	URL          string   `json:"url,omitempty"`
	CredentialID string   `json:"credential_id,omitempty"`
	OS           []string `json:"os,omitempty"`
	Arch         []string `json:"arch,omitempty"`
}

type DeployDependency struct {
	PackageID  string                   `json:"package_id"`
	RevisionID string                   `json:"revision_id"`
	Version    string                   `json:"version,omitempty"`
	Parameters map[string]DeployBinding `json:"parameters,omitempty"`
}

type DeployScript struct {
	Language       string          `json:"language"`
	Source         string          `json:"source"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"`
	Artifact       *SensorArtifact `json:"artifact,omitempty"`
}

type DeployStep struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	If              *DeployCheck  `json:"if,omitempty"`
	Then            []DeployStep  `json:"then,omitempty"`
	Else            []DeployStep  `json:"else,omitempty"`
	Script          *DeployScript `json:"script,omitempty"`
	Files           []string      `json:"files,omitempty"`
	ContinueOnError bool          `json:"continue_on_error,omitempty"`
	RetrySafe       bool          `json:"retry_safe,omitempty"`
	Retries         int           `json:"retries,omitempty"`
	SuccessCodes    []int         `json:"success_codes,omitempty"`
	RebootCodes     []int         `json:"reboot_codes,omitempty"`
	LogPaths        []string      `json:"log_paths,omitempty"`
}

// Check operators retain error separately from false. In particular a failed
// collection must not choose an else branch or satisfy a "no rows" assertion.
type DeployCheck struct {
	Kind            string                   `json:"kind"`
	Children        []DeployCheck            `json:"children,omitempty"`
	Path            string                   `json:"path,omitempty"`
	Name            string                   `json:"name,omitempty"`
	Field           string                   `json:"field,omitempty"`
	Operator        string                   `json:"operator,omitempty"`
	Value           string                   `json:"value,omitempty"`
	Parameter       string                   `json:"parameter,omitempty"`
	Script          *DeployScript            `json:"script,omitempty"`
	SensorID        string                   `json:"sensor_id,omitempty"`
	Sensor          *DeploySensor            `json:"sensor,omitempty"`
	Inputs          map[string]DeployBinding `json:"inputs,omitempty"`
	Rows            []DeployPredicate        `json:"rows,omitempty"`
	Quantifier      string                   `json:"quantifier,omitempty"` // any | none | all | count
	AllowEmpty      bool                     `json:"allow_empty,omitempty"`
	LookbackSeconds int                      `json:"lookback_seconds,omitempty"`
}

type DeployPredicate struct {
	Field     string `json:"field"`
	Operator  string `json:"operator"`
	Value     string `json:"value,omitempty"`
	Parameter string `json:"parameter,omitempty"`
}

// A published custom sensor snapshot is independent of the mutable inventory
// definition. Its invocation results belong only to this deployment.
type DeploySensor struct {
	ID          string                     `json:"id"`
	Name        string                     `json:"name"`
	Fields      []SensorField              `json:"fields"`
	Parameters  []DeployParameter          `json:"parameters,omitempty"`
	Definitions map[string]CustomSensorDef `json:"definitions"`
}

type DeployRevision struct {
	Retired    bool             `json:"retired"`
	ID         string           `json:"id"`
	PackageID  string           `json:"package_id"`
	Label      string           `json:"label"`
	Definition DeployDefinition `json:"definition"`
	Published  bool             `json:"published"`
	CreatedBy  string           `json:"created_by"`
	CreatedAt  time.Time        `json:"created_at"`
	// Why and when a published version was retired ("Superseded by 2.0.0").
	RetiredNote string     `json:"retired_note,omitempty"`
	RetiredBy   string     `json:"retired_by,omitempty"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
}

type DeployLogSettings struct {
	RetentionDays int `json:"retention_days"`
	ArchiveMB     int `json:"archive_mb" api:"required"`
	RotateMB      int `json:"rotate_mb" api:"required"`
	CompressFiles int `json:"compress_files" api:"required"`
}

type DeploySettings struct {
	EndpointLogs DeployLogSettings `json:"endpoint_logs" api:"required"`
	ServerLogs   DeployLogSettings `json:"server_logs" api:"required"`
	CacheMB      int               `json:"cache_mb" api:"required"`
}

func DefaultDeploySettings() DeploySettings {
	logs := DeployLogSettings{ArchiveMB: 100, RotateMB: 10, CompressFiles: 5}
	return DeploySettings{EndpointLogs: logs, ServerLogs: logs, CacheMB: 1024}
}

// A job contains only one endpoint's configuration and a frozen dependency
// order. Persist it before acknowledging acceptance and checkpoint each step.
type DeployJob struct {
	ID          string              `json:"id"`
	RunID       string              `json:"run_id"`
	AgentID     string              `json:"agent_id"`
	PackageID   string              `json:"package_id"`
	RevisionID  string              `json:"revision_id"`
	Operation   string              `json:"operation"`
	Packages    []DeployPackagePlan `json:"packages"`
	Settings    DeploySettings      `json:"settings"`
	ExpiresAt   time.Time           `json:"expires_at,omitempty"`
	AllowReboot bool                `json:"allow_reboot"`
	ForceRemove bool                `json:"force_remove,omitempty"`
	// OverrideWindows lets the job dispatch outside the endpoint's
	// maintenance windows. Granted per deployment by an operator holding
	// the override permission; the dispatcher honours it, the agent never
	// sees it matter.
	OverrideWindows bool      `json:"override_windows,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type DeployPackagePlan struct {
	PackageID  string                    `json:"package_id"`
	RevisionID string                    `json:"revision_id"`
	Name       string                    `json:"name"`
	Operation  string                    `json:"operation"`
	Variant    DeployVariant             `json:"variant"`
	Parameters map[string]string         `json:"parameters"`
	Secrets    []string                  `json:"secrets,omitempty"`
	Files      map[string]PackageFileRef `json:"files,omitempty"`
}

type DeployEvent struct {
	ExitCode  *int      `json:"exit_code,omitempty"`
	ID        string    `json:"id"`
	JobID     string    `json:"job_id"`
	RunID     string    `json:"run_id"`
	AgentID   string    `json:"agent_id"`
	PackageID string    `json:"package_id,omitempty"`
	StepID    string    `json:"step_id,omitempty"`
	Stage     string    `json:"stage"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}
