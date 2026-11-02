package proto

// SensorField is shared by every platform of a custom sensor. Paths live in
// the platform parser because different collectors can return different shapes.
type SensorField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type SensorOutput struct {
	Format    string            `json:"format,omitempty"`
	RowPath   string            `json:"row_path,omitempty"`
	Paths     map[string]string `json:"paths,omitempty"`
	Delimiter string            `json:"delimiter,omitempty"`
	Headers   bool              `json:"headers,omitempty"`
}

type SensorPlatform struct {
	Language  string       `json:"language,omitempty"`
	Namespace string       `json:"namespace,omitempty"`
	Output    SensorOutput `json:"output"`
}

// SensorArtifact is delivered over the authenticated command/definition channel.
type SensorArtifact struct {
	OS   string         `json:"os"`
	Arch string         `json:"arch"`
	File PackageFileRef `json:"file"`
}

const MaxSensorArtifactBytes = 16 << 20
