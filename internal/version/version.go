// Package version carries the build's identity. The values are stamped in
// at link time (see deploy/Dockerfile.server's -ldflags); a build made
// without them — `go build ./cmd/server` on a laptop — reports "dev", which
// is the honest answer rather than a fake version number.
package version

import (
	"runtime"
	"strings"
)

var (
	// Version is the release name, when built from one.
	Version = "dev"
	// Commit is the git revision the binary was built from.
	Commit = ""
	// BuildTime is when it was built, RFC 3339.
	BuildTime = ""
	// AgentVersion is the version stamped into the agent binaries this
	// server serves, which is deliberately not the server's own.
	//
	// They used to be the same value, so every control-plane fix restamped
	// forty identically-behaving agents with a higher number and told every
	// endpoint it was behind. An endpoint is out of date when the *agent*
	// changed, not when the console did.
	AgentVersion = ""
)

// Agent is the version of the agent this server hands out. Falls back to
// the server's own version, which is what a build with no separate agent
// stamp — and every build before this existed — reports.
func Agent() string {
	if AgentVersion != "" {
		return AgentVersion
	}
	return Version
}

// Info is the whole build identity, for /api/about.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	ShortSHA  string `json:"short_sha,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func Current() Info {
	short := Commit
	if len(short) > 12 {
		short = short[:12]
	}
	return Info{
		Version:   Version,
		Commit:    Commit,
		ShortSHA:  short,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String is what the server logs at startup.
func (i Info) String() string {
	parts := []string{i.Version}
	if i.ShortSHA != "" {
		parts = append(parts, i.ShortSHA)
	}
	if i.BuildTime != "" {
		parts = append(parts, i.BuildTime)
	}
	return strings.Join(parts, " ")
}
