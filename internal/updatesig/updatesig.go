// Package updatesig signs and verifies agent update manifests.
//
// The agent binary is the most privileged file on every endpoint, and it
// used to be replaced by running whatever install script the server's
// stored console URL pointed at — a URL that anyone could set with a Host
// header. Now an update is a binary plus a manifest signed with an ed25519
// key whose public half the agent pinned when it enrolled. The agent
// verifies the manifest, then the binary against the manifest's digest,
// and refuses anything older than what it runs unless the manifest itself
// says, under the same signature, that this agent may go back to it.
//
// What is signed is a fixed text rendering of every field, not the JSON,
// so a verifier never depends on how a JSON encoder orders or escapes
// things.
package updatesig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Manifest describes one agent build. It is what `<binary>.sig` contains.
type Manifest struct {
	V       int    `json:"v"`
	File    string `json:"file"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	// AllowDowngrade, AgentID and Expires form the operator's explicit
	// "move this one endpoint back" authorization. A downgrade manifest
	// names the agent it is for and expires, so one observed on the wire
	// cannot be replayed to roll back the rest of the fleet, or this agent
	// again next month.
	AllowDowngrade bool   `json:"allow_downgrade,omitempty"`
	AgentID        string `json:"agent_id,omitempty"`
	Expires        int64  `json:"expires,omitempty"` // unix seconds; 0 = never
	// KeyID is the first 16 hex characters of SHA-256(public key), so an
	// operator can tell which key signed something without the key itself.
	KeyID string `json:"key_id,omitempty"`
	Sig   string `json:"sig"`
}

const manifestVersion = 1

// signedBytes is the exact message that is signed.
func (m Manifest) signedBytes() []byte {
	downgrade := "0"
	if m.AllowDowngrade {
		downgrade = "1"
	}
	return []byte(strings.Join([]string{
		"mustra-agent-update-v1",
		m.File, m.OS, m.Arch, m.Version, strings.ToLower(m.SHA256),
		strconv.FormatInt(m.Size, 10), downgrade, m.AgentID,
		strconv.FormatInt(m.Expires, 10),
	}, "\n"))
}

// KeyID derives the short identifier of a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// EncodePublicKey and ParsePublicKey move a public key through text
// (environment variables, files, JSON) as standard base64.
func EncodePublicKey(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("update signing key is not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("update signing key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey accepts a base64 32-byte seed (what init.sh generates)
// or a base64 64-byte private key.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("update signing key is not base64: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("update signing key is %d bytes, want a %d-byte seed", len(raw), ed25519.SeedSize)
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Sign fills in V, KeyID and Sig.
func Sign(m Manifest, key ed25519.PrivateKey) (Manifest, error) {
	m.V = manifestVersion
	m.SHA256 = strings.ToLower(m.SHA256)
	if !sha256Hex.MatchString(m.SHA256) {
		return Manifest{}, errors.New("manifest digest is not a sha256 hex string")
	}
	if m.File == "" || m.OS == "" || m.Arch == "" || m.Version == "" || m.Size <= 0 {
		return Manifest{}, errors.New("manifest is missing a field")
	}
	if m.AllowDowngrade && (m.AgentID == "" || m.Expires == 0) {
		return Manifest{}, errors.New("a downgrade manifest must name an agent and expire")
	}
	m.KeyID = KeyID(key.Public().(ed25519.PublicKey))
	m.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, m.signedBytes()))
	return m, nil
}

// Verify checks the signature only.
func (m Manifest) Verify(pub ed25519.PublicKey) error {
	if m.V != manifestVersion {
		return fmt.Errorf("unsupported manifest version %d", m.V)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("manifest signature is malformed")
	}
	if !ed25519.Verify(pub, m.signedBytes(), sig) {
		return errors.New("manifest signature does not verify against the pinned update key")
	}
	return nil
}

// Expectation is what the endpoint applying an update knows independently
// of the manifest.
type Expectation struct {
	OS, Arch       string
	AgentID        string
	CurrentVersion string
	Now            time.Time
}

// Check verifies the signature and that the manifest is acceptable for
// this endpoint: right platform, not expired, and not a downgrade unless
// a signed downgrade authorization names this agent.
func (m Manifest) Check(pub ed25519.PublicKey, want Expectation) error {
	if err := m.Verify(pub); err != nil {
		return err
	}
	if !sha256Hex.MatchString(m.SHA256) || m.Size <= 0 {
		return errors.New("manifest has no usable digest")
	}
	if m.OS != want.OS || m.Arch != want.Arch {
		return fmt.Errorf("manifest is for %s/%s, this endpoint is %s/%s", m.OS, m.Arch, want.OS, want.Arch)
	}
	if m.Expires != 0 && want.Now.Unix() > m.Expires {
		return errors.New("manifest has expired")
	}
	if m.AgentID != "" && m.AgentID != want.AgentID {
		return errors.New("manifest is for a different endpoint")
	}
	if _, ok := ParseVersion(m.Version); !ok {
		return fmt.Errorf("manifest version %q is not a release version", m.Version)
	}
	if _, ok := ParseVersion(want.CurrentVersion); !ok {
		// An unstamped development build has no position to defend.
		return nil
	}
	if Newer(m.Version, want.CurrentVersion) {
		return nil
	}
	if m.AllowDowngrade && m.AgentID == want.AgentID && m.Expires != 0 {
		return nil
	}
	if m.Version == want.CurrentVersion {
		return fmt.Errorf("already on %s", m.Version)
	}
	return fmt.Errorf("refusing to move from %s back to %s without a signed downgrade authorization", want.CurrentVersion, m.Version)
}

// Marshal and Unmarshal are the .sig file format.
func (m Manifest) Marshal() ([]byte, error) { return json.MarshalIndent(m, "", "  ") }

func Unmarshal(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	return m, nil
}

var versionRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(.*)$`)

type parsedVersion struct {
	nums [3]int
	pre  string
}

// ParseVersion parses "MAJOR.MINOR.PATCH[suffix]".
func ParseVersion(v string) (parsedVersion, bool) {
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return parsedVersion{}, false
	}
	var p parsedVersion
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return parsedVersion{}, false
		}
		p.nums[i] = n
	}
	p.pre = m[4]
	return p, true
}

// Newer reports whether a is strictly newer than b, with the server's rule
// (internal/server/versioncmp.go): false whenever it cannot tell, a release
// is newer than its own pre-releases, and two pre-releases of the same
// version are not ranked.
func Newer(a, b string) bool {
	x, okA := ParseVersion(a)
	y, okB := ParseVersion(b)
	if !okA || !okB {
		return false
	}
	for i := 0; i < 3; i++ {
		if x.nums[i] != y.nums[i] {
			return x.nums[i] > y.nums[i]
		}
	}
	// Same numbers. A build from source between releases is named by git
	// describe, "0.105.1-24-gc9cd30b": 24 commits after the 0.105.1 tag. That
	// is after the release, not before it, and two of them from the same tag
	// are ordered by their commit count.
	cA, descA := describeCount(x.pre)
	cB, descB := describeCount(y.pre)
	switch {
	case descA && descB:
		return cA > cB
	case descA:
		return y.pre == ""
	case descB:
		return false
	}
	// A release is newer than its own pre-releases -- an endpoint left on
	// 0.41.8-rc is not on 0.41.8 and should be offered the real thing. Two
	// different pre-releases of the same version are not ranked: which of
	// -rc and -rc2 came first is a guess, and the rule here is to answer no
	// rather than risk moving an endpoint backwards.
	return x.pre == "" && y.pre != ""
}

var describeRe = regexp.MustCompile(`^-(\d+)-g[0-9a-f]{4,40}(-dirty)?$`)

// describeCount reads the commit count out of the suffix git describe puts
// after a tag ("-24-gc9cd30b"), and reports whether it is one.
func describeCount(pre string) (int, bool) {
	m := describeRe.FindStringSubmatch(pre)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}
