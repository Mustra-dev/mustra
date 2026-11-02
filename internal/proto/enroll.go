package proto

import "github.com/mustra-dev/mustra/internal/updatesig"

// EnrollRequest asks the control plane for an agent identity of its own.
//
// It travels on one of two subjects, and the subject is what says how the
// sender authenticated (internal/nats.EnrollToken / EnrollLegacy): with an
// enrollment token an administrator created, or with the legacy shared
// agent password while the operator still allows it. The broker grants
// each enrolment connection publish on exactly one of them.
type EnrollRequest struct {
	// Token is the enrollment token, repeated here because the server
	// consumes a use of it when it answers, and it cannot read the
	// password the connection authenticated with.
	Token string `json:"token,omitempty"`
	// PriorAgentID is the identity this endpoint already has, if any. The
	// server keeps it — so the endpoint keeps its history — only when that
	// identity has no credential yet. An enrolled identity is never handed
	// to a second credential.
	PriorAgentID string    `json:"prior_agent_id,omitempty"`
	Info         AgentInfo `json:"info"`
}

// EnrollResponse carries the new credential. The secret is shown once and
// stored only as a hash on the server.
type EnrollResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	Secret  string `json:"secret,omitempty"`
	// UpdateSigningKey is the base64 ed25519 public key agent updates are
	// signed with, for the agent to pin when the install did not already
	// give it one.
	UpdateSigningKey string `json:"update_signing_key,omitempty"`
}

// UpdateOffer is a verified-update instruction: a binary to fetch and the
// signed manifest it must match. The URL is not trusted — the manifest is,
// under the key the agent pinned at enrollment — so an offer that came
// from anywhere other than this deployment's signing key is refused no
// matter how it arrived.
type UpdateOffer struct {
	BinaryURL string             `json:"binary_url"`
	Manifest  updatesig.Manifest `json:"manifest"`
}
