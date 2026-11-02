// Package scim implements enough of SCIM 2.0 (RFC 7643/7644) for an IdP —
// Authentik's outbound SCIM provider is the one this was built and wired
// against, but nothing here is Authentik-specific — to provision console
// users and groups. It's a pragmatic subset, not full RFC compliance: see
// docs/ROADMAP.md for what's deliberately left out (the full SCIM filter
// grammar and PATCH path-expression grammar, in particular — only the
// shapes real IdP provisioning clients actually send are handled).
package scim

import "time"

const (
	schemaUser          = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup         = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaListResponse  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError         = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaPatchOp       = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaServiceConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

type meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
}

type email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type name struct {
	Formatted string `json:"formatted,omitempty"`
}

// userResource is the SCIM User representation.
type userResource struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	Name        *name    `json:"name,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Emails      []email  `json:"emails,omitempty"`
	Active      bool     `json:"active"`
	Meta        meta     `json:"meta"`
}

type groupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

// groupResource is the SCIM Group representation.
type groupResource struct {
	Schemas     []string      `json:"schemas"`
	ID          string        `json:"id"`
	ExternalID  string        `json:"externalId,omitempty"`
	DisplayName string        `json:"displayName"`
	Members     []groupMember `json:"members,omitempty"`
	Meta        meta          `json:"meta"`
}

type listResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

type scimError struct {
	Schemas []string `json:"schemas"`
	Status  string   `json:"status"`
	Detail  string   `json:"detail,omitempty"`
}

// patchOp is a SCIM PATCH request body (RFC 7644 §3.5.2), and patchOperation
// one entry in it.
type patchOp struct {
	Schemas    []string         `json:"schemas"`
	Operations []patchOperation `json:"Operations"`
}

type patchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}
