// Package idgen is the one place that generates mustra's prefixed random
// IDs ("agt-...", "q-...", "usr-scim-...", "grp-..."), so internal/server
// and internal/server/scim (which mount into the same server but can't
// import each other) both have somewhere to get one without an import
// cycle.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// New returns a random, URL-safe identifier with the given prefix. 16
// random bytes makes collision practically impossible at any fleet size
// this project targets.
func New(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the system RNG is broken; there is no
		// sane fallback, so surface it loudly rather than mint a weak ID.
		panic(fmt.Sprintf("crypto/rand read failed: %v", err))
	}
	return prefix + hex.EncodeToString(b)
}
