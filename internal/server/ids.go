package server

import "github.com/mustra-dev/mustra/internal/idgen"

// newID returns a random, URL-safe identifier with the given prefix (e.g.
// "agt-" or "q-"). See internal/idgen for why this lives in a separate leaf
// package rather than here directly.
func newID(prefix string) string { return idgen.New(prefix) }
