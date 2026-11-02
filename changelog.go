// Package mustra exists to embed repository-level documents into the
// binaries that serve them. go:embed can't reach outside its own package
// directory, and CHANGELOG.md belongs at the repository root where people
// expect to find it — so the embed lives here rather than the file moving.
package mustra

import "embed"

// Changelog is CHANGELOG.md, rendered by the console's About page. Shipping
// it inside the binary means the page always describes the build that's
// actually running.
//
//go:embed CHANGELOG.md
var Changelog string

// Guides are the step-by-step guides in docs/guides, served by the
// console's Help page and readable in the repository as they are.
//
//go:embed docs/guides/*.md
var Guides embed.FS
