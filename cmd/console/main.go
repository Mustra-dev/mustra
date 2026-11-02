// Command console is the web console entrypoint.
//
// The console backend is the same process as the control-plane API
// (internal/server serves both the HTTP/SSE console API and the static UI),
// so this binary runs exactly what cmd/server runs, with the same flags,
// environment and startup checks — it used to carry its own copy, which had
// lost the placeholder-secret check and the NATS credentials. It exists as
// its own command so the split called for in the project brief is a matter
// of diverging later, deliberately. See docs/ROADMAP.md.
package main

import "github.com/mustra-dev/mustra/internal/servercmd"

func main() { servercmd.Main("console") }
