// Command server is the mustra control plane: it consumes agent
// registration/heartbeat/facts off NATS, persists inventory to Postgres,
// dispatches live queries, and serves the HTTP+SSE API the console uses.
//
// Flags, environment variables and startup checks live in
// internal/servercmd, shared with cmd/console so the two cannot drift.
package main

import "github.com/mustra-dev/mustra/internal/servercmd"

func main() { servercmd.Main("server") }
