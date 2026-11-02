//go:build loadsim

// Command loadsim load-tests a mustra control plane: it runs the real
// server with profiling, captures a real agent's traffic as templates, and
// simulates a fleet of enrolled agents through the production broker path
// (TLS, auth callout, per-agent credentials). See README.md.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "server":
		runServer(args)
	case "capture":
		runCapture(args)
	case "enroll":
		runEnroll(args)
	case "fleet":
		runFleet(args)
	case "api":
		runAPI(args)
	case "monitor":
		runMonitor(args)
	case "msum":
		runMonSummary(args)
	case "jwtsize":
		runJWTSize(args)
	case "legacy":
		runLegacy(args)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: loadsim <command> [flags]
  server    run the control plane (servercmd) with pprof on LOADSIM_PPROF_ADDR
  capture   record a real agent's payloads as simulator templates
  enroll    enroll N simulated identities with an enrollment token
  fleet     run the enrolled identities as live agents and measure
  api       measure console API latency
  monitor   sample server/Postgres/NATS CPU+RSS and JetStream consumer lag to CSV
  msum      summarize a monitor CSV over a time range
  jwtsize   compute legacy JWT size against the number of enrolled agents
  legacy    connect with the legacy shared credential and report the outcome`)
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "loadsim:", err)
	os.Exit(1)
}
