package main

// Embedded so the agent can confirm the zone name it reports even on a host
// without a zoneinfo package (minimal containers, some appliances).
import _ "time/tzdata"
