package servercmd

// The server image (alpine) carries no zoneinfo, and maintenance windows are
// read in IANA zones: without the embedded database every zone but UTC
// failed to load, and such a window never opened.
import _ "time/tzdata"
