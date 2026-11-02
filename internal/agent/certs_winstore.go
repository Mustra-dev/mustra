package agent

import (
	"regexp"
	"strings"
)

// The Windows certificate store as an install target. A certificate whose
// path is the machine's personal store is made the Windows way: certreq
// creates the key in the machine key store (never exportable, never on
// disk as a file), and certreq -accept pairs the signed certificate with
// it. It can then be bound to an IIS site or to Remote Desktop.

// winStorePath is the one store path Cert Manager installs into.
const winStorePath = `Cert:\LocalMachine\My`

func isWinStore(path string) bool {
	return strings.EqualFold(strings.TrimRight(path, `\`), winStorePath)
}

// Names go into a certreq INF and site names into PowerShell (through the
// environment, never the script text); both are held to plain characters.
var (
	winCertNameRe = regexp.MustCompile(`^[A-Za-z0-9*][A-Za-z0-9.*:-]{0,252}$`)
	iisSiteRe     = regexp.MustCompile(`^[A-Za-z0-9 ._()-]{1,128}$`)
)
