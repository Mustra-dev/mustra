package agent

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// The password on the endpoint's own uninstaller.
//
// What this is for, stated honestly: it stops the person using the machine
// from removing the agent because it is inconvenient. It is not a defence
// against an administrator of that machine, and nothing offline could be --
// whoever can run the uninstaller as root can also stop the service and
// delete the directory. Every endpoint tool's uninstall password is exactly
// this, and describing it as anything stronger would be a lie that someone
// eventually plans around.
//
// The comparison happens here rather than in the uninstall script because
// the hash is bcrypt, and neither PowerShell nor a POSIX shell can check
// one without help. The agent binary is already on the machine.

// UninstallHashPath is where the installer writes the hash the server
// issued. Root-readable only -- not because the hash is a secret worth
// much, but because a file anyone can rewrite is not a check.
const UninstallHashPath = "uninstall.hash"

// VerifyUninstallPassword reads a password from in and reports whether it
// matches the stored hash. A missing or empty hash file means no password
// was configured, which is not an error: it is the default, and the
// uninstaller proceeds.
func VerifyUninstallPassword(hashPath string, in io.Reader) error {
	raw, err := os.ReadFile(hashPath)
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	hash := strings.TrimSpace(string(raw))

	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("no password supplied")
	}
	// Only the trailing newline is stripped. A password may legitimately
	// begin or end with a space, and quietly trimming one would make a
	// correct password fail with no way to tell why.
	password := strings.TrimRight(line, "\r\n")

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return fmt.Errorf("that password is not correct")
	}
	return nil
}
