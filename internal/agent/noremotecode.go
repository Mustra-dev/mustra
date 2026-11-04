package agent

// Inventory-and-patching mode: an endpoint that takes no code from its server.
//
// Everywhere else the trust boundary is the control plane: the agent runs what
// its server tells it to, as root, which is the point of packages and Direct
// Connect, and means a compromised server owns the fleet. This mode moves that
// boundary for the machines that want it. It is a file beside the binary,
// writable only by an administrator on the endpoint, and nothing the server can
// send changes it. A setting the server could flip would protect against nothing.
//
// It is default-deny. noRemoteCodeCommands names what is allowed, so a command
// added later is refused until someone decides otherwise. Everything else that
// can run server-supplied code is closed where it starts: the shell, custom
// sensors, the deployment worker, and updates, since whoever holds the server
// also holds the key that signs them. An endpoint in this mode updates by
// running the installer on the machine.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"unicode"

	"github.com/mustra-dev/mustra/internal/proto"
)

const noRemoteCodeFile = "no-remote-code"

// noRemoteCodeActive is the mode, for the code that has no agent to ask. It is
// the second lock on the places code actually runs, so a path the command filter
// never sees still ends here: Self Service's install, say, takes its command from
// the server's reply. It also keeps a package manager on the repositories this
// machine is configured with. A patch list's override is written into apt's
// sources, and with "[trusted=yes]" and a repository of its own a server could
// install anything as root by calling it an update.
var noRemoteCodeActive atomic.Bool

var errNoRemoteCode = errors.New(proto.NoRemoteCodeRefusal)

// noRemoteCodeCommands are the commands such an endpoint accepts. Each reports
// or changes only what the agent does itself, or applies updates the operating
// system's package manager already offers.
var noRemoteCodeCommands = map[string]bool{
	"deploy_capabilities":   true,
	"action_logs":           true,
	"macos_update_progress": true,
	"configure":             true,
	"watch":                 true,
	"set_sensor_interval":   true,
	"apply_patches":         true, // names checked by checkPatchNames
	"run_compliance":        true, // command rules read as unknown
}

// detectNoRemoteCode looks beside the running binary. Anything but a clear
// "not there" counts as there: a mode that protects an endpoint must not
// quietly turn off because a stat failed.
func detectNoRemoteCode() bool {
	exe, err := os.Executable()
	if err != nil {
		return true
	}
	_, err = os.Stat(filepath.Join(filepath.Dir(exe), noRemoteCodeFile))
	return !errors.Is(err, os.ErrNotExist)
}

// checkPatchNames refuses a package name that could be more than a name. They
// reach package managers as arguments, and "-oDPkg::Pre-Invoke::=<command>" is
// an argument apt would run. Quotes and shell characters are refused too:
// Windows Update titles reach a PowerShell script. Spaces, brackets and commas
// are in those titles, and are harmless as a single argument.
func checkPatchNames(names []string) error {
	for _, name := range names {
		if err := checkPatchName(name); err != nil {
			return err
		}
	}
	return nil
}

func checkPatchName(name string) error {
	if name == "" || strings.HasPrefix(name, "-") || len(name) > 512 {
		return fmt.Errorf("refusing package name %q", name)
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" +._:~()-,/#[]", r) {
			continue
		}
		return fmt.Errorf("refusing package name %q: it contains %q", name, r)
	}
	return nil
}

type noCheckCommandsKey struct{}

// withoutCheckCommands makes compliance leave its command rules unevaluated.
func withoutCheckCommands(ctx context.Context) context.Context {
	return context.WithValue(ctx, noCheckCommandsKey{}, true)
}

func checkCommandsDisabled(ctx context.Context) bool {
	off, _ := ctx.Value(noCheckCommandsKey{}).(bool)
	return off
}
