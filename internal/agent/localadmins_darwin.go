//go:build darwin

package agent

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// On macOS the admin group is the whole story: its members can sudo and
// can change any system setting. dscl is the supported way to read it,
// and it answers for both local accounts and directory-bound ones. root is
// added explicitly because it is an administrator whether or not anyone
// listed it.
func collectLocalAdmins(ctx context.Context) ([]proto.LocalAdmin, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rows := []proto.LocalAdmin{{Name: "root", Kind: "user", Source: "local", Via: "uid 0"}}
	out, err := exec.CommandContext(cctx, "dscl", ".", "-read", "/Groups/admin", "GroupMembership").Output()
	if err != nil {
		// No admin group readable is unusual enough to report rather than
		// answer "just root" as if that were measured.
		return nil, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "GroupMembership:") {
			continue
		}
		for _, name := range strings.Fields(strings.TrimPrefix(line, "GroupMembership:")) {
			if name == "root" {
				continue
			}
			rows = append(rows, proto.LocalAdmin{Name: name, Kind: "user", Source: "local", Via: "admin group"})
		}
	}
	// Nested groups in admin (directory-bound Macs sometimes have one).
	if out, err := exec.CommandContext(cctx, "dscl", ".", "-read", "/Groups/admin", "NestedGroups").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "NestedGroups:") {
				for _, g := range strings.Fields(strings.TrimPrefix(line, "NestedGroups:")) {
					rows = append(rows, proto.LocalAdmin{Name: g, Kind: "group", Source: "unknown", Via: "admin group (nested)"})
				}
			}
		}
	}
	return rows, nil
}
