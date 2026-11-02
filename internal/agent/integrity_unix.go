//go:build !windows

package agent

import (
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/mustra-dev/mustra/internal/proto"
)

// fileOwner resolves uid/gid to names. Ownership changing on /etc/sudoers
// is at least as interesting as its contents changing, so it belongs in
// the baseline rather than being left to the hash alone.
func fileOwner(info os.FileInfo) (owner, group string) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ""
	}
	owner = strconv.FormatUint(uint64(st.Uid), 10)
	group = strconv.FormatUint(uint64(st.Gid), 10)
	if u, err := user.LookupId(owner); err == nil {
		owner = u.Username
	}
	if g, err := user.LookupGroupId(group); err == nil {
		group = g.Name
	}
	return owner, group
}

// collectRegistryIntegrity is Windows-only; a watchlist's registry keys
// are ignored elsewhere.
func collectRegistryIntegrity(_ []string) []proto.IntegrityFile { return nil }
