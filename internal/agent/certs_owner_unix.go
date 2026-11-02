//go:build !windows

package agent

import (
	"io/fs"
	"os"
	"syscall"
)

func chownLike(path string, st fs.FileInfo) {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(sys.Uid), int(sys.Gid))
	}
}
