//go:build !windows

package agent

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v4/host"
)

func deployUser(wanted string) (string, error) {
	sessions, e := host.Users()
	if e != nil {
		return "", e
	}
	names := map[string]bool{}
	for _, s := range sessions {
		if s.User != "root" && (wanted == "" || s.User == wanted) {
			names[s.User] = true
		}
	}
	if len(names) != 1 {
		return "", fmt.Errorf("expected one matching logged-in user, found %d", len(names))
	}
	for name := range names {
		return name, nil
	}
	return "", fmt.Errorf("no logged-in user")
}

// parseDeployID refuses an ID that would not survive the conversions it goes
// through: one that wraps to 0 would run the command as root. The bound is
// what fits an int on every platform, so the result is the same on any build.
func parseDeployID(s string) (int, error) {
	n, e := strconv.ParseUint(s, 10, 32)
	if e != nil {
		return 0, e
	}
	if n > math.MaxInt32 {
		return 0, fmt.Errorf("user or group ID %s is out of range", s)
	}
	return int(n), nil
}

func configureDeployUser(ctx context.Context, cmd *exec.Cmd, wanted, dir string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	name, e := deployUser(wanted)
	if e != nil {
		return e
	}
	u, e := user.Lookup(name)
	if e != nil {
		return e
	}
	uid, e := parseDeployID(u.Uid)
	if e != nil {
		return e
	}
	gid, e := parseDeployID(u.Gid)
	if e != nil {
		return e
	}
	if os.Geteuid() != 0 && os.Geteuid() != uid {
		return fmt.Errorf("agent cannot switch to user %s", name)
	}
	if e = handDirToUser(dir, name, uid, gid); e != nil {
		return e
	}
	parent := filepath.Dir(dir)
	// A custom verification sensor has its own top-level temporary directory;
	// never chmod the system temporary directory when switching its identity.
	if strings.HasPrefix(filepath.Base(parent), "mustra-deploy-") {
		if e = os.Chmod(parent, 0711); e != nil {
			return e
		}
	}
	groups, e := u.GroupIds()
	if e != nil {
		return e
	}
	var groupIDs []uint32
	for _, g := range groups {
		n, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return err
		}
		groupIDs = append(groupIDs, uint32(n))
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groupIDs}
	cmd.Env = append(cmd.Env, "HOME="+u.HomeDir, "USER="+name, "LOGNAME="+name)
	return nil
}
func deployRegistryValue(path, name string) (string, error) {
	return "", fmt.Errorf("registry checks require Windows")
}
func deployFileVersion(ctx context.Context, path string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("file version metadata unavailable; use a sensor or package version check")
	}
	out, e := exec.CommandContext(ctx, "/usr/bin/defaults", "read", path, "CFBundleShortVersionString").Output()
	return strings.TrimSpace(string(out)), e
}
func deployReboot(ctx context.Context) error {
	return exec.CommandContext(ctx, "/sbin/shutdown", "-r", "+1").Run()
}

func cleanupDeployUser(cmd *exec.Cmd) {}

// handDirToUser gives the deployment's private workspace to the selected
// user. This runs again before every step and retry, by which time the user
// may have written into the directory, so nothing in it is followed: a link
// would hand the user ownership of whatever it points at. Lchown changes the
// entry itself, and anything that is not a plain file or directory is
// refused rather than passed over.
func handDirToUser(dir, name string, uid, gid int) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return fmt.Errorf("refusing to hand %s to %s: not a regular file or directory", path, name)
		}
		return os.Lchown(path, uid, gid)
	})
}
