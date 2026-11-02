//go:build linux

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Creates and removes a real account. Opt-in and root-only, for a
// disposable machine or container:
//
//	MUSTRA_LIVE_JIT=1 go test ./internal/agent/ -run LiveJIT -v
func TestLiveJITLinux(t *testing.T) {
	if os.Getenv("MUSTRA_LIVE_JIT") == "" || os.Geteuid() != 0 {
		t.Skip("set MUSTRA_LIVE_JIT=1 and run as root on a disposable machine")
	}
	ctx := context.Background()
	name := "mustra-livetest"
	job := proto.JITAccountJob{Username: name, AuthorizedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOm3 test", ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := jitCreateAccountOS(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, err := jitCreateAccountOS(ctx, job); err == nil || !strings.Contains(err.Error(), errJITExists.Error()) {
		t.Fatalf("second create: %v, want errJITExists", err)
	}
	home, _, _, err := jitPasswdEntry(name)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("authorized_keys: %v %v", fi, err)
	}
	if out, err := exec.Command("sudo", "-l", "-U", name).CombinedOutput(); err != nil || !strings.Contains(string(out), "NOPASSWD: ALL") {
		t.Fatalf("sudo rights: %s %v", out, err)
	}
	if out, _ := exec.Command("chage", "-l", name).Output(); !strings.Contains(string(out), time.Now().UTC().AddDate(0, 0, 1).Format("2006")) {
		t.Fatalf("no expiry date set: %s", out)
	}
	// A running process must not stop the removal.
	sleeper := exec.Command("su", "-s", "/bin/sh", name, "-c", "sleep 300")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := jitDeleteAccountOS(ctx, name); err != nil {
		t.Fatal(err)
	}
	_ = sleeper.Wait()
	if out, _ := exec.Command("getent", "passwd", name).Output(); len(out) > 0 {
		t.Fatal("account still exists")
	}
	if _, err := os.Stat(jitSudoersPath(name)); !os.IsNotExist(err) {
		t.Fatal("sudoers entry still exists")
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatal("home directory still exists")
	}
	// Removing what is already gone is success.
	if _, err := jitDeleteAccountOS(ctx, name); err != nil {
		t.Fatalf("second removal: %v", err)
	}
}
