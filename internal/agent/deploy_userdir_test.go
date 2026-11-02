//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A user-identity step leaves the package directory owned by the user, so
// by the next step it may hold links the user planted. The root agent must
// neither hand over nor write through them.

func TestHandDirToUserRefusesLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership needs root")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "protected")
	if err := os.WriteFile(outside, []byte("root only"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload"), []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "planted")); err != nil {
		t.Fatal(err)
	}
	if err := handDirToUser(dir, "nobody", 65534, 65534); err == nil {
		t.Fatal("a link in the workspace was accepted")
	}
	var st syscall.Stat_t
	if err := syscall.Stat(outside, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 0 {
		t.Fatalf("the link's target changed owner to %d", st.Uid)
	}
}

func TestHandDirToUserGivesPlainEntries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership needs root")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "f"), []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := handDirToUser(dir, "nobody", 65534, 65534); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(dir, "sub", "f"), &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 65534 {
		t.Fatalf("plain file owner = %d, want 65534", st.Uid)
	}
}

func TestWriteFreshDoesNotFollowLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "protected")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, ".mustra-two.sh")
	if err := os.Symlink(target, script); err != nil {
		t.Fatal(err)
	}
	if err := writeFresh(script, []byte("step two"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != "original" {
		t.Fatalf("write went through the link: target now %q", got)
	}
	fi, err := os.Lstat(script)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("script is %v, want a regular file", fi.Mode())
	}
	if got, _ := os.ReadFile(script); string(got) != "step two" {
		t.Fatalf("script = %q", got)
	}
}
