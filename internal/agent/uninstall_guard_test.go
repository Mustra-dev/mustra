package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func uninstallHashFile(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "uninstall.hash")
	if err := os.WriteFile(path, append(h, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCorrectPasswordPasses(t *testing.T) {
	if err := VerifyUninstallPassword(uninstallHashFile(t, "let me out"), strings.NewReader("let me out\n")); err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
}

func TestWrongPasswordFails(t *testing.T) {
	if err := VerifyUninstallPassword(uninstallHashFile(t, "let me out"), strings.NewReader("guess\n")); err == nil {
		t.Fatal("a wrong password was accepted")
	}
}

// No configured password is the default, and it must not turn the
// uninstaller into something that cannot run.
func TestNoHashFileMeansNoPassword(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.hash")
	if err := VerifyUninstallPassword(missing, strings.NewReader("")); err != nil {
		t.Fatalf("a missing hash file should not block uninstall: %v", err)
	}
}

func TestEmptyHashFileMeansNoPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.hash")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyUninstallPassword(path, strings.NewReader("")); err != nil {
		t.Fatalf("an empty hash file should not block uninstall: %v", err)
	}
}

// A password may legitimately start or end with a space. Trimming one
// would make a correct password fail with nothing on screen to explain it.
func TestSurroundingSpacesAreKept(t *testing.T) {
	if err := VerifyUninstallPassword(uninstallHashFile(t, "  spaced  "), strings.NewReader("  spaced  \n")); err != nil {
		t.Fatalf("a password with spaces was rejected: %v", err)
	}
	if err := VerifyUninstallPassword(uninstallHashFile(t, "  spaced  "), strings.NewReader("spaced\n")); err == nil {
		t.Fatal("the trimmed form was accepted")
	}
}

// Windows line endings arrive when the password is typed into PowerShell.
func TestCarriageReturnIsNotPartOfThePassword(t *testing.T) {
	if err := VerifyUninstallPassword(uninstallHashFile(t, "secret"), strings.NewReader("secret\r\n")); err != nil {
		t.Fatalf("CRLF input rejected: %v", err)
	}
}

func TestEmptyInputAgainstASetPasswordFails(t *testing.T) {
	if err := VerifyUninstallPassword(uninstallHashFile(t, "secret"), strings.NewReader("")); err == nil {
		t.Fatal("an empty password was accepted against a configured one")
	}
}

// A corrupt or truncated hash must fail closed. Treating an unreadable
// hash as "no password" would make the check removable by damaging a file.
func TestGarbageHashFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.hash")
	if err := os.WriteFile(path, []byte("not-a-bcrypt-hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyUninstallPassword(path, strings.NewReader("anything")); err == nil {
		t.Fatal("a corrupt hash was treated as no password")
	}
}
