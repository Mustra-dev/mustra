//go:build linux

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Linux: a local user with a home directory, sudo without a password (the
// person signing in never learns one) through its own sudoers.d file, and
// for SSH an authorized key. useradd's expiry date is a second deadline
// beside the agent's own, at day granularity: the day after the deadline,
// so it never locks the account early.
//
// The password goes to chpasswd on stdin, never on a command line, where
// any user's ps (and auditd's execve records) would show it.

const jitSudoersDir = "/etc/sudoers.d"

func jitSudoersPath(name string) string { return filepath.Join(jitSudoersDir, "mustra-jit-"+name) }

func jitCreateAccountOS(ctx context.Context, job proto.JITAccountJob) (string, error) {
	if _, err := exec.LookPath("useradd"); err != nil {
		return "", errors.New("useradd is not installed")
	}
	if out, _ := exec.CommandContext(ctx, "getent", "passwd", job.Username).Output(); len(out) > 0 {
		return "", fmt.Errorf("%s: %w", job.Username, errJITExists)
	}
	expire := job.ExpiresAt.UTC().AddDate(0, 0, 1).Format("2006-01-02")
	if out, err := exec.CommandContext(ctx, "useradd", "--create-home", "--shell", "/bin/bash",
		"--expiredate", expire, "--comment", "Mustra temporary session account", job.Username).CombinedOutput(); err != nil {
		return string(out), fmt.Errorf("useradd: %w", err)
	}
	var notes []string
	if job.Password != "" {
		cmd := exec.CommandContext(ctx, "chpasswd")
		cmd.Stdin = strings.NewReader(job.Username + ":" + job.Password + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			return string(out), fmt.Errorf("chpasswd: %w", err)
		}
	} else if out, err := exec.CommandContext(ctx, "usermod", "--password", "*", job.Username).CombinedOutput(); err != nil {
		// "*" rather than useradd's "!": no password can match it, but the
		// account is not "locked", which sshd without PAM refuses even
		// for key sign-in.
		return string(out), fmt.Errorf("usermod: %w", err)
	}
	if job.AuthorizedKey != "" {
		if err := jitWriteAuthorizedKey(job.Username, job.AuthorizedKey); err != nil {
			return "", err
		}
		notes = append(notes, jitSSHDNotes(ctx, job.Username)...)
	}
	if err := jitWriteSudoers(ctx, job.Username); err != nil {
		return "", err
	}
	return strings.Join(notes, "\n"), nil
}

func jitWriteAuthorizedKey(name, key string) error {
	home, uid, gid, err := jitPasswdEntry(name)
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	// O_EXCL and Lchown: the home directory was made a moment ago by
	// useradd, but nothing here follows a link planted in it.
	file := filepath.Join(dir, "authorized_keys")
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", file, err)
	}
	_, werr := f.WriteString(strings.TrimSpace(key) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("writing %s: %w", file, werr)
	}
	for _, p := range []string{dir, file} {
		if err := os.Lchown(p, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", p, err)
		}
	}
	return nil
}

func jitPasswdEntry(name string) (home string, uid, gid int, err error) {
	out, err := exec.Command("getent", "passwd", name).Output()
	if err != nil {
		return "", 0, 0, fmt.Errorf("looking up %s: %w", name, err)
	}
	f := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(f) < 6 {
		return "", 0, 0, fmt.Errorf("unexpected passwd entry for %s", name)
	}
	uid, err1 := strconv.Atoi(f[2])
	gid, err2 := strconv.Atoi(f[3])
	if err1 != nil || err2 != nil || f[5] == "" {
		return "", 0, 0, fmt.Errorf("unexpected passwd entry for %s", name)
	}
	return f[5], uid, gid, nil
}

func jitWriteSudoers(ctx context.Context, name string) error {
	if _, err := os.Stat(jitSudoersDir); err != nil {
		return errors.New("sudo is not installed (no /etc/sudoers.d); the account would have no administrator rights")
	}
	path := jitSudoersPath(name)
	tmp := path + ".tmp" // sudo skips names containing a dot
	content := name + " ALL=(ALL:ALL) NOPASSWD: ALL\n"
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if visudo, err := exec.LookPath("visudo"); err == nil {
		if out, err := exec.CommandContext(ctx, visudo, "-cf", tmp).CombinedOutput(); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("visudo rejected the sudoers entry: %s", bytes.TrimSpace(out))
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("installing %s: %w", path, err)
	}
	return nil
}

// jitSSHDNotes reports sshd settings that would turn the key away, so the
// failure has a reason beside it instead of only "authentication failed".
func jitSSHDNotes(ctx context.Context, name string) []string {
	out, err := exec.CommandContext(ctx, "sshd", "-T").Output()
	if err != nil {
		return nil
	}
	var notes []string
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "allowusers", "allowgroups":
			notes = append(notes, fmt.Sprintf("sshd limits sign-in with %s %s; %s may be refused", k, v, name))
		case "pubkeyauthentication":
			if v == "no" {
				notes = append(notes, "sshd has pubkeyauthentication no; the key will be refused")
			}
		}
	}
	return notes
}

func jitDeleteAccountOS(ctx context.Context, name string) (string, error) {
	var notes []string
	// Sessions first: userdel refuses a user with running processes, and
	// an open shell must not outlive the account.
	if _, err := exec.LookPath("loginctl"); err == nil {
		_ = exec.CommandContext(ctx, "loginctl", "terminate-user", name).Run()
	}
	_ = exec.CommandContext(ctx, "pkill", "-KILL", "-u", name).Run()
	if err := os.Remove(jitSudoersPath(name)); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("removing the sudoers entry: %w", err)
	}
	out, err := exec.CommandContext(ctx, "userdel", "--remove", "--force", name).CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		switch {
		case errors.As(err, &ee) && ee.ExitCode() == 6:
			// Already gone, which is what was asked for.
		case errors.As(err, &ee) && ee.ExitCode() == 12:
			notes = append(notes, "account removed; its home directory could not be: "+strings.TrimSpace(string(out)))
		default:
			return string(out), fmt.Errorf("userdel: %w", err)
		}
	}
	return strings.Join(notes, "\n"), nil
}

// jitDeleteProfileOS: the home directory goes with the account here, so
// there is never a profile left to retry.
func jitDeleteProfileOS(string) (bool, error) { return true, nil }

func jitOrphanProfilesOS() []string { return nil }
