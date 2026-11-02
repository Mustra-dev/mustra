//go:build darwin

package agent

import (
	"bufio"
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

// macOS: a hidden local user in the admin group, allowed to use Screen
// Sharing (the Remote Management privilege attribute, which counts when
// Screen Sharing is limited to listed users). dscl reads its commands on
// stdin in interactive mode, so the password is never on a command line
// where ps would show it.
//
// macOS has no expiry the agent can set cheaply on a local account, so the
// agent's own deadline and the server's removal are the two that apply.

// jitARDAllPrivileges is the naprivs value for every Remote Management
// privilege (observe, control, and the rest).
const jitARDAllPrivileges = "-1073741569"

func jitCreateAccountOS(ctx context.Context, job proto.JITAccountJob) (string, error) {
	if job.Password == "" {
		return "", errors.New("a macOS account needs a password")
	}
	if err := exec.CommandContext(ctx, "dscl", ".", "-read", "/Users/"+job.Username).Run(); err == nil {
		return "", fmt.Errorf("%s: %w", job.Username, errJITExists)
	}
	uid, err := jitFreeUID(ctx)
	if err != nil {
		return "", err
	}
	home := "/Users/" + job.Username
	rec := "/Users/" + job.Username
	var script strings.Builder
	for _, line := range []string{
		"create " + rec,
		"create " + rec + " UserShell /bin/zsh",
		`create ` + rec + ` RealName "Mustra temporary session account"`,
		"create " + rec + " UniqueID " + strconv.Itoa(uid),
		"create " + rec + " PrimaryGroupID 20",
		"create " + rec + " NFSHomeDirectory " + home,
		"create " + rec + " IsHidden 1",
		"create " + rec + " naprivs " + jitARDAllPrivileges,
		"passwd " + rec + " " + jitDsclQuote(job.Password),
	} {
		script.WriteString(line + "\n")
	}
	cmd := exec.CommandContext(ctx, "dscl", ".")
	cmd.Stdin = strings.NewReader(script.String())
	out, err := cmd.CombinedOutput()
	// Interactive dscl reports a failed line on stdout and still exits 0.
	if err != nil || bytes.Contains(out, []byte("DS Error")) {
		return "", fmt.Errorf("dscl: %s", jitRedact(string(out), job.Password))
	}
	if out, err := exec.CommandContext(ctx, "dseditgroup", "-o", "edit", "-a", job.Username, "-t", "user", "admin").CombinedOutput(); err != nil {
		return string(out), fmt.Errorf("adding %s to admin: %w", job.Username, err)
	}
	if out, err := exec.CommandContext(ctx, "createhomedir", "-c", "-u", job.Username).CombinedOutput(); err != nil {
		// Screen Sharing works without it and a GUI sign-in makes one.
		return "home folder not created: " + strings.TrimSpace(string(out)), nil
	}
	return "", nil
}

// jitFreeUID picks the lowest unused UID from 600, above the range the
// Users & Groups pane hands out to people (501 up) and below system ones.
func jitFreeUID(ctx context.Context) (int, error) {
	out, err := exec.CommandContext(ctx, "dscl", ".", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		return 0, fmt.Errorf("listing UIDs: %w", err)
	}
	used := map[int]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			if n, err := strconv.Atoi(f[1]); err == nil {
				used[n] = true
			}
		}
	}
	for uid := 600; uid < 900; uid++ {
		if !used[uid] {
			return uid, nil
		}
	}
	return 0, errors.New("no free UID between 600 and 899")
}

// jitDsclQuote quotes a value for an interactive dscl line. The server
// mints passwords without quotes or backslashes, but nothing here relies
// on that.
func jitDsclQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func jitRedact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "••••")
}

func jitDeleteAccountOS(ctx context.Context, name string) (string, error) {
	if exec.CommandContext(ctx, "dscl", ".", "-read", "/Users/"+name).Run() != nil {
		return "", nil // already gone
	}
	if out, err := exec.CommandContext(ctx, "id", "-u", name).Output(); err == nil {
		uid := strings.TrimSpace(string(out))
		_ = exec.CommandContext(ctx, "launchctl", "bootout", "user/"+uid).Run()
	}
	_ = exec.CommandContext(ctx, "pkill", "-KILL", "-u", name).Run()
	_ = exec.CommandContext(ctx, "dseditgroup", "-o", "edit", "-d", name, "-t", "user", "admin").Run()
	var notes []string
	if out, err := exec.CommandContext(ctx, "sysadminctl", "-deleteUser", name).CombinedOutput(); err != nil {
		// sysadminctl can refuse (no secure-token admin to authorise it on
		// some setups); dscl removes the record regardless.
		if out2, err2 := exec.CommandContext(ctx, "dscl", ".", "-delete", "/Users/"+name).CombinedOutput(); err2 != nil {
			return string(out) + string(out2), fmt.Errorf("removing %s: %w", name, err2)
		}
		notes = append(notes, "removed with dscl (sysadminctl: "+strings.TrimSpace(string(out))+")")
	}
	home := filepath.Join("/Users", name)
	if _, err := os.Lstat(home); err == nil {
		if err := os.RemoveAll(home); err != nil {
			notes = append(notes, "account removed; its home folder could not be: "+err.Error())
		}
	}
	return strings.Join(notes, "\n"), nil
}

// jitDeleteProfileOS: the home directory goes with the account here, so
// there is never a profile left to retry.
func jitDeleteProfileOS(string) (bool, error) { return true, nil }

func jitOrphanProfilesOS() []string { return nil }
