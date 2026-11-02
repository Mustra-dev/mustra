//go:build linux

package agent

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Who can administer a Linux endpoint, read from the files that decide it
// rather than by asking a command: uid 0 accounts in /etc/passwd, the
// members of the groups distributions use to grant sudo (sudo on Debian,
// wheel on Red Hat and Arch, admin on older Ubuntu), and explicit grants in
// /etc/sudoers and /etc/sudoers.d. This is what a local attacker with a
// foothold would read too, and it does not require sudo itself to run —
// except that sudoers is root-readable only, which the agent is.
//
// It is deliberately not a sudoers parser. A user or %group at the start of
// a grant line is recorded as holding sudo; the command list after it is
// not interpreted, because "can run one command as root" is still a lead
// worth showing and the alternative was silently dropping grants the
// parser did not understand.
func collectLocalAdmins(ctx context.Context) ([]proto.LocalAdmin, error) {
	var rows []proto.LocalAdmin
	seen := map[string]bool{}
	add := func(name, kind, via string) {
		key := kind + ":" + name
		if name == "" || seen[key] {
			return
		}
		seen[key] = true
		rows = append(rows, proto.LocalAdmin{Name: name, Kind: kind, Source: "local", Via: via})
	}

	// uid 0: root, and anything else somebody gave uid 0 to.
	if f, err := os.Open("/etc/passwd"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			parts := strings.Split(sc.Text(), ":")
			if len(parts) >= 3 && parts[2] == "0" {
				add(parts[0], "user", "uid 0")
			}
		}
		f.Close()
	}

	// The sudo groups. Membership is listed on the group line; a user whose
	// primary group is one of these (rare, but possible) is caught through
	// /etc/passwd's gid field.
	adminGroups := map[string]bool{"sudo": true, "wheel": true, "admin": true}
	gidOf := map[string]string{}
	if f, err := os.Open("/etc/group"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			parts := strings.Split(sc.Text(), ":")
			if len(parts) < 4 || !adminGroups[parts[0]] {
				continue
			}
			gidOf[parts[2]] = parts[0]
			for _, m := range strings.Split(parts[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					add(m, "user", parts[0]+" group")
				}
			}
		}
		f.Close()
	}
	if len(gidOf) > 0 {
		if f, err := os.Open("/etc/passwd"); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				parts := strings.Split(sc.Text(), ":")
				if len(parts) >= 4 {
					if g, ok := gidOf[parts[3]]; ok {
						add(parts[0], "user", g+" group")
					}
				}
			}
			f.Close()
		}
	}

	// sudoers grants. Lines look like "alex ALL=(ALL:ALL) ALL" or
	// "%admins ALL=(ALL) NOPASSWD: ALL"; Defaults, comments, includes and
	// aliases are skipped.
	files := []string{"/etc/sudoers"}
	if extra, err := filepath.Glob("/etc/sudoers.d/*"); err == nil {
		files = append(files, extra...)
	}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") ||
				strings.HasPrefix(line, "@include") || strings.HasPrefix(line, "Cmnd_Alias") ||
				strings.HasPrefix(line, "User_Alias") || strings.HasPrefix(line, "Host_Alias") ||
				strings.HasPrefix(line, "Runas_Alias") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 || !strings.Contains(line, "=") {
				continue
			}
			who := fields[0]
			via := "sudoers"
			if filepath.Dir(path) == "/etc/sudoers.d" {
				via = "sudoers.d/" + filepath.Base(path)
			}
			switch {
			case strings.HasPrefix(who, "%"):
				add(strings.TrimPrefix(who, "%"), "group", via)
			case strings.HasPrefix(who, "+") || strings.HasPrefix(who, "#"):
				// netgroups and numeric uids: not something this resolves
			default:
				add(who, "user", via)
			}
		}
		f.Close()
		if ctx.Err() != nil {
			return rows, ctx.Err()
		}
	}
	if rows == nil {
		rows = []proto.LocalAdmin{}
	}
	return rows, nil
}
