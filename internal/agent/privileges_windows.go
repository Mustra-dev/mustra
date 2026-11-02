//go:build windows

package agent

import (
	"context"
	"fmt"
	"os/user"

	"golang.org/x/sys/windows"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Windows privileges are the subtle half of "run as SYSTEM". A LocalSystem
// token *holds* SeDebugPrivilege, SeBackupPrivilege and the rest, but they
// arrive disabled: until a process calls AdjustTokenPrivileges to enable
// them, the kernel behaves as though it doesn't have them. That's why an
// agent can be running as SYSTEM and still be denied when it opens another
// process or reads a file whose ACL excludes it.
//
// enableFullPrivileges is called once at startup, before anything tries to
// use them, and the privileges sensor reports which ones actually took —
// so an endpoint that can't be fully managed says so instead of failing
// silently later.

// wantedPrivileges is what full management of an endpoint needs.
var wantedPrivileges = []struct {
	name string
	why  string
}{
	{"SeDebugPrivilege", "read details of processes owned by other accounts"},
	{"SeBackupPrivilege", "read any file regardless of its ACL"},
	{"SeRestorePrivilege", "write any file regardless of its ACL"},
	{"SeTakeOwnershipPrivilege", "take ownership of a locked-down object"},
	{"SeSecurityPrivilege", "read and manage the security event log"},
	{"SeLoadDriverPrivilege", "load a driver"},
	{"SeSystemEnvironmentPrivilege", "read firmware environment values"},
	{"SeShutdownPrivilege", "reboot the endpoint after an update"},
}

// enableFullPrivileges turns on every privilege the token holds. A
// privilege the token doesn't hold simply can't be enabled — that's a
// finding to report, not an error to fail on, so this never returns fatal.
func enableFullPrivileges() (enabled, missing []string) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		for _, p := range wantedPrivileges {
			missing = append(missing, p.name)
		}
		return nil, missing
	}
	defer token.Close()

	for _, p := range wantedPrivileges {
		if err := enableOne(token, p.name); err != nil {
			missing = append(missing, p.name)
			continue
		}
		enabled = append(enabled, p.name)
	}
	return enabled, missing
}

func enableOne(token windows.Token, name string) error {
	var luid windows.LUID
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return err
	}
	state := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
		return err
	}
	// AdjustTokenPrivileges reports success even when it enabled nothing —
	// the real answer is in GetLastError, which the wrapper surfaces as
	// ERROR_NOT_ALL_ASSIGNED.
	if err := windows.GetLastError(); err == windows.ERROR_NOT_ALL_ASSIGNED {
		return fmt.Errorf("%s not held by this token", name)
	}
	return nil
}

func collectPrivileges(ctx context.Context) (proto.PrivilegeInfo, error) {
	info := proto.PrivilegeInfo{UID: -1, Service: "windows-service"}

	if u, err := user.Current(); err == nil {
		info.Account = u.Username
	}

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		info.Elevated = token.IsElevated()
		info.IntegrityLevel = integrityLevel(token)
	}

	// Re-assert on every collection rather than only at startup: a service
	// that was restarted by the SCM gets a fresh token, and this keeps the
	// reported state honest about the process that's running right now.
	info.EnabledPrivileges, info.MissingPrivileges = enableFullPrivileges()

	// LocalSystem is the account that makes an endpoint fully manageable.
	// An Administrator account is close, but not the same: it can't read
	// another session's registry hive and it loses rights when the user
	// signing in changes.
	isSystem := info.Account == "NT AUTHORITY\\SYSTEM" || info.Account == "NT AUTHORITY\\System"
	if !isSystem && !info.Elevated {
		info.Limitations = append(info.Limitations,
			"the agent is not running as LocalSystem or an elevated account")
		info.Remedy = append(info.Remedy,
			"reinstall from an elevated PowerShell; the installer creates the service under LocalSystem")
	}
	for _, p := range wantedPrivileges {
		for _, m := range info.MissingPrivileges {
			if m == p.name {
				info.Limitations = append(info.Limitations,
					fmt.Sprintf("missing %s, so mustra cannot %s", p.name, p.why))
				info.Remedy = append(info.Remedy,
					"grant "+p.name+" to the service account, or run the service as LocalSystem")
			}
		}
	}

	info.FullRights = len(info.Limitations) == 0
	return info, nil
}

func integrityLevel(token windows.Token) string {
	// A LocalSystem service runs at System integrity; an elevated admin at
	// High; anything else can't manage the machine.
	if token.IsElevated() {
		return "high-or-system"
	}
	return "medium"
}
