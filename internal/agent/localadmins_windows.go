//go:build windows

package agent

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mustra-dev/mustra/internal/proto"
)

// The members of BUILTIN\Administrators, which is what "can administer
// this machine" means on Windows, read with NetLocalGroupGetMembers. On a
// domain controller, which has no local SAM, the same call returns the
// domain's own Administrators group. This used to start PowerShell
// (Get-LocalGroupMember, with `net localgroup` on domain controllers) every
// sensor interval.

var (
	modnetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupGetMembers = modnetapi32.NewProc("NetLocalGroupGetMembers")
)

// localGroupMembersInfo2 mirrors LOCALGROUP_MEMBERS_INFO_2.
type localGroupMembersInfo2 struct {
	sid           *windows.SID
	sidUsage      uint32
	domainAndName *uint16
}

func collectLocalAdmins(ctx context.Context) ([]proto.LocalAdmin, error) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	// The group's name is localised (Administratoren, Administrateurs);
	// the SID is not.
	group, _, _, err := admins.LookupAccount("")
	if err != nil {
		return nil, fmt.Errorf("name the Administrators group: %w", err)
	}
	gname, _ := windows.UTF16PtrFromString(group)
	var (
		buf                 *byte
		read, total, resume uint32
	)
	r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(gname)), 2, uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 {
		return nil, fmt.Errorf("list local administrators: %w", windows.Errno(r))
	}
	defer windows.NetApiBufferFree(buf)
	computer, _ := windows.ComputerName()
	rows := make([]proto.LocalAdmin, 0, read)
	for _, m := range unsafe.Slice((*localGroupMembersInfo2)(unsafe.Pointer(buf)), read) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		sid := ""
		if m.sid != nil {
			sid = m.sid.String()
		}
		domain, name := splitNTAccount(windows.UTF16PtrToString(m.domainAndName))
		rows = append(rows, proto.LocalAdmin{Name: name, Domain: domain, SID: sid,
			Kind: adminKind(m.sidUsage), Source: adminSource(sid, domain, computer), Via: "Administrators"})
	}
	return rows, nil
}

// adminKind maps the SID_NAME_USE of a member to user or group.
func adminKind(use uint32) string {
	switch use {
	case windows.SidTypeUser:
		return "user"
	case windows.SidTypeGroup, windows.SidTypeAlias, windows.SidTypeWellKnownGroup:
		return "group"
	}
	return "unknown"
}

// adminSource says where a member is defined: builtin (S-1-5-32-*, the
// groups Windows ships with), local (this computer's own accounts), or
// domain (Active Directory or Entra ID). Get-LocalGroupMember's
// PrincipalSource made the same distinction.
func adminSource(sid, domain, computer string) string {
	switch {
	case strings.HasPrefix(sid, "S-1-5-32-"):
		return "builtin"
	case strings.HasPrefix(sid, "S-1-12-1-"), strings.EqualFold(domain, "AzureAD"):
		return "domain"
	case domain != "" && strings.EqualFold(domain, computer):
		return "local"
	case domain != "" && !strings.EqualFold(domain, "NT AUTHORITY"):
		return "domain"
	}
	return "unknown"
}

// splitNTAccount separates "DOMAIN\name" into its halves; a bare name has
// no domain. A UPN ("name@domain") is left whole in the name, because the
// server matches on either form.
func splitNTAccount(s string) (domain, name string) {
	if i := strings.Index(s, `\`); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}
