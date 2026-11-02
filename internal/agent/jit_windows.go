//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Windows: a local account in Administrators and Remote Desktop Users,
// through the NetUser* APIs rather than net.exe or New-LocalUser, so the
// password is never on a command line (process-creation auditing, 4688,
// records command lines). The account's own expiry is set too, a second
// deadline beside the agent's, which Windows enforces at sign-in.
//
// Groups are found by well-known SID, not name: "Administrators" is
// "Administradores" on a Spanish install.
//
// A domain controller has no local accounts, so NetUserAdd there would
// create a domain account; that is refused rather than done quietly.

var (
	netapi32JIT = windows.NewLazySystemDLL("netapi32.dll")

	procNetUserAdd              = netapi32JIT.NewProc("NetUserAdd")
	procNetUserDel              = netapi32JIT.NewProc("NetUserDel")
	procNetUserSetInfo          = netapi32JIT.NewProc("NetUserSetInfo")
	procNetLocalGroupAddMembers = netapi32JIT.NewProc("NetLocalGroupAddMembers")
	procWTSQuerySessionInfoJIT  = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSLogoffSessionJIT     = wtsapi32.NewProc("WTSLogoffSession")
	procDeleteProfileJIT        = userenv.NewProc("DeleteProfileW")
)

const (
	nerrSuccess        = 0
	nerrUserExists     = 2224
	nerrUserNotFound   = 2221
	nerrGroupMemberDup = 1378 // ERROR_MEMBER_IN_ALIAS
	ufScript           = 0x0001
	ufDontExpirePasswd = 0x10000
	userPrivUser       = 1
	verNTDomainCtrl    = 2
	wtsUserName        = 5
)

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

type userInfo1017 struct{ AcctExpires uint32 }

type localGroupMembersInfo3 struct{ DomainAndName *uint16 }

func jitCreateAccountOS(ctx context.Context, job proto.JITAccountJob) (string, error) {
	if job.Password == "" {
		return "", errors.New("a Windows account needs a password")
	}
	if v := windows.RtlGetVersion(); v != nil && v.ProductType == verNTDomainCtrl {
		return "", errors.New("this is a domain controller, which has no local accounts; a temporary account here would be a domain account")
	}
	name, _ := windows.UTF16PtrFromString(job.Username)
	pass, err := windows.UTF16PtrFromString(job.Password)
	if err != nil {
		return "", errors.New("the password cannot be passed to Windows")
	}
	comment, _ := windows.UTF16PtrFromString("Mustra temporary session account")
	info := userInfo1{Name: name, Password: pass, Priv: userPrivUser, Comment: comment, Flags: ufScript | ufDontExpirePasswd}
	var parmErr uint32
	r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	switch r {
	case nerrSuccess:
	case nerrUserExists:
		return "", fmt.Errorf("%s: %w", job.Username, errJITExists)
	default:
		return "", fmt.Errorf("NetUserAdd: %w (parameter %d)", netErr(r), parmErr)
	}
	expiry := userInfo1017{AcctExpires: uint32(job.ExpiresAt.Unix())}
	if r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(name)), 1017, uintptr(unsafe.Pointer(&expiry)), 0); r != nerrSuccess {
		return "", fmt.Errorf("setting the account's expiry: %w", netErr(r))
	}
	for _, sid := range []string{"S-1-5-32-544", "S-1-5-32-555"} { // Administrators, Remote Desktop Users
		if err := jitAddToGroup(sid, job.Username); err != nil {
			return "", err
		}
	}
	return jitQuietFirstSignIn(), nil
}

// jitQuietFirstSignIn turns off what Windows shows a new account at its
// first sign-in: the "Choose privacy settings for your device" page and
// the "Hi … we're getting things ready" animation. Every temporary account
// is new, so without this each session starts with both. They are machine
// policies and so apply to every new account on the endpoint, which only
// skips screens: the privacy choices stay at their policy-set or default
// values, and CIS recommends the animation off anyway. A failure is
// reported, not fatal; the session still opens.
func jitQuietFirstSignIn() string {
	var notes []string
	for _, v := range []struct {
		key, name string
		value     uint32
	}{
		{`SOFTWARE\Policies\Microsoft\Windows\OOBE`, "DisablePrivacyExperience", 1},
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableFirstLogonAnimation", 0},
	} {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, v.key, registry.QUERY_VALUE|registry.SET_VALUE)
		if err == nil {
			if cur, _, qerr := k.GetIntegerValue(v.name); qerr != nil || cur != uint64(v.value) {
				err = k.SetDWordValue(v.name, v.value)
			}
			k.Close()
		}
		if err != nil {
			notes = append(notes, fmt.Sprintf("could not set %s (the first sign-in shows it): %v", v.name, err))
		}
	}
	return strings.Join(notes, "\n")
}

func jitAddToGroup(groupSID, user string) error {
	sid, err := windows.StringToSid(groupSID)
	if err != nil {
		return err
	}
	group, _, _, err := sid.LookupAccount("")
	if err != nil {
		return fmt.Errorf("looking up group %s: %w", groupSID, err)
	}
	gp, _ := windows.UTF16PtrFromString(group)
	member, _ := windows.UTF16PtrFromString(user)
	m := localGroupMembersInfo3{DomainAndName: member}
	r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(gp)), 3, uintptr(unsafe.Pointer(&m)), 1)
	if r != nerrSuccess && r != nerrGroupMemberDup {
		return fmt.Errorf("adding %s to %s: %w", user, group, netErr(r))
	}
	return nil
}

func jitDeleteAccountOS(ctx context.Context, name string) (string, error) {
	var notes []string
	// The SID is needed for the profile, and is gone with the account.
	var sidString string
	if sid, _, _, err := windows.LookupSID("", name); err == nil {
		sidString = sid.String()
	}
	if n := jitLogoff(name); n > 0 {
		notes = append(notes, fmt.Sprintf("signed out %d session(s)", n))
	}
	np, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(np)))
	if r != nerrSuccess && r != nerrUserNotFound {
		return strings.Join(notes, "\n"), fmt.Errorf("NetUserDel: %w", netErr(r))
	}
	if sidString == "" {
		return strings.Join(notes, "\n"), nil
	}
	// Sign-out is asynchronous, and Windows keeps the profile's registry
	// hive loaded for a while after it; a profile cannot be deleted while
	// it is. Wait for it to unload, then delete, then check: on
	// 2026-10-20 DeleteProfileW reported nothing wrong and the profile
	// stayed. What is still there is handed back for the sweep to retry.
	deadline := time.Now().Add(30 * time.Second)
	for jitProfileLoaded(sidString) && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return strings.Join(notes, "\n"), &jitProfilePending{SID: sidString}
		case <-time.After(time.Second):
		}
	}
	if gone, err := jitDeleteProfileOS(sidString); !gone {
		notes = append(notes, fmt.Sprintf("account removed; its profile is still in use and will be deleted later (%v)", err))
		return strings.Join(notes, "\n"), &jitProfilePending{SID: sidString}
	}
	return strings.Join(notes, "\n"), nil
}

const jitProfileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`

// jitOrphanProfilesOS lists profiles that belonged to temporary accounts
// whose accounts are gone: the folder name says so, and the SID no longer
// resolves to an account. Those left by an agent before 0.57.41, which did
// not keep track of them, are found this way.
func jitOrphanProfilesOS() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, strings.TrimSuffix(jitProfileListKey, `\`), registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var out []string
	for _, sid := range sids {
		if !strings.HasPrefix(sid, "S-1-5-21-") {
			continue // system and service profiles
		}
		pk, err := registry.OpenKey(registry.LOCAL_MACHINE, jitProfileListKey+sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		path, _, err := pk.GetStringValue("ProfileImagePath")
		pk.Close()
		if err != nil || !jitOrphanProfilePattern.MatchString(path) {
			continue
		}
		s, err := windows.StringToSid(sid)
		if err != nil {
			continue
		}
		if _, _, _, err := s.LookupAccount(""); err == nil {
			continue // the account exists: not ours to touch
		}
		out = append(out, sid)
	}
	return out
}

// jitProfileLoaded reports whether the account's registry hive is still
// loaded (it appears under HKEY_USERS while it is).
func jitProfileLoaded(sid string) bool {
	k, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// jitDeleteProfileOS deletes a profile (folder and ProfileList entry) and
// reports whether it is gone, judged by the ProfileList entry rather than
// by DeleteProfileW's answer.
func jitDeleteProfileOS(sid string) (bool, error) {
	exists := func() bool {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, jitProfileListKey+sid, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		k.Close()
		return true
	}
	if !exists() {
		return true, nil
	}
	if jitProfileLoaded(sid) {
		return false, errors.New("the profile is still loaded")
	}
	sp, _ := windows.UTF16PtrFromString(sid)
	ok, _, e := procDeleteProfileJIT.Call(uintptr(unsafe.Pointer(sp)), 0, 0)
	if !exists() {
		return true, nil
	}
	if ok != 0 {
		e = errors.New("DeleteProfileW succeeded but the profile is still registered")
	}
	return false, e
}

// jitLogoff signs the account out of every session it holds (console or
// Remote Desktop) and returns how many there were.
func jitLogoff(name string) int {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return 0
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	n := 0
	for _, s := range unsafe.Slice(sessions, count) {
		var buf *uint16
		var size uint32
		ok, _, _ := procWTSQuerySessionInfoJIT.Call(0, uintptr(s.SessionID), wtsUserName, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size)))
		if ok == 0 || buf == nil {
			continue
		}
		user := windows.UTF16PtrToString(buf)
		windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
		if strings.EqualFold(user, name) {
			if ok, _, _ := procWTSLogoffSessionJIT.Call(0, uintptr(s.SessionID), 1); ok != 0 {
				n++
			}
		}
	}
	return n
}

func netErr(code uintptr) error {
	return fmt.Errorf("%w (%d)", syscall.Errno(code), code)
}
