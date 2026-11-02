//go:build windows

package agent

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// interactiveUser is the account signed in at the console session. The
// agent runs as SYSTEM, so its own account is no use as a greeting.
func interactiveUser() string {
	sessionID, _, _ := procWTSGetActiveConsoleSessionId.Call()
	if sessionID == uintptr(^uint32(0)) {
		return ""
	}
	var token windows.Token
	if ret, _, _ := procWTSQueryUserToken.Call(sessionID, uintptr(unsafe.Pointer(&token))); ret == 0 {
		return ""
	}
	defer token.Close()
	tu, err := token.GetTokenUser()
	if err != nil {
		return ""
	}
	name, _, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}
	return name
}
