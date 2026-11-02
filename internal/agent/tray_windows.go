//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Starting the tray helper in the signed-in user's session.
//
// This is the piece that session 0 isolation makes necessary. The agent is a
// LocalSystem service; the helper has to draw in somebody's desktop. A
// service cannot simply start a process there -- that is the entire point of
// the isolation -- so the documented route is to borrow the token of whoever
// is signed in at the console and create the process with it.
//
// Two other approaches were tried on a real desktop first, and both were
// wrong in ways worth recording:
//
//   - A scheduled task with an interactive token. schtasks writes warnings to
//     stderr on success, and the installer runs with $ErrorActionPreference =
//     "Stop", so a *successful* call aborted the rest of the install. Twice.
//   - Letting the helper replace its own binary. Windows does allow renaming
//     a running image, so it looked clean -- but the helper runs unelevated
//     as the user and its binary lives in Program Files, which the user
//     cannot write. "Access is denied", every five seconds, forever.
//
// The token is the only thing that actually crosses the boundary.

var (
	wtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")
	userenv  = windows.NewLazySystemDLL("userenv.dll")

	procWTSGetActiveConsoleSessionId = kernel32Tray.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQueryUserToken            = wtsapi32.NewProc("WTSQueryUserToken")
	procCreateEnvironmentBlock       = userenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock      = userenv.NewProc("DestroyEnvironmentBlock")

	kernel32Tray = windows.NewLazySystemDLL("kernel32.dll")
)

const (
	createUnicodeEnvironment = 0x00000400
	createNoWindowTray       = 0x08000000
	trayStartupInfoDesktop   = `winsta0\default`
)

// startTrayForConsoleUser starts the tray helper as whoever is signed in at
// the console. It is best effort in every direction: a server with nobody
// signed in, a locked machine, a helper that was never installed -- none of
// those are failures worth reporting, they are just "no tray right now".
func (a *Agent) startTrayForConsoleUser() {
	exe := trayPath()
	if exe == "" {
		return
	}
	// One already running. Its poll of /api/notification is the proof --
	// the same signal that suppresses the msg.exe fallback -- so no extra
	// bookkeeping is needed to know it is alive.
	//
	// Without this the supervisor started a process every thirty seconds
	// forever. The helper's single-instance mutex made each extra copy exit
	// immediately, so nothing broke and nothing showed it: just a process
	// launched every half minute on every Windows endpoint, for good.
	if a.tray.active(90 * time.Second) {
		return
	}
	a.logger.Info("no tray helper is polling; starting one",
		"last_poll_age", a.tray.age().String())

	sessionID, _, _ := procWTSGetActiveConsoleSessionId.Call()
	// 0xFFFFFFFF means no session is attached to the console.
	if sessionID == uintptr(^uint32(0)) {
		return
	}

	var token windows.Token
	ret, _, err := procWTSQueryUserToken.Call(sessionID, uintptr(unsafe.Pointer(&token)))
	if ret == 0 {
		a.trayProblem(a.logger.Warn, "no console user token", err)
		return
	}
	defer token.Close()

	// A duplicated primary token is what CreateProcessAsUser requires; the
	// one WTS hands back is an impersonation token.
	var primary windows.Token
	if err := windows.DuplicateTokenEx(token, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityIdentification, windows.TokenPrimary, &primary); err != nil {
		a.trayProblem(a.logger.Warn, "could not duplicate the console user's token", err)
		return
	}
	defer primary.Close()

	// The user's environment, not the service's. Without this the helper
	// inherits SYSTEM's profile and writes its log into
	// C:\Windows\System32\config\systemprofile.
	var env uintptr
	if ret, _, _ := procCreateEnvironmentBlock.Call(uintptr(unsafe.Pointer(&env)),
		uintptr(primary), 0); ret == 0 {
		env = 0
	}
	defer func() {
		if env != 0 {
			procDestroyEnvironmentBlock.Call(env)
		}
	}()

	desktop, err := windows.UTF16PtrFromString(trayStartupInfoDesktop)
	if err != nil {
		return
	}
	cmdline, err := windows.UTF16PtrFromString(`"` + exe + `"`)
	if err != nil {
		return
	}

	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	flags := uint32(createNoWindowTray)
	if env != 0 {
		flags |= createUnicodeEnvironment
	}
	if err := windows.CreateProcessAsUser(primary, nil, cmdline, nil, nil, false,
		flags, (*uint16)(unsafe.Pointer(env)), nil, &si, &pi); err != nil {
		a.trayProblem(a.logger.Warn, "could not start the tray helper in the user session", err)
		return
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	a.logger.Info("tray helper started in the console session", "session", uint32(sessionID))
}

// trayPath is the helper beside this agent, or empty when it is not
// installed -- an endpoint that has never had one, or a build that predates
// it.
func trayPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(exe), "mustra-tray.exe")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// superviseTray keeps one running for whoever is signed in.
//
// It polls rather than watching for session changes: a service can subscribe
// to WM_WTSSESSION_CHANGE, but that needs a window and a message loop inside
// a Windows service, which is a great deal of machinery for something a
// thirty-second check does just as well. Starting a second copy is harmless
// anyway -- the helper takes a named mutex and the loser exits.
func (a *Agent) superviseTray(stop <-chan struct{}) {
	a.installEmbeddedTray()
	a.startTrayForConsoleUser()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			a.startTrayForConsoleUser()
		}
	}
}

// trayProblem reports a tray failure once rather than every thirty seconds.
//
// The first version logged these at debug, which meant that when the helper
// did not appear there was nothing at all to look at -- the worst of both:
// no noise and no evidence. Once, at warn, is the useful amount.
func (a *Agent) trayProblem(log func(string, ...any), msg string, err error) {
	a.trayReported.mu.Lock()
	defer a.trayReported.mu.Unlock()
	if !a.trayReported.at.IsZero() {
		return
	}
	a.trayReported.at = time.Now()
	log("tray helper unavailable: "+msg, "error", err,
		"effect", "notifications fall back to msg.exe; the Startup shortcut still starts it at sign-in")
}
