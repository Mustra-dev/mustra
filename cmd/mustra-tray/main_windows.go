//go:build windows

package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

func main() {
	// Uninstalling. The registry entries this helper writes are per-user
	// and live in HKCU, so the agent's uninstaller -- running as SYSTEM --
	// cannot reach them. It runs this instead, in the session that owns
	// them, before deleting the executable.
	if len(os.Args) > 1 && os.Args[1] == "--uninstall" {
		unregister()
		return
	}

	// The Start Menu and Desktop "Mustra Self Service" shortcut: open the
	// window, then carry on as the tray unless one is already running (the
	// single-instance check below ends this copy if so). One app, rather
	// than a shortcut for the window and another for the tray.
	if len(os.Args) > 1 && os.Args[1] == "--open" {
		openSelfService()
		os.Args = os.Args[:1]
	}

	// Activated by a toast button: answer, then get out of the way. This
	// copy is not the tray -- the shell started it purely to carry the URI.
	if len(os.Args) > 1 {
		if action, minutes, ok := parseActivation(os.Args[1]); ok {
			if err := answer(action, minutes); err != nil {
				log.Printf("could not send that answer: %v", err)
				os.Exit(1)
			}
			return
		}
		// mustra://open, or anything else we do not recognise: showing the
		// window is the harmless interpretation, and it is what clicking
		// the body of a toast should do.
		openSelfService()
		return
	}

	// Built with -H windowsgui, so there is no console and anything written
	// to stderr goes nowhere at all. Without a file, the first question
	// anybody asks about this helper -- "why is there no icon?" -- would
	// have no evidence behind it.
	closeLog := startLogging()
	defer closeLog()
	cleanupOldBinary()

	// Win32 delivers window messages to the thread that created the window.
	runtime.LockOSThread()

	only, err := singleInstance("Global\\mustra-tray-" + os.Getenv("USERNAME"))
	if err != nil {
		log.Fatalf("could not claim single-instance lock: %v", err)
	}
	if !only {
		return
	}

	// Two assets, because they are consumed by different things: the tray
	// icon is loaded by LoadImage and must be an .ico, while a toast's
	// appLogoOverride renders PNG reliably and ICO not at all on some
	// builds. Either may be missing without costing the other.
	trayIcon := assetPath("mustra.ico")
	logo := assetPath("mustra.png")
	if err := registerIdentity(logo); err != nil {
		// Not fatal. A toast under the wrong name is a worse notification,
		// not a missing one, and the tray itself still works.
		log.Printf("could not register the application identity: %v", err)
	}
	if err := registerProtocol(); err != nil {
		log.Printf("could not register the mustra: protocol: %v", err)
	}
	if err := registerAutostart(); err != nil {
		log.Printf("could not register autostart: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var mu sync.RWMutex
	var last *agentState
	getState := func() *agentState {
		mu.RLock()
		defer mu.RUnlock()
		return last
	}

	// Retry rather than exit. Shell_NotifyIcon talks to explorer, and right
	// after a service restart -- which is exactly when the agent starts this
	// helper -- the shell can still be busy and refuse the icon. The first
	// version treated that as fatal, so the helper died, and the only thing
	// that rescued it was the agent noticing thirty seconds later and
	// starting another. Recovering here is cheaper than a whole new process,
	// and it is visible in the log either way.
	var t *tray
	for attempt := 1; ; attempt++ {
		t, err = newTray(ctx, trayIcon, getState)
		if err == nil {
			if attempt > 1 {
				log.Printf("tray icon created on attempt %d", attempt)
			}
			break
		}
		if attempt >= 10 {
			log.Fatalf("could not create the tray icon after %d attempts: %v", attempt, err)
		}
		log.Printf("could not create the tray icon (attempt %d), retrying: %v", attempt, err)
		time.Sleep(3 * time.Second)
	}

	go func() {
		// shown is the last notification this helper raised a toast for.
		// Without it the poll would re-toast the same message every few
		// seconds, which is how a notification becomes something people
		// turn off.
		shown := ""
		failures := 0
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			state, err := fetchState()
			if err != nil {
				// The agent restarting is ordinary -- an update does it on
				// purpose -- so this is not worth shouting about every five
				// seconds. But saying nothing at all was worse: a helper
				// that never reaches the agent looks identical to one that
				// is working, and the agent then starts another one
				// believing none is running.
				failures++
				if failures == 1 || failures%60 == 0 {
					log.Printf("cannot reach the agent at %s (%d consecutive): %v",
						agentAddr, failures, err)
				}
				mu.Lock()
				last = nil
				mu.Unlock()
				t.update(nil)
			} else {
				if failures > 0 {
					log.Printf("reached the agent again after %d failed attempts", failures)
					failures = 0
				}
				mu.Lock()
				last = state
				mu.Unlock()
				t.update(state)

				switch {
				case state.Notification == nil:
					// Cleared or postponed: forget it, so the same message
					// toasts again when a postponement ends.
					shown = ""
				case state.Notification.ID != shown:
					if err := showToast(ctx, state.Notification, logo); err != nil {
						log.Printf("could not show the toast: %v", err)
					}
					shown = state.Notification.ID
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	t.run()
}

// assetPath resolves a file shipped beside this executable.
func assetPath(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(exe), name)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// openSelfService shows the window as an app of its own: Edge's (or
// Chrome's) app mode has no tabs, address bar or browser chrome, so it
// reads as the Self Service application rather than a web page. A machine
// with neither falls back to the default browser.
func openSelfService() {
	url := "http://" + agentAddr + "/"
	for _, browser := range appBrowsers() {
		if err := exec.Command(browser, "--app="+url, "--window-size=1040,800").Start(); err == nil {
			return
		}
	}
	// rundll32 rather than "start": no shell, so nothing in the URL is
	// interpreted, and it is the documented way to hand a URL to the
	// default browser.
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
}

// appBrowsers lists the installed browsers with an app mode, Edge first:
// it ships with Windows, so it is nearly always there.
func appBrowsers() []string {
	var out []string
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Google\Chrome\Application\chrome.exe`),
	} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func checkIn() {
	resp, err := postLocal("/api/checkin", []byte("{}"))
	if err != nil {
		log.Printf("check-in failed: %v", err)
		return
	}
	resp.Body.Close()
}

func updateAgent() {
	resp, err := postLocal("/api/update-agent", []byte("{}"))
	if err != nil {
		log.Printf("update request failed: %v", err)
		return
	}
	resp.Body.Close()
}

// startLogging sends the log to a file beside the user's other application
// data. Failing to open it is not worth refusing to start over: a tray icon
// with no log is still a tray icon.
func startLogging() func() {
	dir := os.Getenv("LOCALAPPDATA")
	if dir == "" {
		return func() {}
	}
	dir = filepath.Join(dir, "mustra")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return func() {}
	}
	path := filepath.Join(dir, "tray.log")
	// Append, not truncate. Truncating looked tidy and destroyed the thing
	// most worth having: when a start fails and the agent starts another
	// thirty seconds later, the second one erased the first one's reason.
	// Bounded by rotating once past a megabyte, so it still cannot fill a
	// disk.
	if fi, err := os.Stat(path); err == nil && fi.Size() > 1<<20 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return func() {}
	}
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("mustra-tray ")
	log.Printf("starting (agent at %s)", agentAddr)
	return func() { f.Close() }
}

// cleanupOldBinary clears leftovers from the self-replacing build this
// replaced. Harmless when there are none.
func cleanupOldBinary() {
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
		os.Remove(exe + ".new")
	}
}
