//go:build windows

package main

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The notification-area icon, written against Win32 directly.
//
// A tray icon is a hidden window plus a NOTIFYICONDATA plus a message loop.
// That is perhaps two hundred lines here, against a dependency that would
// have brought cgo with it on one of the platforms this repository builds
// for. The agent's six targets are cross-compiled from a single Linux
// container with CGO_ENABLED=0, and keeping that true is worth more than
// the lines saved.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procLoadImage        = user32.NewProc("LoadImageW")
	procLoadIcon         = user32.NewProc("LoadIconW")
	procShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
	procCreateMutex      = kernel32.NewProc("CreateMutexW")
)

const (
	wmDestroy      = 0x0002
	wmCommand      = 0x0111
	wmUser         = 0x0400
	wmTrayCallback = wmUser + 1

	wmLButtonUp = 0x0202
	wmRButtonUp = 0x0205

	nimAdd    = 0x0000
	nimModify = 0x0001
	nimDelete = 0x0002

	nifMessage = 0x0001
	nifIcon    = 0x0002
	nifTip     = 0x0004

	imageIcon      = 1
	lrLoadFromFile = 0x0010
	lrDefaultSize  = 0x0040

	idiApplication = 32512

	mfString    = 0x0000
	mfSeparator = 0x0800
	mfGrayed    = 0x0001

	tpmLeftAlign   = 0x0000
	tpmRightButton = 0x0002

	menuOpen    = 1001
	menuCheckIn = 1002
	menuUpdate  = 1003
	menuQuit    = 1009
)

type wndClassEx struct {
	Size, Style                        uint32
	WndProc                            uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background windows.Handle
	MenuName, ClassName                *uint16
	IconSm                             windows.Handle
}

type notifyIconData struct {
	Size            uint32
	Wnd             windows.HWND
	ID, Flags       uint32
	CallbackMessage uint32
	Icon            windows.Handle
	Tip             [128]uint16
}

type point struct{ X, Y int32 }

type msg struct {
	Wnd      windows.HWND
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type tray struct {
	wnd    windows.HWND
	icon   windows.Handle
	data   notifyIconData
	ctx    context.Context
	cancel context.CancelFunc
	state  func() *agentState
}

// singleInstance stops a second copy appearing in the tray when the shell
// starts one at login and the installer starts another. The mutex is
// released by the OS when the process exits, including when it crashes.
func singleInstance(name string) (bool, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	h, _, lastErr := procCreateMutex.Call(0, 1, uintptr(unsafe.Pointer(n)))
	if h == 0 {
		return false, fmt.Errorf("create mutex: %v", lastErr)
	}
	// ERROR_ALREADY_EXISTS: somebody else holds it, so this copy should go.
	if lastErr == syscall.Errno(windows.ERROR_ALREADY_EXISTS) {
		return false, nil
	}
	return true, nil
}

func newTray(ctx context.Context, iconPath string, state func() *agentState) (*tray, error) {
	ctx, cancel := context.WithCancel(ctx)
	t := &tray{ctx: ctx, cancel: cancel, state: state}

	instance, _, _ := procGetModuleHandle.Call(0)
	className, err := windows.UTF16PtrFromString("MustraTrayWindow")
	if err != nil {
		cancel()
		return nil, err
	}

	class := wndClassEx{
		Instance: windows.Handle(instance), ClassName: className,
		WndProc: windows.NewCallback(t.wndProc),
	}
	class.Size = uint32(unsafe.Sizeof(class))
	if ret, _, e := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&class))); ret == 0 {
		cancel()
		return nil, fmt.Errorf("register window class: %v", e)
	}

	// A message-only window: it exists to receive the icon's callbacks and
	// is never shown.
	wnd, _, e := procCreateWindowEx.Call(0,
		uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(className)),
		0, 0, 0, 0, 0, 0, 0, instance, 0)
	if wnd == 0 {
		cancel()
		return nil, fmt.Errorf("create window: %v", e)
	}
	t.wnd = windows.HWND(wnd)
	t.icon = loadIcon(iconPath)

	t.data = notifyIconData{
		Wnd: t.wnd, ID: 1, Flags: nifMessage | nifIcon | nifTip,
		CallbackMessage: wmTrayCallback, Icon: t.icon,
	}
	t.data.Size = uint32(unsafe.Sizeof(t.data))
	t.setTip("mustra")
	if ret, _, e := procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&t.data))); ret == 0 {
		cancel()
		return nil, fmt.Errorf("add tray icon: %v", e)
	}
	return t, nil
}

// loadIcon prefers the installed .ico and falls back to the stock
// application icon. A missing icon file must not cost the tray entry
// itself: an icon nobody chose is still better than no way to reach Self
// Service.
func loadIcon(path string) windows.Handle {
	if path != "" {
		if p, err := windows.UTF16PtrFromString(path); err == nil {
			h, _, _ := procLoadImage.Call(0, uintptr(unsafe.Pointer(p)),
				imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize)
			if h != 0 {
				return windows.Handle(h)
			}
		}
	}
	h, _, _ := procLoadIcon.Call(0, idiApplication)
	return windows.Handle(h)
}

func (t *tray) setTip(s string) {
	runes := windows.StringToUTF16(s)
	if len(runes) > len(t.data.Tip) {
		runes = runes[:len(t.data.Tip)-1]
		runes = append(runes, 0)
	}
	for i := range t.data.Tip {
		t.data.Tip[i] = 0
	}
	copy(t.data.Tip[:], runes)
}

// update refreshes the hover text, which is the only always-visible place
// this helper can say whether the agent is actually connected.
func (t *tray) update(s *agentState) {
	if s == nil {
		t.setTip("mustra — agent not reachable")
	} else if !s.Connected {
		t.setTip("mustra " + s.AgentVersion + " — offline")
	} else {
		t.setTip("mustra " + s.AgentVersion + " — connected")
	}
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&t.data)))
}

func (t *tray) wndProc(hwnd windows.HWND, message uint32, wParam, lParam uintptr) uintptr {
	switch message {
	case wmTrayCallback:
		switch lParam {
		case wmRButtonUp, wmLButtonUp:
			t.showMenu()
		}
	case wmCommand:
		switch wParam & 0xffff {
		case menuOpen:
			openSelfService()
		case menuCheckIn:
			go checkIn()
		case menuUpdate:
			go updateAgent()
		case menuQuit:
			t.remove()
			procPostQuitMessage.Call(0)
		}
	case wmDestroy:
		t.remove()
		procPostQuitMessage.Call(0)
	}
	ret, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(message), wParam, lParam)
	return ret
}

func (t *tray) showMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	add := func(flags uintptr, id uintptr, label string) {
		p, err := windows.UTF16PtrFromString(label)
		if err != nil {
			return
		}
		procAppendMenu.Call(menu, flags, id, uintptr(unsafe.Pointer(p)))
	}

	// The status line is a disabled item rather than a tooltip, so it is
	// readable without hovering and without a click going anywhere.
	if s := t.state(); s != nil {
		status := s.Hostname + " — agent " + s.AgentVersion
		if !s.Connected {
			status += " (offline)"
		}
		add(mfString|mfGrayed, 0, status)
		add(mfSeparator, 0, "")
	}
	add(mfString, menuOpen, "Open Self Service")
	add(mfString, menuCheckIn, "Check in now")
	add(mfString, menuUpdate, "Update agent")
	add(mfSeparator, 0, "")
	add(mfString, menuQuit, "Quit")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// Required, and easy to miss: without it the menu does not close when
	// the person clicks elsewhere.
	procSetForegroundWin.Call(uintptr(t.wnd))
	procTrackPopupMenu.Call(menu, tpmLeftAlign|tpmRightButton,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.wnd), 0)
}

func (t *tray) remove() {
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&t.data)))
	t.cancel()
}

// run pumps messages until the icon is quit. It must stay on the goroutine
// that created the window -- Win32 delivers messages to the creating thread
// -- which is why main locks the OS thread before calling this.
func (t *tray) run() {
	var m msg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}
