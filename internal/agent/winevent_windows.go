//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A Windows event log subscription (wevtapi), in pull mode: Windows sets
// an event when new records match the query and the agent reads them with
// EvtNext. Nothing is started per read and the event log service is not
// asked to search the log, which is what polling with Get-WinEvent cost:
// a PowerShell start (about 1.6 CPU-seconds on a two-core server) every
// fifteen seconds, plus the service filtering the whole Security log each
// time.

var (
	modwevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = modwevtapi.NewProc("EvtSubscribe")
	procEvtNext      = modwevtapi.NewProc("EvtNext")
	procEvtRender    = modwevtapi.NewProc("EvtRender")
	procEvtClose     = modwevtapi.NewProc("EvtClose")
)

const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXML          = 1
	errEvtChannelNotFound      = windows.Errno(15007)
	errEvtQueryResultStale     = windows.Errno(15011)
)

// eventSubscription delivers the events of one channel that match an
// XPath query, from the moment it is opened.
type eventSubscription struct {
	handle uintptr
	signal windows.Handle
}

// subscribeEvents opens a subscription. A channel that does not exist
// (Sysmon not installed) returns errEvtChannelNotFound.
func subscribeEvents(channel, query string) (*eventSubscription, error) {
	if err := modwevtapi.Load(); err != nil {
		return nil, err
	}
	// Manual-reset and created signalled, as in Microsoft's pull
	// subscription sample: the subscription signals again only after a
	// read has found nothing left (drain resets it then), so the first
	// read must happen before the first wait. An unsignalled auto-reset
	// event waited forever on a server writing logons every few seconds.
	signal, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return nil, err
	}
	ch, _ := windows.UTF16PtrFromString(channel)
	q, _ := windows.UTF16PtrFromString(query)
	h, _, callErr := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)),
		0, 0, 0, evtSubscribeToFutureEvents)
	if h == 0 {
		windows.CloseHandle(signal)
		return nil, callErr
	}
	return &eventSubscription{handle: h, signal: signal}, nil
}

func (s *eventSubscription) Close() {
	if s.handle != 0 {
		procEvtClose.Call(s.handle)
		s.handle = 0
	}
	if s.signal != 0 {
		windows.CloseHandle(s.signal)
		s.signal = 0
	}
}

// wait blocks until events are signalled, the timeout passes or ctx ends.
func (s *eventSubscription) wait(ctx context.Context, timeout time.Duration) bool {
	ms := uint32(timeout / time.Millisecond)
	ev, err := windows.WaitForSingleObject(s.signal, ms)
	if ctx.Err() != nil || err != nil {
		return false
	}
	return ev == windows.WAIT_OBJECT_0
}

// drain reads every event waiting on the subscription, up to max, and
// renders each.
func (s *eventSubscription) drain(max int) ([]winEvent, error) {
	var out []winEvent
	handles := make([]uintptr, 64)
	for len(out) < max {
		var returned uint32
		r, _, err := procEvtNext.Call(s.handle, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), 0, 0,
			uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) || errors.Is(err, windows.ERROR_INVALID_OPERATION) {
				windows.ResetEvent(s.signal)
				return out, nil
			}
			return out, err
		}
		for _, h := range handles[:returned] {
			if ev, err := renderEvent(h); err == nil {
				out = append(out, ev)
			}
			procEvtClose.Call(h)
		}
	}
	// More than max waiting: the rest are skipped, not queued up behind a
	// burst (a domain controller under a password spray).
	for {
		var returned uint32
		r, _, _ := procEvtNext.Call(s.handle, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), 0, 0,
			uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			windows.ResetEvent(s.signal)
			return out, nil
		}
		for _, h := range handles[:returned] {
			procEvtClose.Call(h)
		}
	}
}

func renderEvent(h uintptr) (winEvent, error) {
	buf := make([]uint16, 4096)
	for {
		var used, props uint32
		r, _, err := procEvtRender.Call(0, h, evtRenderEventXML, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return parseEventXML(windows.UTF16ToString(buf[:used/2]))
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || int(used/2) <= len(buf) || used > 1<<22 {
			return winEvent{}, fmt.Errorf("render event: %w", err)
		}
		buf = make([]uint16, used/2+1)
	}
}
