package agent

import (
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Showing a message to the person at the endpoint.
//
// There are two delivery channels here and they are not redundant:
//
//   - The Self Service window is the RELIABLE one. It is already a local web
//     UI the agent serves, so it works identically on every platform, needs
//     no session trickery, and the message survives until it is answered.
//   - A native toast is BEST EFFORT. It is what actually gets someone's
//     attention, but a service cannot reliably draw in a user's session --
//     that is what session 0 isolation on Windows exists to prevent -- so
//     every platform's route is a compromise and any of them can fail.
//
// So the toast is fired and forgotten, and the window is where the message
// really lives. A toast that fails to appear must never lose the message.

// activeNotification is the message currently awaiting an answer. One at a
// time, deliberately: a stack of competing restart prompts is not something
// a person can act on, and the newest is the one that matters.
type activeNotification struct {
	mu           sync.RWMutex
	msg          *proto.EndUserNotification
	shownAt      time.Time
	postponeUnti time.Time
}

func (a *activeNotification) set(m *proto.EndUserNotification) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.msg = m
	a.shownAt = time.Now()
	a.postponeUnti = time.Time{}
}

func (a *activeNotification) get() (*proto.EndUserNotification, time.Time) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.msg, a.postponeUnti
}

func (a *activeNotification) clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.msg = nil
}

func (a *activeNotification) postpone(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.postponeUnti = time.Now().Add(d)
}

// visible reports whether the message should be shown right now: it exists,
// its deadline has not passed, and it is not inside a postponement the
// person asked for.
func (a *activeNotification) visible() *proto.EndUserNotification {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.msg == nil {
		return nil
	}
	if a.msg.Deadline != nil && time.Now().After(*a.msg.Deadline) {
		return nil
	}
	if !a.postponeUnti.IsZero() && time.Now().Before(a.postponeUnti) {
		return nil
	}
	return a.msg
}

// showNotification records the message and makes a best-effort attempt at a
// native toast. It returns immediately: the endpoint acknowledging that it
// has the message is a different thing from the person answering it, and
// conflating them would hold the command channel open for however long
// somebody takes to look at their screen.
func (a *Agent) showNotification(ctx context.Context, m *proto.EndUserNotification) {
	a.notification.set(m)
	go a.nativeToast(context.WithoutCancel(ctx), m)
	a.logger.Info("end-user notification shown", "kind", m.Kind, "title", m.Title, "run_id", m.RunID)
}

// nativeToast is the attention-getter. Every platform's route is a
// compromise, and failure is logged at debug rather than error: the Self
// Service window still has the message, so a missing toast is a degraded
// experience, not a lost one.
func (a *Agent) nativeToast(ctx context.Context, m *proto.EndUserNotification) {
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	text := m.Title
	if m.Body != "" {
		text += "\n\n" + m.Body
	}

	// When the tray helper is running, it is showing this message as a
	// proper toast -- the product's icon, the operator's own buttons -- and
	// msg.exe would put a second, uglier copy of the same thing on screen.
	// One notification per notification.
	//
	// The window is a few poll intervals rather than one, so an endpoint
	// under load does not flicker back to the fallback; and because it
	// expires, killing the tray restores msg.exe on its own within half a
	// minute.
	if a.tray.active(30 * time.Second) {
		a.logger.Debug("tray helper is present, leaving the toast to it",
			"kind", m.Kind, "run_id", m.RunID)
		return
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// msg.exe is the one route that works from a service across session
		// 0 isolation without a helper process living in the user's session.
		// It is plain and old, which is exactly why it still works -- and it
		// is the fallback for an endpoint with no tray helper running.
		cmd = exec.CommandContext(tctx, "msg.exe", "*", "/TIME:120", text)
	case "darwin":
		// osascript has to run AS the console user; run as root it draws
		// into a session nobody is looking at.
		script := "display notification " + strconv.Quote(m.Body) +
			" with title " + strconv.Quote(m.Title)
		cmd = exec.CommandContext(tctx, "/bin/sh", "-c",
			"launchctl asuser $(stat -f %u /dev/console) /usr/bin/osascript -e "+strconv.Quote(script))
	default:
		// notify-send needs the logged-in user's bus. Best effort by
		// definition: a headless Linux host has nobody to notify anyway.
		cmd = exec.CommandContext(tctx, "/bin/sh", "-c",
			`u=$(who 2>/dev/null | awk 'NR==1{print $1}'); [ -n "$u" ] && `+
				`uid=$(id -u "$u") && DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus `+
				`sudo -u "$u" notify-send `+strconv.Quote(m.Title)+" "+strconv.Quote(m.Body))
	}

	if err := cmd.Run(); err != nil {
		a.logger.Debug("native toast unavailable, the Self Service window still has the message",
			"os", runtime.GOOS, "error", err)
	}
}

// answerNotification records what the person chose and tells the server.
// The answer is the point of the whole feature: a restart prompt nobody can
// prove was postponed twice is indistinguishable from one never shown.
func (a *Agent) answerNotification(ctx context.Context, action string, postponeMinutes int) string {
	msg, _ := a.notification.get()
	if msg == nil {
		return "there is no notification to answer"
	}

	detail := ""
	switch action {
	case "postponed":
		if !msg.AllowPostpone {
			return "this notification cannot be postponed"
		}
		if postponeMinutes <= 0 {
			postponeMinutes = 60
		}
		a.notification.postpone(time.Duration(postponeMinutes) * time.Minute)
		detail = "postponed for " + strconv.Itoa(postponeMinutes) + " minute(s)"
	case "acknowledged":
		a.notification.clear()
		detail = "acknowledged"
	case "restart_now":
		a.notification.clear()
		detail = "restart accepted by the user"
		go a.restartNow(context.WithoutCancel(ctx))
	case actionOpenSoftwareUpdate:
		a.notification.clear()
		detail = "opened Software Update to install the macOS update"
		go openSoftwareUpdate(context.WithoutCancel(ctx), a.logger)
	default:
		return "unknown response: " + action
	}

	a.reportActionResult(ctx, proto.AgentActionResult{
		RunID: msg.RunID, ActionID: msg.ActionID, Kind: "end_user_notification",
		OK: true, Detail: detail,
	})
	a.logger.Info("end-user notification answered", "action", action, "detail", detail)
	return ""
}

// restartNow reboots after a short grace period, so the answer reaches the
// server before the machine goes away. Reported first, restarted second --
// the other order loses the record of what the person chose.
func (a *Agent) restartNow(ctx context.Context) {
	time.Sleep(10 * time.Second)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("shutdown.exe", "/r", "/t", "30", "/f", "/c", "Restart requested from mustra Self Service")
	default:
		cmd = exec.Command("/bin/sh", "-c", "shutdown -r +1 'Restart requested from mustra Self Service'")
	}
	if err := cmd.Run(); err != nil {
		a.logger.Error("user-accepted restart failed", "error", err)
	}
}

// notificationForWindow is what the Self Service window renders. Returns nil
// when there is nothing to show, including while a postponement the person
// asked for is still running.
func (a *Agent) notificationForWindow() map[string]any {
	m := a.notification.visible()
	if m == nil {
		return nil
	}
	out := map[string]any{
		"id": m.ID, "kind": m.Kind, "title": m.Title, "body": m.Body,
		"allow_postpone": m.AllowPostpone, "postpone_minutes": m.PostponeMinutes,
	}
	// Only when the operator defined some. Absent means the window renders
	// the defaults for the kind, which is what every message sent by a
	// server too old to set this field looks like.
	if len(m.Buttons) > 0 {
		out["buttons"] = m.Buttons
	}
	if m.Deadline != nil {
		out["deadline"] = m.Deadline.Format(time.RFC3339)
		out["minutes_left"] = int(time.Until(*m.Deadline).Minutes())
	}
	if m.Kind == proto.EUNKindRestart {
		out["countdown_minutes"] = m.CountdownMinutes
	}
	return out
}
