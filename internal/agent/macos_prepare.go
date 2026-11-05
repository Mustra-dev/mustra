package agent

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// On Apple Silicon macOS installs only with the password of a user who owns
// the disk. Without an MDM that can install it (Fleet's software update
// declarations need Fleet Premium), the agent tries to download the update and
// then asks the person at the Mac to install it: a notification whose Install
// button opens Software Update, where installing takes their password and a
// restart. The download can want that password too (macOS 27 answered "Failed
// to authenticate"), so the notification says which of the two happened.

// actionOpenSoftwareUpdate is the notification answer that opens Software
// Update for the person at the Mac.
const actionOpenSoftwareUpdate = "open_software_update"

// macOSDownloadTimeout bounds one download: a macOS update is 4-12 GB.
const macOSDownloadTimeout = 3 * time.Hour

// preparing holds the labels being downloaded, so a second patch run while
// one is still downloading does not start another.
var preparing sync.Map

func (a *Agent) prepareMacOSUpdate(ctx context.Context, runID, actionID string, u macUpdate) {
	if _, busy := preparing.LoadOrStore(u.Label, true); busy {
		return
	}
	defer preparing.Delete(u.Label)
	title := u.Name
	if title == "" {
		title = u.Label
	}
	dctx, cancel := context.WithTimeout(ctx, macOSDownloadTimeout)
	start := time.Now()
	out, err := exec.CommandContext(dctx, "softwareupdate", "--download", u.Label).CombinedOutput()
	cancel()
	downloaded := err == nil
	if downloaded {
		a.logger.Info("macOS update downloaded for the user to install", "update", title, "took", time.Since(start).Round(time.Second))
	} else {
		// Software Update downloads it itself when asked to install, so the
		// person is still asked; only the wait is longer.
		a.logger.Warn("macOS update download failed; asking the user to install it anyway",
			"update", title, "error", err, "output", lastLine(string(out), err))
	}
	heading, body := macOSUpdateMessage(title, downloaded)
	a.showNotification(ctx, &proto.EndUserNotification{
		ID:    "macos-update-" + strings.ReplaceAll(u.Label, " ", "-"),
		Kind:  proto.EUNKindNotice,
		Title: heading,
		Body:  body,
		Buttons: []proto.EUNButton{
			{Label: "Install…", Action: actionOpenSoftwareUpdate, Primary: true},
			{Label: "Later", Action: "postponed", Minutes: 240},
		},
		AllowPostpone:   true,
		PostponeMinutes: []int{60, 240, 1440},
		RunID:           runID,
		ActionID:        actionID,
	})
}

// macOSUpdateMessage says it is ready only when the download worked.
func macOSUpdateMessage(title string, downloaded bool) (heading, body string) {
	if downloaded {
		return title + " is ready to install",
			title + " has been downloaded. Install it from Software Update: it asks for your password, and the Mac restarts to finish, so save your work first."
	}
	return title + " is available",
		title + " is available. Install it from Software Update: it downloads the update, asks for your password, and restarts the Mac to finish."
}
