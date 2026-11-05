package agent

import (
	"strings"
	"testing"
)

// "Ready" is a claim about the download, so a failed one must not make it.
func TestMacOSUpdateMessageSaysReadyOnlyWhenDownloaded(t *testing.T) {
	heading, body := macOSUpdateMessage("macOS 27.2", true)
	if heading != "macOS 27.2 is ready to install" || !strings.Contains(body, "has been downloaded") {
		t.Errorf("downloaded: %q / %q", heading, body)
	}
	heading, body = macOSUpdateMessage("macOS 27.2", false)
	if strings.Contains(heading, "ready") || strings.Contains(body, "has been downloaded") {
		t.Errorf("not downloaded: %q / %q", heading, body)
	}
	if !strings.Contains(body, "downloads the update") {
		t.Errorf("not downloaded: %q", body)
	}
}
