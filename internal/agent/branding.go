package agent

import (
	"encoding/json"
	"sync"

	"github.com/mustra-dev/mustra/internal/proto"
)

// selfServiceBranding is the look of the Self Service window as the server
// last described it. Held here and in the store rather than fetched each
// time the window opens: the window should look like the organisation's on
// a machine that is offline, and the images are too large to resend on
// every state request (the server only sends them when the version moves).
type selfServiceBranding struct {
	mu      sync.RWMutex
	version string
	b       *proto.SelfServiceBranding
}

type storedBranding struct {
	Version  string                    `json:"version"`
	Branding proto.SelfServiceBranding `json:"branding"`
}

func (a *Agent) loadBranding() {
	raw, err := a.store.LoadBranding()
	if err != nil || len(raw) == 0 {
		return
	}
	var s storedBranding
	if json.Unmarshal(raw, &s) != nil || s.Version == "" {
		return
	}
	a.branding.mu.Lock()
	a.branding.version, a.branding.b = s.Version, &s.Branding
	a.branding.mu.Unlock()
}

func (a *Agent) brandingVersion() string {
	a.branding.mu.RLock()
	defer a.branding.mu.RUnlock()
	return a.branding.version
}

// brandingForWindow is what the window renders; nil means the built-in look.
func (a *Agent) brandingForWindow() *proto.SelfServiceBranding {
	a.branding.mu.RLock()
	defer a.branding.mu.RUnlock()
	return a.branding.b
}

// applyBranding takes the branding half of a state reply. Only a reply the
// server actually produced counts: an error reply from a timeout carries no
// version either, and reading that as "reset to default" would strip the
// branding from every window opened during an outage.
func (a *Agent) applyBranding(reply proto.SelfServiceReply) {
	if reply.Error != "" && reply.BrandingVersion == "" {
		return
	}
	a.branding.mu.Lock()
	defer a.branding.mu.Unlock()
	switch {
	case reply.BrandingVersion == a.branding.version:
		return
	case reply.BrandingVersion == "":
		a.branding.version, a.branding.b = "", nil
		_ = a.store.SaveBranding(nil)
	case reply.Branding != nil:
		a.branding.version, a.branding.b = reply.BrandingVersion, reply.Branding
		raw, err := json.Marshal(storedBranding{Version: reply.BrandingVersion, Branding: *reply.Branding})
		if err == nil {
			_ = a.store.SaveBranding(raw)
		}
		a.logger.Info("self service branding updated", "version", reply.BrandingVersion)
	}
}
