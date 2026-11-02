package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/selfservice"
	"github.com/mustra-dev/mustra/internal/server/auth"
)

// Self Service branding: how the window on every endpoint looks. Stored as
// one JSON setting, validated here, and handed to agents on their state
// request only when it has changed (see proto.SelfServiceRequest's
// BrandingVersion). Agents keep the last copy, so a window opened while the
// server is unreachable still looks like the organisation's, not mustra's.

const settingSelfServiceBranding = "selfservice.branding"

// Image limits. Both travel to every endpoint once per change and are held
// by every agent, so they are sized for a logo and a wallpaper rather than
// for whatever someone happens to drag in. The console downsizes before
// uploading; these are the backstop.
const (
	maxSelfServiceLogoBytes       = 256 * 1024
	maxSelfServiceBackgroundBytes = 1024 * 1024
	maxSelfServiceCSSBytes        = 32 * 1024
)

var (
	selfServiceTabIDs   = []string{"catalog", "updates", "history", "activity", "device"}
	hexColour           = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	selfServiceThemes   = map[string]bool{"": true, "dark": true, "light": true, "system": true}
	selfServiceFonts    = map[string]bool{"": true, "system": true, "segoe": true, "serif": true, "rounded": true, "mono": true}
	selfServicePatterns = map[string]bool{"": true, "waves": true, "contours": true, "dots": true,
		"grid": true, "none": true, "image": true}
	selfServiceBgFits      = map[string]bool{"": true, "cover": true, "contain": true, "tile": true, "center": true}
	selfServiceBgPositions = map[string]bool{"": true, "center": true, "top": true, "bottom": true, "left": true, "right": true}
)

// normalizeSelfServiceBranding trims, checks and canonicalises a branding
// as an operator submitted it. Canonical matters: the version is a hash of
// the result, and two saves of the same look must not roll the fleet.
func normalizeSelfServiceBranding(b proto.SelfServiceBranding) (proto.SelfServiceBranding, error) {
	text := []struct {
		name  string
		field *string
		max   int
	}{
		{"window title", &b.WindowTitle, 80},
		{"organization name", &b.OrgName, 120},
		{"welcome message", &b.Welcome, 1000},
		{"help heading", &b.HelpHeading, 60},
		{"help link text", &b.HelpText, 120},
		{"help link", &b.HelpURL, 500},
		{"empty activity message", &b.ActivityEmpty, 200},
	}
	for _, t := range text {
		*t.field = strings.TrimSpace(*t.field)
		if len([]rune(*t.field)) > t.max {
			return b, fmt.Errorf("the %s is longer than %d characters", t.name, t.max)
		}
	}
	if b.HelpURL != "" {
		u, err := url.Parse(b.HelpURL)
		if err != nil || u.Host == "" && u.Scheme != "mailto" {
			return b, fmt.Errorf("the help link must be a full URL (https://…) or a mailto: address")
		}
		// javascript: in an href would run in the window's origin, which is
		// the agent's loopback API. Only schemes that leave the page.
		if s := strings.ToLower(u.Scheme); s != "https" && s != "http" && s != "mailto" {
			return b, fmt.Errorf("the help link must be http, https or mailto")
		}
	}

	b.Theme = strings.ToLower(strings.TrimSpace(b.Theme))
	if !selfServiceThemes[b.Theme] {
		return b, fmt.Errorf("unknown theme %q", b.Theme)
	}
	b.Font = strings.ToLower(strings.TrimSpace(b.Font))
	if !selfServiceFonts[b.Font] {
		return b, fmt.Errorf("unknown font %q", b.Font)
	}
	b.Pattern = strings.ToLower(strings.TrimSpace(b.Pattern))
	if !selfServicePatterns[b.Pattern] {
		return b, fmt.Errorf("unknown background pattern %q", b.Pattern)
	}
	for _, c := range []struct {
		name  string
		field *string
	}{{"accent", &b.Accent}, {"background", &b.Background}, {"sidebar", &b.Sidebar},
		{"surface", &b.Surface}, {"text", &b.Text}} {
		*c.field = strings.ToLower(strings.TrimSpace(*c.field))
		if *c.field != "" && !hexColour.MatchString(*c.field) {
			return b, fmt.Errorf("the %s colour must look like #1a2b3c", c.name)
		}
	}
	if b.Radius != nil && (*b.Radius < 0 || *b.Radius > 24) {
		return b, fmt.Errorf("corner radius must be between 0 and 24")
	}
	if b.PatternOpacity != nil && (*b.PatternOpacity < 0 || *b.PatternOpacity > 100) {
		return b, fmt.Errorf("pattern intensity must be between 0 and 100")
	}

	if b.LogoDataURL != "" {
		if _, _, err := parseImageDataURL(b.LogoDataURL, maxSelfServiceLogoBytes); err != nil {
			return b, fmt.Errorf("logo: %w", err)
		}
	}
	if b.BackgroundDataURL != "" {
		if _, _, err := parseImageDataURL(b.BackgroundDataURL, maxSelfServiceBackgroundBytes); err != nil {
			return b, fmt.Errorf("background image: %w", err)
		}
	}
	b.BackgroundFit = strings.ToLower(strings.TrimSpace(b.BackgroundFit))
	if !selfServiceBgFits[b.BackgroundFit] {
		return b, fmt.Errorf("unknown background image fit %q", b.BackgroundFit)
	}
	b.BackgroundPosition = strings.ToLower(strings.TrimSpace(b.BackgroundPosition))
	if !selfServiceBgPositions[b.BackgroundPosition] {
		return b, fmt.Errorf("unknown background image position %q", b.BackgroundPosition)
	}
	if b.BackgroundBlur != nil && (*b.BackgroundBlur < 0 || *b.BackgroundBlur > 20) {
		return b, fmt.Errorf("background blur must be between 0 and 20")
	}
	// The defaults are stored as nothing, so choosing them does not make a
	// new version and roll the fleet for a look that did not change.
	if b.BackgroundFit == "cover" {
		b.BackgroundFit = ""
	}
	if b.BackgroundPosition == "center" {
		b.BackgroundPosition = ""
	}
	if b.BackgroundBlur != nil && *b.BackgroundBlur == 0 {
		b.BackgroundBlur = nil
	}
	if b.Pattern == "image" && b.BackgroundDataURL == "" {
		return b, fmt.Errorf("the background is set to an image, but no image was uploaded")
	}
	if len(b.CustomCSS) > maxSelfServiceCSSBytes {
		return b, fmt.Errorf("custom CSS is over %d KB", maxSelfServiceCSSBytes/1024)
	}
	b.CustomCSS = strings.TrimSpace(b.CustomCSS)

	// Tabs: every known tab exactly once, in the operator's order, with any
	// the submission left out appended in the default order. A window with
	// a tab missing from the list would have no way to show it.
	seen := map[string]bool{}
	var tabs []proto.SelfServiceTab
	for _, t := range b.Tabs {
		t.ID = strings.ToLower(strings.TrimSpace(t.ID))
		t.Label = strings.TrimSpace(t.Label)
		if !validSelfServiceTab(t.ID) {
			return b, fmt.Errorf("unknown tab %q", t.ID)
		}
		if seen[t.ID] {
			return b, fmt.Errorf("tab %q is listed twice", t.ID)
		}
		if len([]rune(t.Label)) > 40 {
			return b, fmt.Errorf("tab label %q is longer than 40 characters", t.Label)
		}
		seen[t.ID] = true
		tabs = append(tabs, t)
	}
	for _, id := range selfServiceTabIDs {
		if !seen[id] {
			tabs = append(tabs, proto.SelfServiceTab{ID: id})
		}
	}
	visible := 0
	for _, t := range tabs {
		if !t.Hidden {
			visible++
		}
	}
	if visible == 0 {
		return b, fmt.Errorf("at least one tab has to be shown")
	}
	b.Tabs = tabs
	if b.DefaultTab != "" {
		b.DefaultTab = strings.ToLower(strings.TrimSpace(b.DefaultTab))
		ok := false
		for _, t := range tabs {
			if t.ID == b.DefaultTab && !t.Hidden {
				ok = true
			}
		}
		if !ok {
			return b, fmt.Errorf("the window can't open on a tab that is hidden")
		}
	}
	return b, nil
}

func validSelfServiceTab(id string) bool {
	for _, v := range selfServiceTabIDs {
		if v == id {
			return true
		}
	}
	return false
}

// selfServiceBrandingVersion is the content hash agents compare against.
// The zero branding has no version: "" means the built-in look, and is what
// an agent holding a stale copy is told when an operator resets it.
func selfServiceBrandingVersion(b proto.SelfServiceBranding) string {
	raw, _ := json.Marshal(b)
	if string(raw) == "{}" {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// isDefaultSelfServiceBranding reports whether a normalised branding says
// nothing but the default tab list, which is how "reset" arrives. Stored as
// empty, so resetting the look gives the fleet version "" again rather
// than a new hash of the defaults.
func isDefaultSelfServiceBranding(b proto.SelfServiceBranding) bool {
	if len(b.Tabs) != len(selfServiceTabIDs) {
		return false
	}
	for i, t := range b.Tabs {
		if t != (proto.SelfServiceTab{ID: selfServiceTabIDs[i]}) {
			return false
		}
	}
	b.Tabs = nil
	raw, _ := json.Marshal(b)
	return string(raw) == "{}"
}

// loadSelfServiceBranding reads the stored branding. A row that no longer
// validates (a rule tightened since it was saved) falls back to the default
// look and says so, rather than shipping something the rules now refuse.
func (s *Server) loadSelfServiceBranding(ctx context.Context) (proto.SelfServiceBranding, string) {
	raw, err := s.store.GetSetting(ctx, settingSelfServiceBranding)
	if err != nil || strings.TrimSpace(raw) == "" {
		return proto.SelfServiceBranding{}, ""
	}
	var stored proto.SelfServiceBranding
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		s.logger.Warn("stored Self Service branding is unreadable; using the default", "error", err)
		return proto.SelfServiceBranding{}, ""
	}
	b, err := normalizeSelfServiceBranding(stored)
	if err != nil {
		s.logger.Warn("stored Self Service branding no longer validates; using the default", "error", err)
		return proto.SelfServiceBranding{}, ""
	}
	return b, selfServiceBrandingVersion(b)
}

// selfServiceBrandingReply fills in the branding half of a state reply.
func (s *Server) selfServiceBrandingReply(ctx context.Context, reply *proto.SelfServiceReply, have string) {
	b, v := s.loadSelfServiceBranding(ctx)
	reply.BrandingVersion = v
	if v != "" && v != have {
		reply.Branding = &b
	}
}

// selfServiceBrandingResponse is what GET and PUT /api/selfservice/branding
// answer.
type selfServiceBrandingResponse struct {
	Branding proto.SelfServiceBranding `json:"branding"`
	Version  string                    `json:"version"`
}

func (s *Server) handleGetSelfServiceBranding(w http.ResponseWriter, r *http.Request) {
	b, v := s.loadSelfServiceBranding(r.Context())
	writeJSONResponse(w, selfServiceBrandingResponse{Branding: b, Version: v})
}

func (s *Server) handleUpdateSelfServiceBranding(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var in proto.SelfServiceBranding
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	b, err := normalizeSelfServiceBranding(in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	value := ""
	if !isDefaultSelfServiceBranding(b) {
		raw, _ := json.Marshal(b)
		value = string(raw)
	} else {
		b = proto.SelfServiceBranding{}
	}
	u := auth.CurrentUser(r.Context())
	if err := s.store.SetSetting(r.Context(), settingSelfServiceBranding, value, u.Username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v := selfServiceBrandingVersion(b)
	// Every endpoint's Self Service window shows what this sets.
	s.audit(r.Context(), auditEvent{
		Action: "selfservice.branding_update", Actor: u.Username, Target: "Self Service branding", Severity: "notice",
		Detail: map[string]any{"version": v, "default": value == ""},
	})
	writeJSONResponse(w, selfServiceBrandingResponse{Branding: b, Version: v})
}

// handleSelfServicePreview serves the endpoint window itself, switched into
// preview mode, for the console's Appearance editor to frame.
//
// Under a nonce CSP like the endpoint serves it with (internal/agent
// selfservice_guard.go): it renders operator-supplied branding, and only
// the window's own scripts may run.
func handleSelfServicePreview(w http.ResponseWriter, r *http.Request) {
	nonce := newID("")
	w.Header().Set("Content-Security-Policy", selfservice.CSP(nonce, "'self'"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Write(selfservice.WithNonce(selfservice.PreviewHTML(), nonce))
}
