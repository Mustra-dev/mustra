package server

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

func (s *Server) handleGetPreferences(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r.Context())
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	prefs, err := s.store.GetUserPreferences(r.Context(), u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, prefs)
}

func (s *Server) handleSetPreferences(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r.Context())
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	prefs := store.DefaultUserPreferences()
	if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// Clamp rather than reject. These come from a form where a typo is far
	// more likely than an attack, and refusing the whole save because
	// somebody typed 300 into a percentage helps nobody.
	if prefs.ResultsCompletePercent < 1 {
		prefs.ResultsCompletePercent = 1
	}
	if prefs.Timestamps != "local" {
		prefs.Timestamps = "server"
	}
	if prefs.ResultsCompletePercent > 100 {
		prefs.ResultsCompletePercent = 100
	}
	if prefs.SignOutAfterMinutes < 0 {
		prefs.SignOutAfterMinutes = 0
	}
	// A day is already far past the point where an idle console is a
	// reasonable thing to leave signed in.
	if prefs.SignOutAfterMinutes > 1440 {
		prefs.SignOutAfterMinutes = 1440
	}
	switch prefs.Theme {
	case "light", "dark", "system":
	default:
		prefs.Theme = "system"
	}
	prefs.CustomPalette = cleanCustomPalette(prefs.CustomPalette)
	if !paletteID.MatchString(prefs.Palette) || (prefs.Palette == "custom" && prefs.CustomPalette == nil) {
		prefs.Palette = "mustra"
	}
	// A landing page is a redirect target, so it has to stay inside this
	// console: an absolute URL here would turn a preference into an
	// open-redirect that fires on every sign-in.
	prefs.LandingPage = auth.SafeNext(prefs.LandingPage)

	// Home shows one dashboard and up to five micro-chart cards.
	if len(prefs.HomeDashboardList) > 5 {
		prefs.HomeDashboardList = prefs.HomeDashboardList[:5]
	}
	if prefs.HomeDashboardList == nil {
		prefs.HomeDashboardList = []string{}
	}
	// Bounded so a malformed client cannot grow the row without limit;
	// there are fewer than a hundred cards to hide.
	if len(prefs.HiddenModules) > 300 {
		prefs.HiddenModules = prefs.HiddenModules[:300]
	}
	if prefs.HiddenModules == nil {
		prefs.HiddenModules = []string{}
	}

	prefs.Shortcuts = cleanShortcuts(prefs.Shortcuts)

	if err := s.store.SetUserPreferences(r.Context(), u.ID, prefs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, prefs)
}

// A palette ID names a preset in static/theme.js, which the browser looks
// up and falls back from when it does not know one. The server only keeps
// it to a shape that cannot carry anything but a name.
var paletteID = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

var paletteHex = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// cleanPaletteColors returns the colours lower-cased, or nil unless all
// five are #rrggbb. These end up as CSS custom property values, so nothing
// else may get through.
func cleanPaletteColors(c *store.PaletteColors) *store.PaletteColors {
	if c == nil {
		return nil
	}
	out := store.PaletteColors{}
	for _, f := range []struct {
		in  string
		out *string
	}{{c.Bg, &out.Bg}, {c.Surface, &out.Surface}, {c.Text, &out.Text}, {c.Muted, &out.Muted}, {c.Accent, &out.Accent}} {
		v := strings.ToLower(strings.TrimSpace(f.in))
		if !paletteHex.MatchString(v) {
			return nil
		}
		*f.out = v
	}
	return &out
}

// cleanCustomPalette drops a mode whose colours are not all valid, and the
// whole palette when neither mode survives.
func cleanCustomPalette(p *store.CustomPalette) *store.CustomPalette {
	if p == nil {
		return nil
	}
	out := &store.CustomPalette{Dark: cleanPaletteColors(p.Dark), Light: cleanPaletteColors(p.Light)}
	if out.Dark == nil && out.Light == nil {
		return nil
	}
	name := strings.TrimSpace(p.Name)
	if !utf8.ValidString(name) {
		name = ""
	}
	if utf8.RuneCountInString(name) > 40 {
		name = string([]rune(name)[:40])
	}
	if name == "" {
		name = "Custom"
	}
	out.Name = name
	return out
}

// shortcutKeys is a key combination as the console writes it: modifiers
// (Ctrl, Alt, Shift) then one key, joined with "+", at least one of Ctrl
// or Alt so a shortcut never swallows ordinary typing.
var shortcutKeys = regexp.MustCompile(`^(Ctrl\+|Alt\+)(Alt\+)?(Shift\+)?([A-Z0-9]|[/;'.,\[\]\\=` + "`" + `-]|F[1-9]|F1[0-2]|ArrowUp|ArrowDown|ArrowLeft|ArrowRight|Space|Enter)$`)

// cleanShortcuts keeps the top bar modes it knows, in a shape the console
// can draw and match, and drops a combination already taken by another.
func cleanShortcuts(in map[string]string) map[string]string {
	out := map[string]string{}
	taken := map[string]bool{}
	for _, mode := range []string{"ask", "endpoints", "dashboards", "links"} {
		k := in[mode]
		if k == "" || !shortcutKeys.MatchString(k) || taken[k] {
			continue
		}
		taken[k] = true
		out[mode] = k
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
