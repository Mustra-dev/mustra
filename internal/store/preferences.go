package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// UserPreferences is how one person wants the console to behave.
//
// Server-side rather than browser-side because one of these is a security
// control: an idle-timeout kept in localStorage is a control anyone can
// clear by opening a private window, which is no control at all. The rest
// ride along so a console follows its person between machines.
//
// PUT /api/preferences replaces the whole object: a field it leaves out
// returns to its default, and a custom palette or custom shortcuts left
// out are dropped. Read the preferences first and send them all back
// with the change, as the console does.
type UserPreferences struct {
	// ResultsCompletePercent is how much of the fleet must have answered
	// before a question's results are called complete. The default is
	// 99, and the reason it is not 100 is that one permanently unreachable
	// endpoint should not make every question look unfinished forever.
	ResultsCompletePercent int `json:"results_complete_percent"`
	// SignOutAfterMinutes signs an idle session out. 0 disables it.
	SignOutAfterMinutes int `json:"sign_out_after_minutes"`
	// Theme is "system", "light" or "dark".
	Theme string `json:"theme"`
	// Palette is the colour scheme: a preset ID from static/theme.js
	// ("mustra" is the built-in one), or "custom" for CustomPalette.
	Palette string `json:"palette"`
	// CustomPalette is the person's own colours, built in Preferences or
	// uploaded as a theme file. Kept while another palette is selected, so
	// switching back does not lose it.
	CustomPalette *CustomPalette `json:"custom_palette,omitempty"`
	// LandingPage is where signing in takes you.
	LandingPage string `json:"landing_page"`
	// HideErrorResults drops endpoints that errored from question results.
	HideErrorResults bool `json:"hide_error_results"`
	// Timestamps is "server" or "local": which clock every date in the
	// console is drawn on. Server is the default because the console is
	// read next to audit rows, agent logs and journalctl, and those are all
	// on the server's clock -- an operator comparing two of them should not
	// have to do arithmetic first.
	Timestamps string `json:"timestamps"`
	// ShowEnvironmentDetails draws the identity banner across the top —
	// who you are and which persona you are acting under. Worth having in a
	// console that can act on a whole fleet, and worth being able to turn
	// off when you are sharing your screen.
	ShowEnvironmentDetails bool `json:"show_environment_details"`
	// HomeDashboardID is the dashboard shown full-size on Home;
	// HomeDashboardList is up to five shown as micro-chart cards beneath
	// it. Empty means mustra picks (the first shared dashboards).
	HomeDashboardID   string   `json:"home_dashboard_id"`
	HomeDashboardList []string `json:"home_dashboard_list"`
	// HiddenModules are the Home module cards this person has put away,
	// by href. A hidden list rather than a shown one on purpose: a module
	// added in a later release then appears for everybody instead of
	// staying invisible to anyone who ever customised the grid.
	HiddenModules []string `json:"hidden_modules"`
	// Shortcuts are the account's own key combinations for the top bar's
	// search modes (ask, endpoints, dashboards, links), only where they
	// differ from the defaults the console ships with.
	Shortcuts map[string]string `json:"shortcuts,omitempty"`
}

// CustomPalette is a person's own colour scheme. Either mode may be
// missing, in which case that mode keeps the built-in colours.
type CustomPalette struct {
	Name  string         `json:"name"`
	Dark  *PaletteColors `json:"dark,omitempty"`
	Light *PaletteColors `json:"light,omitempty"`
}

// PaletteColors are the five seeds the console derives every surface
// colour from (see static/theme.js). Each is "#rrggbb".
type PaletteColors struct {
	Bg      string `json:"bg"`
	Surface string `json:"surface"`
	Text    string `json:"text"`
	Muted   string `json:"muted"`
	Accent  string `json:"accent"`
}

// DefaultUserPreferences are what someone gets before they have chosen
// anything.
func DefaultUserPreferences() UserPreferences {
	return UserPreferences{
		ResultsCompletePercent: 99,
		SignOutAfterMinutes:    180,
		Theme:                  "system",
		Palette:                "mustra",
		LandingPage:            "/",
		HideErrorResults:       true,
		ShowEnvironmentDetails: true,
		Timestamps:             "server",
	}
}

func (s *Store) GetUserPreferences(ctx context.Context, userID string) (UserPreferences, error) {
	prefs := DefaultUserPreferences()
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT prefs FROM user_preferences WHERE user_id = $1`, userID).Scan(&raw)
	if err != nil {
		// No row is the normal case for someone who has never opened
		// Preferences, so it returns the defaults rather than an error.
		return prefs, nil
	}
	// Decoded over the defaults, so a preference added after this row was
	// written gets its default rather than a zero value.
	_ = json.Unmarshal(raw, &prefs)
	return prefs, nil
}

func (s *Store) SetUserPreferences(ctx context.Context, userID string, prefs UserPreferences) error {
	raw, err := json.Marshal(prefs)
	if err != nil {
		return fmt.Errorf("encode preferences: %w", err)
	}
	const q = `
INSERT INTO user_preferences (user_id, prefs) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET prefs = EXCLUDED.prefs, updated_at = now()`
	if _, err := s.pool.Exec(ctx, q, userID, raw); err != nil {
		return fmt.Errorf("save preferences: %w", err)
	}
	return nil
}
