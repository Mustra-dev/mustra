package server

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

type paletteSeeds struct {
	Bg, Surface, Text, Muted, Accent, Button, Series string
	Categorical                                      []string
}

func themePresets(t *testing.T) map[string]struct {
	Name  string
	Dark  paletteSeeds
	Light paletteSeeds
} {
	t.Helper()
	js, err := staticFS.ReadFile("static/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)
	start := strings.Index(src, "/*palettes-begin*/")
	end := strings.Index(src, "/*palettes-end*/")
	if start < 0 || end < start {
		t.Fatal("theme.js has lost its palette markers")
	}
	var out map[string]struct {
		Name  string
		Dark  paletteSeeds
		Light paletteSeeds
	}
	if err := json.Unmarshal([]byte(src[start+len("/*palettes-begin*/"):end]), &out); err != nil {
		t.Fatalf("theme.js palettes are not strict JSON: %v", err)
	}
	return out
}

func relLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	if !paletteHex.MatchString(hex) {
		t.Fatalf("%q is not #rrggbb", hex)
	}
	var sum float64
	for i, w := range []float64{0.2126, 0.7152, 0.0722} {
		v, _ := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		c := float64(v) / 255
		if c <= 0.03928 {
			c /= 12.92
		} else {
			c = math.Pow((c+0.055)/1.055, 2.4)
		}
		sum += w * c
	}
	return sum
}

func contrastRatio(t *testing.T, a, b string) float64 {
	x, y := relLuminance(t, a), relLuminance(t, b)
	return (math.Max(x, y) + 0.05) / (math.Min(x, y) + 0.05)
}

// Every preset palette is readable in both modes: body text, muted text and
// links clear WCAG AA (4.5:1) on both the page and the cards.
func TestThemePresetsAreReadable(t *testing.T) {
	presets := themePresets(t)
	if _, ok := presets["mustra"]; !ok {
		t.Fatal(`the built-in "mustra" palette is missing`)
	}
	if len(presets) < 8 {
		t.Fatalf("only %d presets", len(presets))
	}
	for id, p := range presets {
		if !paletteID.MatchString(id) || id == "custom" {
			t.Errorf("preset id %q would not survive the preferences API", id)
		}
		if p.Name == "" {
			t.Errorf("%s has no name", id)
		}
		for mode, s := range map[string]paletteSeeds{"dark": p.Dark, "light": p.Light} {
			for _, c := range []struct {
				fg, bg, what string
			}{
				{s.Text, s.Bg, "text on page"}, {s.Text, s.Surface, "text on cards"},
				{s.Muted, s.Bg, "muted on page"}, {s.Muted, s.Surface, "muted on cards"},
				{s.Accent, s.Bg, "accent on page"}, {s.Accent, s.Surface, "accent on cards"},
			} {
				if r := contrastRatio(t, c.fg, c.bg); r < 4.5 {
					t.Errorf("%s/%s: %s is %.2f:1, below 4.5:1", id, mode, c.what, r)
				}
			}
			// Chart colours are marks, not text: 3:1 against the cards they
			// sit on (WCAG 1.4.11). The categorical order is eight slots
			// exactly, the number charts.js cycles through.
			if s.Series != "" {
				if r := contrastRatio(t, s.Series, s.Surface); r < 3 {
					t.Errorf("%s/%s: series bars are %.2f:1 on cards, below 3:1", id, mode, r)
				}
			}
			if s.Categorical != nil {
				if len(s.Categorical) != 8 {
					t.Errorf("%s/%s: %d categorical colours, want 8", id, mode, len(s.Categorical))
				}
				for _, c := range s.Categorical {
					if !paletteHex.MatchString(c) {
						t.Errorf("%s/%s: categorical %q is not #rrggbb", id, mode, c)
					}
				}
			}
			// The primary fill (the button colour, else the accent) carries
			// its label in whichever of black or white reads better on it.
			fill := s.Accent
			if s.Button != "" {
				fill = s.Button
			}
			if r := math.Max(contrastRatio(t, "#000000", fill), contrastRatio(t, "#ffffff", fill)); r < 4.5 {
				t.Errorf("%s/%s: primary button label is %.2f:1, below 4.5:1", id, mode, r)
			}
		}
	}
}

// Every console page loads theme.js in its <head>, so no page paints in a
// theme other than the one chosen; the per-page copies are gone.
func TestEveryPageLoadsTheTheme(t *testing.T) {
	entries, err := staticFS.ReadDir("static")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		b, _ := staticFS.ReadFile("static/" + e.Name())
		page := string(b)
		head := page
		if i := strings.Index(page, "</head>"); i >= 0 {
			head = page[:i]
		}
		if !strings.Contains(head, `<script src="/static/theme.js"></script>`) {
			t.Errorf("%s does not load theme.js in its <head>", e.Name())
		}
		if strings.Contains(page, `localStorage.getItem("mustra-theme")`) {
			t.Errorf("%s still carries its own theme snippet", e.Name())
		}
		n++
	}
	if n < 30 {
		t.Fatalf("checked only %d pages", n)
	}
}

func TestCleanCustomPalette(t *testing.T) {
	good := &store.PaletteColors{Bg: "#0A0B0C", Surface: "#111111", Text: "#eeeeee", Muted: "#999999", Accent: " #ff00aa "}
	got := cleanCustomPalette(&store.CustomPalette{Name: strings.Repeat("x", 60), Dark: good,
		Light: &store.PaletteColors{Bg: "red", Surface: "#fff", Text: "#000000", Muted: "#000000", Accent: "#000000"}})
	if got == nil || got.Dark == nil {
		t.Fatal("a valid dark mode was dropped")
	}
	if got.Dark.Bg != "#0a0b0c" || got.Dark.Accent != "#ff00aa" {
		t.Errorf("colours not normalised: %+v", got.Dark)
	}
	if got.Light != nil {
		t.Errorf("an invalid light mode survived: %+v", got.Light)
	}
	if len([]rune(got.Name)) != 40 {
		t.Errorf("name not capped at 40: %d", len([]rune(got.Name)))
	}
	for _, evil := range []string{"#fff;--x:1", "url(x)", "#12345g", "var(--bg)", ""} {
		c := *good
		c.Muted = evil
		if cleanCustomPalette(&store.CustomPalette{Dark: &c}) != nil {
			t.Errorf("%q accepted as a colour", evil)
		}
	}
	if p := cleanCustomPalette(&store.CustomPalette{Dark: good}); p.Name != "Custom" {
		t.Errorf("empty name became %q", p.Name)
	}
	for _, id := range []string{"midnight", "custom", "a-1"} {
		if !paletteID.MatchString(id) {
			t.Errorf("%q refused", id)
		}
	}
	for _, id := range []string{"", "Mid", "x y", "<b>", strings.Repeat("a", 33)} {
		if paletteID.MatchString(id) {
			t.Errorf("%q accepted as a palette id", id)
		}
	}
}
