// Theme: light/dark mode and colour palette.
//
// Loaded in every page's <head>, before the stylesheet paints anything, so a
// page never flashes the wrong theme on its way to the right one. It reads
// the last choice from localStorage (a cache: the real preference lives on
// the account, and app.js re-applies it from /api/preferences once that has
// loaded), and app.js calls mustraTheme.set() whenever the choice changes.
//
// A palette is five seed colours per mode: page background, card surface,
// text, muted text and accent. Every other token app.css defines for the
// surface family (raised surfaces, borders, hover rows, chrome, the primary
// button) is derived from those five, so a palette — a preset or one a
// person built or uploaded — can only ever be a complete theme. Status
// colours (ok / warning / critical) are never themed: they mean the same
// thing everywhere. "mustra" applies nothing and leaves app.css's own
// hand-tuned tokens in place.
(function () {
  "use strict";

  // Strict JSON between the markers: theme_palettes_test.go reads it and
  // checks every preset's contrast, so a new one cannot ship unreadable.
  var PALETTES = /*palettes-begin*/{
  "mustra": {"name": "Mustra", "dark": {"bg": "#121820", "surface": "#1d2939", "text": "#dcdfe6", "muted": "#9aa4b5", "accent": "#66b8ff"}, "light": {"bg": "#f5f7fa", "surface": "#ffffff", "text": "#1a2230", "muted": "#5b6474", "accent": "#0f6cbd"}},
  "navy": {"name": "Navy", "dark": {"bg": "#121820", "surface": "#2a3546", "text": "#dcdfe6", "muted": "#a3adbd", "accent": "#66b8ff"}, "light": {"bg": "#f5f7fa", "surface": "#ffffff", "text": "#1a2230", "muted": "#5b6474", "accent": "#105b94"}},
  "midnight": {"name": "Midnight", "dark": {"bg": "#0b0d17", "surface": "#131726", "text": "#e6e8f2", "muted": "#9aa0b8", "accent": "#8b9cff"}, "light": {"bg": "#f5f6fb", "surface": "#ffffff", "text": "#12142a", "muted": "#5b6078", "accent": "#4353e0"}},
  "aurora": {"name": "Aurora", "dark": {"bg": "#06120f", "surface": "#0d1c18", "text": "#e2f2ec", "muted": "#8fb3a7", "accent": "#3ee6b0"}, "light": {"bg": "#f2faf7", "surface": "#ffffff", "text": "#0b1f19", "muted": "#4f6b62", "accent": "#0b7a5c"}},
  "synthwave": {"name": "Synthwave", "dark": {"bg": "#120a1f", "surface": "#1c1230", "text": "#f2e9ff", "muted": "#b4a2cf", "accent": "#ff5fd2"}, "light": {"bg": "#fbf6ff", "surface": "#ffffff", "text": "#1f0f33", "muted": "#6c5a85", "accent": "#b0198a"}},
  "ember": {"name": "Ember", "dark": {"bg": "#120c08", "surface": "#1c1410", "text": "#f5ebe4", "muted": "#b9a497", "accent": "#ff8a3d"}, "light": {"bg": "#fdf8f4", "surface": "#ffffff", "text": "#24160d", "muted": "#6f5a4c", "accent": "#b8500f"}},
  "glacier": {"name": "Glacier", "dark": {"bg": "#1e222a", "surface": "#262b35", "text": "#e5e9f0", "muted": "#a3acbd", "accent": "#88c0d0"}, "light": {"bg": "#eceff4", "surface": "#ffffff", "text": "#2e3440", "muted": "#5b6475", "accent": "#3b6e9a"}},
  "rose": {"name": "Rosé", "dark": {"bg": "#140b0f", "surface": "#1f1218", "text": "#f8e8ee", "muted": "#c09fac", "accent": "#ff7aa8"}, "light": {"bg": "#fff7f9", "surface": "#ffffff", "text": "#2a0f1a", "muted": "#7a5562", "accent": "#c0255f"}},
  "nightshade": {"name": "Nightshade", "dark": {"bg": "#191a21", "surface": "#22232c", "text": "#f8f8f2", "muted": "#a6a8bf", "accent": "#bd93f9"}, "light": {"bg": "#f7f5fc", "surface": "#ffffff", "text": "#1d1b2a", "muted": "#605c78", "accent": "#7240c9"}},
  "ocean": {"name": "Ocean", "dark": {"bg": "#031421", "surface": "#0a2133", "text": "#e3f1fb", "muted": "#8fb0c7", "accent": "#38bdf8"}, "light": {"bg": "#f1f8fd", "surface": "#ffffff", "text": "#0a2133", "muted": "#4c6a80", "accent": "#0369a1"}},
  "solar": {"name": "Solar", "dark": {"bg": "#002b36", "surface": "#073642", "text": "#eee8d5", "muted": "#9fb0b0", "accent": "#f0b429"}, "light": {"bg": "#fdf6e3", "surface": "#fffbef", "text": "#073642", "muted": "#586e75", "accent": "#8a5a00"}},
  "terminal": {"name": "Terminal", "dark": {"bg": "#050805", "surface": "#0c140c", "text": "#d9f7d9", "muted": "#8fb08f", "accent": "#7cff6b"}, "light": {"bg": "#f5fbf4", "surface": "#ffffff", "text": "#0d1f0b", "muted": "#4f6b4c", "accent": "#2f7d1f"}},
  "slate": {"name": "Slate", "dark": {"bg": "#1d2939", "surface": "#2a3546", "text": "#e8edf3", "muted": "#a9b6c8", "accent": "#66b8e6", "button": "#105b94"}, "light": {"bg": "#eef1f5", "surface": "#ffffff", "text": "#1b2533", "muted": "#55627a", "accent": "#0f5c99", "button": "#105b94"}},
  "modern": {"name": "Modern", "dark": {"bg": "#181818", "surface": "#1f1f1f", "text": "#cccccc", "muted": "#9d9d9d", "accent": "#4daafc", "button": "#0078d4", "series": "#3794ff", "categorical": ["#3794ff", "#9d9a37", "#8e4d8a", "#0b9f88", "#a04e2a", "#33a1d2", "#c5031f", "#669a4e"]}, "light": {"bg": "#f8f8f8", "surface": "#ffffff", "text": "#3b3b3b", "muted": "#616161", "accent": "#005fb8", "button": "#005fb8", "series": "#1a85ff", "categorical": ["#1a85ff", "#8e8b24", "#9b5896", "#1fb097", "#9a4824", "#007fac", "#a70419", "#63974b"]}},
  "graphite": {"name": "Graphite", "dark": {"bg": "#0e0e10", "surface": "#18181b", "text": "#f4f4f5", "muted": "#a1a1aa", "accent": "#e4e4e7"}, "light": {"bg": "#f4f4f5", "surface": "#ffffff", "text": "#18181b", "muted": "#63636b", "accent": "#3f3f46"}}
}/*palettes-end*/;

  var MODE_KEY = "mustra-theme";
  var PALETTE_KEY = "mustra-palette";
  var HEX = /^#[0-9a-f]{6}$/;
  var SEEDS = ["bg", "surface", "text", "muted", "accent"];

  function rgb(h) { return [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)]; }
  function hex(c) {
    return "#" + c.map(function (v) {
      v = Math.round(Math.max(0, Math.min(255, v)));
      return (v < 16 ? "0" : "") + v.toString(16);
    }).join("");
  }
  // Per-channel sRGB mix, the same as CSS color-mix(in srgb, a, b t).
  function mix(a, b, t) {
    var x = rgb(a), y = rgb(b);
    return hex([0, 1, 2].map(function (i) { return x[i] + (y[i] - x[i]) * t; }));
  }
  function luminance(h) {
    var w = [0.2126, 0.7152, 0.0722];
    return rgb(h).reduce(function (sum, c, i) {
      c /= 255;
      return sum + w[i] * (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
    }, 0);
  }
  // WCAG 2 contrast ratio, 1 to 21.
  function contrast(a, b) {
    var x = luminance(a), y = luminance(b);
    return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
  }

  // A palette's colours for one mode, or null unless all five are #rrggbb.
  function validSeeds(s) {
    if (!s || typeof s !== "object") return null;
    var out = {};
    for (var i = 0; i < SEEDS.length; i++) {
      var v = String(s[SEEDS[i]] == null ? "" : s[SEEDS[i]]).trim().toLowerCase();
      if (!HEX.test(v)) return null;
      out[SEEDS[i]] = v;
    }
    return out;
  }

  // The tokens one mode's seeds produce. Field edges get the smallest mix
  // toward the text colour that still clears 3:1 against both the card and
  // the page, which is what WCAG asks of a control's boundary.
  function derive(s, mode) {
    var dark = mode === "dark";
    var input = s.text;
    for (var t = 0.35; t < 1; t += 0.05) {
      var c = mix(s.surface, s.text, t);
      if (contrast(c, s.surface) >= 3 && contrast(c, s.bg) >= 3) { input = c; break; }
    }
    var chrome = dark ? s.bg : s.surface;
    var border = mix(s.surface, s.text, 0.12);
    var v = {
      "--bg": s.bg,
      "--surface": s.surface,
      "--surface-2": mix(s.surface, s.text, 0.05),
      "--surface-3": mix(s.surface, s.text, 0.09),
      "--border": border,
      "--border-strong": mix(s.surface, s.text, 0.2),
      "--border-input": input,
      "--input-bg": dark ? s.bg : s.surface,
      "--text": s.text,
      "--text-muted": s.muted,
      "--accent": s.accent,
      "--accent-text": contrast("#000000", s.accent) >= contrast("#ffffff", s.accent) ? "#000000" : "#ffffff",
      "--focus": s.accent,
      "--viz-series": s.series || s.accent,
      // The primary action is filled with the accent, not the text colour:
      // a text-coloured fill read as a blank white slab on dark palettes.
      "--primary": s.accent,
      "--primary-hover": mix(s.accent, s.text, 0.15),
      "--primary-text": contrast("#000000", s.accent) >= contrast("#ffffff", s.accent) ? "#000000" : "#ffffff",
      "--row-hover": mix(s.surface, s.text, 0.04),
      "--chrome-bg": chrome,
      "--chrome-hover": mix(chrome, s.text, 0.06),
      "--chrome-active-bg": mix(chrome, s.text, 0.1)
    };
    // A preset may name a sixth colour, "button": a primary fill other
    // than the accent. Custom palettes keep to the five seeds.
    if (s.button) {
      v["--primary"] = s.button;
      v["--primary-hover"] = mix(s.button, s.text, 0.15);
      v["--primary-text"] = contrast("#000000", s.button) >= contrast("#ffffff", s.button) ? "#000000" : "#ffffff";
    }
    if (s.categorical) s.categorical.forEach(function (c, i) { v["--viz-cat-" + (i + 1)] = c; });
    if (dark) v["--shadow-pop"] = "0 0 0 1px " + border + ", 0 16px 40px rgba(0, 0, 0, 0.7)";
    return v;
  }

  // Readability problems with one mode's seeds, worst first, for the
  // custom editor to show while someone picks colours.
  function problems(s) {
    var out = [];
    function need(a, b, min, what) {
      var r = contrast(s[a], s[b]);
      if (r < min) out.push({ ratio: r, message: what + " is " + r.toFixed(1) + ":1 (needs " + min + ":1)" });
    }
    need("text", "surface", 4.5, "Text on cards");
    need("text", "bg", 4.5, "Text on the page");
    need("muted", "surface", 4.5, "Muted text on cards");
    need("accent", "surface", 4.5, "Links on cards");
    need("accent", "bg", 3, "Accent on the page");
    return out.sort(function (a, b) { return a.ratio - b.ratio; });
  }

  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  var current = { mode: "system", palette: { id: "mustra" } };
  var applied = [];

  function normMode(m) { return m === "light" || m === "dark" ? m : "system"; }
  function normPalette(p) { return p && typeof p.id === "string" ? p : { id: "mustra" }; }
  function effectiveMode(mode) {
    mode = normMode(mode == null ? current.mode : mode);
    return mode === "system" ? (mq && mq.matches ? "dark" : "light") : mode;
  }
  function seedsFor(palette, mode) {
    if (!palette || palette.id === "mustra") return null;
    if (palette.id === "custom") return validSeeds((palette.custom || {})[mode]);
    var p = Object.prototype.hasOwnProperty.call(PALETTES, palette.id) ? PALETTES[palette.id] : null;
    if (!p) return null;
    var seeds = validSeeds(p[mode]);
    if (seeds && HEX.test(p[mode].button || "")) seeds.button = p[mode].button;
    // Presets may also colour the charts: "series" fills single-series bars
    // (otherwise the accent), "categorical" is the eight-slot order dashboard
    // charts use. Both were run through the palette validator's colour-
    // vision checks; custom palettes keep to the five seeds.
    if (seeds && HEX.test(p[mode].series || "")) seeds.series = p[mode].series;
    var cat = p[mode].categorical;
    if (seeds && Array.isArray(cat) && cat.length === 8 && cat.every(function (c) { return HEX.test(c); })) seeds.categorical = cat.slice();
    return seeds;
  }

  function paint(state) {
    var root = document.documentElement;
    if (state.mode === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", state.mode);
    for (var i = 0; i < applied.length; i++) root.style.removeProperty(applied[i]);
    applied = [];
    var mode = effectiveMode(state.mode);
    var seeds = seedsFor(state.palette, mode);
    if (!seeds) { root.removeAttribute("data-palette"); return; }
    var vars = derive(seeds, mode);
    for (var k in vars) { root.style.setProperty(k, vars[k]); applied.push(k); }
    root.setAttribute("data-palette", state.palette.id);
  }

  // paintSmooth paints a change of look as one short cross-fade instead of
  // every surface snapping at once (a full-screen brightness jump). Only
  // for a change someone made after the page loaded, only when the look
  // really changes, and never under reduced motion.
  var painted = "";
  function look(state) { return effectiveMode(state.mode) + "|" + JSON.stringify(state.palette); }
  function paintSmooth(state) {
    var next = look(state), changed = painted !== "" && next !== painted;
    painted = next;
    var still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (changed && !still && document.startViewTransition && document.readyState === "complete") {
      document.startViewTransition(function () { paint(state); });
    } else {
      paint(state);
    }
  }

  function readCache() {
    var state = { mode: "system", palette: { id: "mustra" } };
    try { state.mode = normMode(localStorage.getItem(MODE_KEY)); } catch (e) {}
    try { state.palette = normPalette(JSON.parse(localStorage.getItem(PALETTE_KEY) || "null")); } catch (e) {}
    return state;
  }

  // Apply and remember a choice. app.js calls this with the account's
  // preference on every page load and whenever it changes.
  function set(mode, palette) {
    current = { mode: normMode(mode), palette: normPalette(palette) };
    try {
      if (current.mode === "system") localStorage.removeItem(MODE_KEY);
      else localStorage.setItem(MODE_KEY, current.mode);
      if (current.palette.id === "mustra") localStorage.removeItem(PALETTE_KEY);
      else localStorage.setItem(PALETTE_KEY, JSON.stringify(current.palette));
    } catch (e) {}
    paintSmooth(current);
  }

  // Show a choice without remembering it (the Preferences dialog's live
  // preview); revert() puts back whatever was last set.
  function preview(mode, palette) { paintSmooth({ mode: normMode(mode), palette: normPalette(palette) }); }
  function revert() { paintSmooth(current); }

  current = readCache();
  paintSmooth(current);
  if (mq) {
    var onChange = function () { paintSmooth(current); };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }
  // Another tab changed it: follow along.
  window.addEventListener("storage", function (e) {
    if (e.key === MODE_KEY || e.key === PALETTE_KEY || e.key === null) { current = readCache(); paintSmooth(current); }
  });

  window.mustraTheme = {
    palettes: PALETTES,
    seeds: SEEDS.slice(),
    set: set,
    preview: preview,
    revert: revert,
    current: function () { return { mode: current.mode, palette: current.palette }; },
    effectiveMode: effectiveMode,
    seedsFor: seedsFor,
    validSeeds: validSeeds,
    derive: derive,
    problems: problems,
    contrast: contrast
  };
})();
