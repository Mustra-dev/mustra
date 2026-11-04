// Shared across every console page: the sidebar (an icon rail plus a
// flyout panel with permission-gated subcategories), theme toggle, user
// chip, small helpers. The FOUC-prevention snippet (reads localStorage and
// sets data-theme before paint) stays inline in each page's <head> since it
// must block rendering — this file loads at the end of <body>, after the
// page's own `<div class="app-shell">` skeleton (the overlay div and the
// empty `#sidebar-rail` / `#sidebar-flyout` <aside> elements) is already in
// the DOM.

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// sx carries a style computed at render time (a bar's width, a series'
// colour) into markup built as a string. The console's CSP refuses style
// attributes (#143), so markup that injection slipped into cannot restyle
// the page; sx returns a data-sx attribute instead, indexing a
// declaration list this page produced, and the observer below applies it
// through the CSSOM, which the policy allows, before the next paint. An
// injected data-sx can only name a style the page itself made. Lists are
// interned, so re-rendering the same bars does not grow the table.
const sxStyles = [];
const sxIndex = new Map();
function sx(css) {
  css = String(css ?? "");
  let i = sxIndex.get(css);
  if (i === undefined) {
    i = sxStyles.push(css) - 1;
    sxIndex.set(css, i);
  }
  return ` data-sx="${i}"`;
}

function applySx(root) {
  const els = root.matches("[data-sx]") ? [root, ...root.querySelectorAll("[data-sx]")] : root.querySelectorAll("[data-sx]");
  for (const el of els) {
    const css = sxStyles[Number(el.getAttribute("data-sx"))];
    if (css) el.style.cssText += ";" + css;
    el.removeAttribute("data-sx");
  }
}

new MutationObserver(records => {
  for (const r of records) for (const n of r.addedNodes) if (n.nodeType === Node.ELEMENT_NODE) applySx(n);
}).observe(document.documentElement, { childList: true, subtree: true });

// csvCell quotes one value for a client-side CSV export. A spreadsheet
// treats a cell starting with = + - @ (or a tab or carriage return) as a
// formula, and agent-reported values -- hostnames, paths, snippets -- land in
// these cells, so such a cell is prefixed with a single quote and shown as
// text. Same rule as the server's csvsafe.go.
function csvCell(v) {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

// csvRow joins one record of csvCell-quoted values.
function csvRow(cells) {
  return cells.map(csvCell).join(",");
}

// safeUrl keeps a link built from data to http(s) and same-origin paths, so
// a stored value can't become a javascript: or data: URL. The browser's own
// parser decides the scheme, so tabs, newlines and odd casing don't slip
// through. The result still needs escapeHtml() inside an attribute.
function safeUrl(u) {
  const s = String(u ?? "").trim();
  if (!s) return "#";
  try {
    const p = new URL(s, window.location.href);
    if (p.protocol === "http:" || p.protocol === "https:") return s;
  } catch (e) { /* not a URL at all */ }
  return "#";
}

// osLabel/archLabel turn Go's runtime names into what people call these
// systems. The underlying values are unchanged — group rules still match
// "darwin" — so this is presentation only, and the raw value stays in the
// element's title for anyone writing a rule.
function osLabel(os) {
  return { linux: "Linux", darwin: "macOS", windows: "Windows" }[os] || os || "—";
}

// Distro names as their projects write them — RHEL and openSUSE are not
// "Rhel" and "Opensuse". Anything unrecognized is capitalized, which is
// right far more often than it's wrong.
const PLATFORM_LABELS = {
  debian: "Debian", ubuntu: "Ubuntu", raspbian: "Raspberry Pi OS", rhel: "RHEL",
  redhat: "Red Hat", centos: "CentOS", rocky: "Rocky Linux", almalinux: "AlmaLinux",
  fedora: "Fedora", opensuse: "openSUSE", "opensuse-leap": "openSUSE Leap",
  suse: "SUSE", sles: "SLES", arch: "Arch Linux", alpine: "Alpine", gentoo: "Gentoo",
  amzn: "Amazon Linux", ol: "Oracle Linux", linuxmint: "Linux Mint", pop: "Pop!_OS",
  darwin: "macOS", windows: "Windows", haos: "Home Assistant OS",
};

function platformLabel(platform) {
  if (!platform) return "";
  const key = platform.toLowerCase();
  if (PLATFORM_LABELS[key]) return PLATFORM_LABELS[key];
  // gopsutil reports Windows as a whole lowercase product string
  // ("microsoft windows server 2025 standard"), and capitalizing only the
  // first character left the rest of it lowercase in every chart legend and
  // table. Title-case each word, but only one that is entirely lowercase —
  // a name that already carries its own capitalization, openSUSE or
  // Pop!_OS reaching here unmapped, keeps it.
  //
  // The vendor prefix goes too. No other platform here carries one — it is
  // Debian and Ubuntu, not "Software in the Public Interest Debian" — and
  // those ten characters are what pushed the label past its cell in Home's
  // platform legend, wrapping one entry to two lines beside neighbours that
  // fit on one. "Windows Server 2025 Standard" says the same thing.
  const name = platform.replace(/^microsoft\s+(?=windows\b)/i, "");
  return name.split(" ").map(word =>
    word === word.toLowerCase() ? word.charAt(0).toUpperCase() + word.slice(1) : word
  ).join(" ");
}

// osDisplay prefers the distribution over the kernel: "Debian 12" says far
// more than "Linux". Falls back to the OS when an agent hasn't reported a
// platform yet (it arrives with the first facts publish, not registration).
// statusPill sets a status pill's state class and label (Settings, Access →
// Remote desktop, Integrations).
function statusPill(el, status, labels) {
  if (!el) return;
  el.className = "status-pill " + status;
  el.textContent = labels[status] || status;
}

function osDisplay(agent) {
  const platform = platformLabel(agent.platform);
  if (!platform) return osLabel(agent.os);
  // gopsutil hands back a full product string on Windows ("Microsoft
  // Windows 11 Pro"), which already carries its version.
  if (/\d/.test(platform)) return platform;
  const version = (agent.platform_version || "").trim();
  return version ? `${platform} ${version}` : platform;
}

function archLabel(arch) {
  return { amd64: "x86-64", arm64: "ARM64", "386": "x86", arm: "ARM" }[arch] || arch || "—";
}

// --- timestamps -------------------------------------------------------
//
// Every date in the console is drawn on the control plane's clock by
// default, not the browser's. The console is read beside the audit log,
// the agent logs and journalctl, all of which are on the server's clock, and
// a reader comparing two of them should not have to subtract seven hours
// first. The zone is always printed for the same reason: a bare time with
// no zone is the thing that caused the arithmetic.
//
// Preferences can switch it back to the browser's clock per person.
let serverTZ = { zone: "", offset: 0 };

function setServerTimeZone(u) {
  serverTZ = {
    zone: (u && u.server_time_zone) || "",
    offset: (u && u.server_utc_offset_seconds) || 0,
  };
}

function useServerClock() {
  // Server is the default, so anything other than an explicit "local"
  // means the server's clock -- including preferences not loaded yet.
  return !userPrefs || userPrefs.timestamps !== "local";
}

// zoneLabel names the clock a timestamp is on. Intl gives the abbreviation
// the reader expects ("UTC", "PDT") rather than the IANA id.
function zoneLabel(d) {
  if (!useServerClock()) return shortZone(d, undefined);
  if (serverTZ.zone) return shortZone(d, serverTZ.zone);
  const hours = serverTZ.offset / 3600;
  if (!hours) return "UTC";
  return "UTC" + (hours > 0 ? "+" : "") + (Number.isInteger(hours) ? hours : hours.toFixed(1));
}

function shortZone(d, timeZone) {
  try {
    const parts = new Intl.DateTimeFormat(undefined, { timeZone, timeZoneName: "short" }).formatToParts(d);
    const name = parts.find(p => p.type === "timeZoneName");
    if (name) return name.value;
  } catch (e) {}
  return "";
}

// fmtTime is the date-and-time renderer. fmtDate drops the time for the
// places that only ever showed a day.
function fmtTime(iso) { return formatOn(iso, { dateStyle: "medium", timeStyle: "short" }, true); }
function fmtDate(iso) { return formatOn(iso, { dateStyle: "medium" }, false); }

function formatOn(iso, opts, withZone) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  const options = { ...opts };
  if (useServerClock()) {
    if (serverTZ.zone) {
      options.timeZone = serverTZ.zone;
    } else {
      // No zone name to hand Intl: shift the instant by the server's offset
      // and render it as UTC, which lands on the same wall clock.
      const shifted = new Date(d.getTime() + serverTZ.offset * 1000);
      const text = new Intl.DateTimeFormat(undefined, { ...options, timeZone: "UTC" }).format(shifted);
      return withZone ? `${text} ${zoneLabel(d)}`.trim() : text;
    }
  }
  let text;
  try {
    text = new Intl.DateTimeFormat(undefined, options).format(d);
  } catch (e) {
    text = d.toLocaleString();
  }
  return withZone ? `${text} ${zoneLabel(d)}`.trim() : text;
}

// fmtAgo says how long ago (or, for a time still to come, how soon) in
// days and hours: "3d 13h ago", "5h ago", "in 2d 4h". Under an hour it
// counts minutes ("12 min ago"), and under a minute it is "just now":
// right after a refresh, "<1h ago" could not tell seconds from most of an
// hour. Counting hours past a day ("85h") would make the reader do the
// division, so days stay.
function fmtAgo(iso) {
  if (!iso) return "never";
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  // A few seconds of clock skew still reads as the past.
  const ahead = diff < -5;
  const secs = Math.abs(diff);
  if (secs < 60) return ahead ? "in under a minute" : "just now";
  const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600);
  const span = d ? d + "d" + (h ? " " + h + "h" : "") : h ? h + "h" : Math.floor(secs / 60) + " min";
  return ahead ? "in " + span : span + " ago";
}

// --- Sidebar: categories (pages) each with permission-gated subcategories
// (sections within that page). One tree, shared by every page, so the nav
// doesn't have to be hand-duplicated into five HTML files — see
// docs/ARCHITECTURE.md for why this lives in JS rather than being
// server-templated (Slice 1's static pages have no per-request templating
// today).
// ---------------------------------------------------------------------------
// Icons
//
// Inline SVG rather than emoji. Emoji render as full-colour platform glyphs —
// Apple's on iOS, Noto's on Linux, Segoe's on Windows — so the same console
// looked like three different products, and none of them could inherit the
// rail's active colour. These are single-path line icons on a 24-unit grid,
// stroked in currentColor, so they take the surrounding text colour and look
// identical everywhere.
//
// One weight, one grid, one stroke width. That uniformity is most of what
// makes an icon set read as a set rather than as clip art.
const ICON_PATHS = {
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  grid:        '<rect x="4" y="4" width="4" height="4" rx=".8"/><rect x="10" y="4" width="4" height="4" rx=".8"/><rect x="16" y="4" width="4" height="4" rx=".8"/><rect x="4" y="10" width="4" height="4" rx=".8"/><rect x="10" y="10" width="4" height="4" rx=".8"/><rect x="16" y="10" width="4" height="4" rx=".8"/><rect x="4" y="16" width="4" height="4" rx=".8"/><rect x="10" y="16" width="4" height="4" rx=".8"/><rect x="16" y="16" width="4" height="4" rx=".8"/>',
  home:        '<path d="M3.5 10.5 12 3.5l8.5 7"/><path d="M5.5 9.5V20h13V9.5"/><path d="M9.75 20v-5.5h4.5V20"/>',
  certificate: '<rect x="3.5" y="3.5" width="17" height="12" rx="1.5"/><path d="M7 7.5h7M7 11h4"/><circle cx="16.5" cy="16.5" r="3.2"/><path d="M14.6 19.1 14 22.5l2.5-1.4 2.5 1.4-.6-3.4"/>',
  clients:     '<rect x="2.5" y="4.5" width="19" height="12" rx="1.5"/><path d="M8 20.5h8M12 16.5v4"/><path d="M12 7.5v5m0 0-2-2m2 2 2-2"/>',
  comply:      '<path d="M8 4.5H6.5A1.5 1.5 0 0 0 5 6v13.5A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V6a1.5 1.5 0 0 0-1.5-1.5H16"/><rect x="8" y="2.5" width="8" height="4" rx="1"/><path d="m8.75 13 2.25 2.25L15.5 10.5"/>',
  connect:     '<path d="M9.5 14.5 14.5 9.5"/><path d="M12.5 6.5 14.7 4.3a3.9 3.9 0 0 1 5.5 5.5L18 12"/><path d="M11.5 17.5 9.3 19.7a3.9 3.9 0 0 1-5.5-5.5L6 12"/>',
  deploy:      '<path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9"/>',
  terminal:    '<rect x="2.5" y="4" width="19" height="16" rx="1.5"/><path d="m6.5 9.5 3 2.5-3 2.5M12.5 15h5"/>',
  discover:    '<circle cx="12" cy="12" r="2"/><path d="M8.1 15.9a5.5 5.5 0 0 1 0-7.8M15.9 8.1a5.5 5.5 0 0 1 0 7.8"/><path d="M5.3 18.7a9.5 9.5 0 0 1 0-13.4M18.7 5.3a9.5 9.5 0 0 1 0 13.4"/>',
  integrity:   '<path d="M12 2.8 4.5 6v6.2c0 4.4 3.1 7.9 7.5 9 4.4-1.1 7.5-4.6 7.5-9V6z"/><path d="m9 12 2.2 2.2L15.5 10"/>',
  interact:    '<path d="M20.5 15.5a1.5 1.5 0 0 1-1.5 1.5H8l-4 4V5a1.5 1.5 0 0 1 1.5-1.5h13.5A1.5 1.5 0 0 1 20.5 5z"/><path d="M9.8 8.6a2.3 2.3 0 1 1 3 2.2v1.1"/><path d="M12.8 14.6h.01"/>',
  patch:       '<rect x="2.6" y="8.6" width="18.8" height="6.8" rx="3.4" transform="rotate(-45 12 12)"/><path d="m9.2 9.2 5.6 5.6"/><path d="M10.4 13.1h.01M13.1 10.4h.01M11.8 11.8h.01"/>',
  performance: '<path d="M2.5 12.5h4l2.5-6 3.5 12 3-9 2 3h4.5"/>',
  settings:    '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 9 19.4a1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 4.6 9a1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z"/>',

  // Subcategory icons. A smaller vocabulary reused across modules, so the
  // same idea always looks the same wherever it appears.
  chart:    '<path d="M3.5 20.5h17"/><rect x="5" y="12" width="3.5" height="6" rx="0.7"/><rect x="10.2" y="7" width="3.5" height="11" rx="0.7"/><rect x="15.4" y="10" width="3.5" height="8" rx="0.7"/>',
  download: '<path d="M12 3.5v11m0 0-4-4m4 4 4-4"/><path d="M4 16v3.5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V16"/>',
  database: '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v6c0 1.55 3.36 2.8 7.5 2.8s7.5-1.25 7.5-2.8v-6"/><path d="M4.5 11.5v7c0 1.55 3.36 2.8 7.5 2.8s7.5-1.25 7.5-2.8v-7"/>',
  key:      '<circle cx="7.5" cy="12" r="3.5"/><path d="M11 12h9.5M17.5 12v3M20.5 12v2.5"/>',
  list:     '<path d="M8.5 6.5h12M8.5 12h12M8.5 17.5h12"/><path d="M4 6.5h.01M4 12h.01M4 17.5h.01"/>',
  search:   '<circle cx="10.8" cy="10.8" r="6.3"/><path d="m15.5 15.5 5 5"/>',
  book:     '<path d="M4 4.5h6a3 3 0 0 1 2 3v12a2.5 2.5 0 0 0-2-2H4z"/><path d="M20 4.5h-6a3 3 0 0 0-2 3v12a2.5 2.5 0 0 1 2-2h6z"/>',
  alert:    '<path d="M10.3 3.9 2.6 17.2a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4M12 17.2h.01"/>',
  chat:     '<path d="M21 11.5a8.4 8.4 0 0 1-9 8.4 9.2 9.2 0 0 1-3.6-.7L3 21l1.9-4.6A8.3 8.3 0 0 1 12 3.1a8.4 8.4 0 0 1 9 8.4z"/>',
  box:      '<path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9"/>',
  star:     '<path d="m12 3.5 2.7 5.5 6 .9-4.35 4.25 1.03 6L12 17.3l-5.38 2.85 1.03-6L3.3 9.9l6-.9z"/>',
  clock:    '<circle cx="12" cy="12" r="8.5"/><path d="M12 7v5.3l3.4 2"/>',
  rocket:   '<path d="M12 2.5s4.5 2.5 4.5 8c0 3-1.5 5.5-4.5 8-3-2.5-4.5-5-4.5-8 0-5.5 4.5-8 4.5-8z"/><circle cx="12" cy="9.5" r="1.8"/><path d="M8.5 15 6 17.5l1 3 2.4-1.4M15.5 15l2.5 2.5-1 3-2.4-1.4"/>',
  folder:   '<path d="M3.5 6.5a1.5 1.5 0 0 1 1.5-1.5h4l2 2.5h7.5A1.5 1.5 0 0 1 20 9v9a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 18z"/>',
  scale:    '<path d="M12 3.5v17M6 20.5h12"/><path d="M12 6.5 5 9m7-2.5L19 9"/><path d="M2.5 13.5a2.5 2.5 0 0 0 5 0L5 8.5zM16.5 13.5a2.5 2.5 0 0 0 5 0L19 8.5z"/>',
  groups:   '<rect x="3" y="3.5" width="7.5" height="7.5" rx="1.3"/><rect x="13.5" y="3.5" width="7.5" height="7.5" rx="1.3"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.3"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.3"/>',
  sliders:  '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2.2"/><circle cx="9" cy="17" r="2.2"/>',
  filter:   '<path d="M3.5 5h17l-6.6 7.6v5.6l-3.8 1.8v-7.4z"/>',
  lock:     '<rect x="4.5" y="10.5" width="15" height="10" rx="1.8"/><path d="M8 10.5V7.2a4 4 0 0 1 8 0v3.3"/>',
  sync:     '<path d="M20.5 11a8.5 8.5 0 0 0-14.6-5"/><path d="M3.5 13a8.5 8.5 0 0 0 14.6 5"/><path d="M3.5 5v5h5M20.5 19v-5h-5"/>',
  door:     '<path d="M4.5 3.5h11v17h-11z"/><path d="M15.5 12h5m0 0-2.5-2.5M20.5 12 18 14.5"/><path d="M8 12h.01"/>',
  globe:    '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5a13 13 0 0 1 0 17 13 13 0 0 1 0-17z"/>',
  plug:     '<path d="M9 3.5v6M15 3.5v6"/><path d="M6.5 9.5h11v3a5.5 5.5 0 0 1-11 0z"/><path d="M12 18v3"/>',
  user:     '<circle cx="12" cy="8" r="3.8"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/>',
  users:    '<circle cx="9" cy="8" r="3.4"/><path d="M2.5 20.5a6.5 6.5 0 0 1 13 0"/><path d="M16 5a3.4 3.4 0 0 1 0 6.5M17.5 15a6.5 6.5 0 0 1 4 5.5"/>',
  shield:   '<path d="M12 2.8 4.5 6v6.2c0 4.4 3.1 7.9 7.5 9 4.4-1.1 7.5-4.6 7.5-9V6z"/>',
  info:     '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5M12 7.8h.01"/>',
  bag:      '<path d="M4.5 7.5h15l-1 12a1.5 1.5 0 0 1-1.5 1.4H7a1.5 1.5 0 0 1-1.5-1.4z"/><path d="M8.5 10V6.5a3.5 3.5 0 0 1 7 0V10"/>',
  radar:    '<circle cx="12" cy="12" r="8.5"/><path d="M12 12 17 7"/><path d="M12 12h5.5"/><circle cx="12" cy="12" r="1"/>',
  bug:      '<rect x="7" y="7.5" width="10" height="13" rx="5"/><path d="M9.5 7.5a2.5 2.5 0 0 1 5 0M12 11v9.5M3.5 13h3.5M17 13h3.5M4.5 8.5l2.8 1.6M19.5 8.5l-2.8 1.6M4.5 19l2.8-2M19.5 19l-2.8-2"/>',
  tag:      '<path d="M3.5 12.2V4.5a1 1 0 0 1 1-1h7.7l8.3 8.3a1.4 1.4 0 0 1 0 2l-6.7 6.7a1.4 1.4 0 0 1-2 0z"/><circle cx="8" cy="8" r="1.4"/>',
  signal:   '<circle cx="12" cy="12" r="1.6"/><path d="M8.6 15.4a4.8 4.8 0 0 1 0-6.8M15.4 8.6a4.8 4.8 0 0 1 0 6.8M5.8 18.2a8.8 8.8 0 0 1 0-12.4M18.2 5.8a8.8 8.8 0 0 1 0 12.4"/>',
  layers:   '<path d="m12 3.5 8.5 4.5L12 12.5 3.5 8z"/><path d="m3.5 12 8.5 4.5 8.5-4.5M3.5 16l8.5 4.5 8.5-4.5"/>',
  cpu:      '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5" rx=".5"/><path d="M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3"/>',
};

// paintIcons fills every element carrying data-icon. Static markup can
// then declare an icon without being a template literal — pasting ${icon()}
// into plain HTML renders the source text, which is exactly the mistake
// this exists to make impossible.
function paintIcons(root) {
  (root || document).querySelectorAll("[data-icon]").forEach(el => {
    if (el.dataset.painted) return;
    el.innerHTML = icon(el.dataset.icon);
    el.dataset.painted = "1";
  });
}

// icon renders one by name. An unknown name yields nothing rather than a
// broken glyph — a missing icon should be invisible, not a mystery box.
function icon(name) {
  const body = ICON_PATHS[name];
  if (!body) return "";
  return /* safe-html: fixed SVG paths from ICON_PATHS */ '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
         'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" ' +
         'aria-hidden="true">' + body + '</svg>';
}

// Rail icons are solid shapes rather than the line set above: the rail is
// drawn after Tanium's, whose icons are filled glyphs, and at rail size a
// filled shape is what makes seven icons tell apart at a glance. Same
// 24-unit grid and currentColor, so active and hover colours still apply.
const RAIL_ICON_PATHS = {
  home:       '<path fill-rule="evenodd" d="M12 2.6 1.8 11.4h2.9V21.4h14.6V11.4h2.9L17.8 7.6V3.6h-2.6v1.8zM13.6 13.4h3v8h-3z"/>',
  grid:       '<circle cx="5" cy="5" r="2.05"/><circle cx="12" cy="5" r="2.05"/><circle cx="19" cy="5" r="2.05"/><circle cx="5" cy="12" r="2.05"/><circle cx="12" cy="12" r="2.05"/><circle cx="19" cy="12" r="2.05"/><circle cx="5" cy="19" r="2.05"/><circle cx="12" cy="19" r="2.05"/><circle cx="19" cy="19" r="2.05"/>',
  reporting:  '<rect x="2.6" y="15.6" width="3.6" height="5.4" rx=".4"/><rect x="7.6" y="10.6" width="3.6" height="10.4" rx=".4"/><rect x="12.6" y="13.2" width="3.6" height="7.8" rx=".4"/><rect x="17.6" y="5.6" width="3.6" height="15.4" rx=".4"/>',
  shared:     '<path d="M2.4 5.6 5.6 4.8v10.6l-1.2.3a1 1 0 0 1-1.2-1z"/><path d="M6.6 7.4 9.8 6.6v10.6l-1.2.3a1 1 0 0 1-1.2-1z"/><path d="M11 9.6l9.8-2.4a1 1 0 0 1 1.2 1v9.6a1 1 0 0 1-.8 1L12.2 21a1 1 0 0 1-1.2-1z"/>',
  admin:      '<path fill-rule="evenodd" d="M14.46 12.95 L16.52 13.08 L16.52 15.32 L14.46 15.45 L13.75 17.17 L15.1 18.73 L13.53 20.3 L11.97 18.95 L10.25 19.66 L10.12 21.72 L7.88 21.72 L7.75 19.66 L6.03 18.95 L4.47 20.3 L2.9 18.73 L4.25 17.17 L3.54 15.45 L1.48 15.32 L1.48 13.08 L3.54 12.95 L4.25 11.23 L2.9 9.67 L4.47 8.1 L6.03 9.45 L7.75 8.74 L7.88 6.68 L10.12 6.68 L10.25 8.74 L11.97 9.45 L13.53 8.1 L15.1 9.67 L13.75 11.23ZM11.4 14.2A2.4 2.4 0 1 0 6.6 14.2A2.4 2.4 0 1 0 11.4 14.2Z"/><path fill-rule="evenodd" d="M21.49 5.18 L22.74 5.26 L22.74 6.74 L21.49 6.82 L20.97 7.91 L21.68 8.93 L20.53 9.85 L19.69 8.93 L18.51 9.2 L18.15 10.39 L16.72 10.07 L16.92 8.83 L15.97 8.08 L14.81 8.55 L14.17 7.22 L15.26 6.61 L15.26 5.39 L14.17 4.78 L14.81 3.45 L15.97 3.92 L16.92 3.17 L16.72 1.93 L18.15 1.61 L18.51 2.8 L19.69 3.07 L20.53 2.15 L21.68 3.07 L20.97 4.09ZM19.75 6A1.35 1.35 0 1 0 17.05 6A1.35 1.35 0 1 0 19.75 6Z"/>',
  tools:      '<path stroke="currentColor" fill="none" stroke-linecap="round" stroke-width="1.9" d="M4 4 11.5 11.5"/><path stroke="currentColor" fill="none" stroke-linecap="round" stroke-width="4.4" d="M14.2 14.2 19.4 19.4"/><path stroke="currentColor" fill="none" stroke-linecap="round" stroke-width="3.4" d="M5.6 18.4 13.6 10.4"/><path stroke="currentColor" fill="none" stroke-linecap="round" stroke-width="2.8" d="M16.87 10.49A3.1 3.1 0 1 1 19.69 7.13"/>',
  explore:    '<circle cx="12" cy="12" r="9.2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-width="2"/><path d="M16.4 7.6 13.4 13.4 7.6 16.4 10.6 10.6z"/>',
  help:       '<circle cx="12" cy="12" r="9.4" fill="none" stroke="currentColor" stroke-width="2.2"/><path d="M9.2 9.5a2.9 2.9 0 0 1 5.6 1c0 2-2.8 2.4-2.8 4.2" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/><circle cx="12" cy="18.1" r="1.45"/>',
  settings:   '<path fill-rule="evenodd" d="M19.02 10.39 L21.5 10.59 L21.5 13.41 L19.02 13.61 L18.1 15.82 L19.71 17.72 L17.72 19.71 L15.82 18.1 L13.61 19.02 L13.41 21.5 L10.59 21.5 L10.39 19.02 L8.18 18.1 L6.28 19.71 L4.29 17.72 L5.9 15.82 L4.98 13.61 L2.5 13.41 L2.5 10.59 L4.98 10.39 L5.9 8.18 L4.29 6.28 L6.28 4.29 L8.18 5.9 L10.39 4.98 L10.59 2.5 L13.41 2.5 L13.61 4.98 L15.82 5.9 L17.72 4.29 L19.71 6.28 L18.1 8.18ZM15.2 12A3.2 3.2 0 1 0 8.8 12A3.2 3.2 0 1 0 15.2 12Z"/>',
};
function railIcon(name) {
  const body = RAIL_ICON_PATHS[name];
  if (!body) return icon(name);
  return /* safe-html: fixed SVG paths from RAIL_ICON_PATHS */ '<svg class="ic rail-ic" viewBox="0 0 24 24" fill="currentColor" ' +
         'aria-hidden="true">' + body + '</svg>';
}

// MUSTRA_MARK is the brand's icon mark — solid stroke rather than the dot
// grid, because everywhere the console draws it is under 48px, where the
// dots merge into mush (see the brand kit's README). It's inlined rather
// than an <img> so it inherits currentColor, which makes light/dark free.
const MUSTRA_MARK = '<svg class="brand-mark" viewBox="0 0 100 100" fill="none" role="img" aria-label="mustra">' +
  '<path d="M20 76V24l30 36 30-36v52" stroke="currentColor" stroke-width="16" stroke-linecap="round" stroke-linejoin="round"/></svg>';

// The rail groups modules rather than listing all fifteen.
//
// A flat rail of fifteen identical-sized icons is a lookup problem, not a
// navigation one: nothing about the shape tells you where "Patch" is, so
// every visit is a scan. Grouping is the answer — six things to choose
// between, then a short list inside
// each, which is a decision a person can make from muscle memory.
//
// Home and Interact stay top-level deliberately. They are the two things
// people open constantly, and burying a daily action one level down to make
// a diagram tidier is a bad trade.
const NAV_GROUPS = [
  // The rail is Tanium's, in Tanium's order: Home, Modules, Reporting,
  // Shared Services, Administration, Tools, Explore, with Preferences on a
  // gear at the foot of the rail. Atlas, Tanium's AI assistant, has no
  // counterpart here and is left out.
  { id: "home", label: "Home", icon: "home" },
  // Every module A to Z, each with its sections one hover away. Modules
  // that belong to no other group are filed here, so this icon is "you are
  // here" on their pages.
  { id: "modules", label: "Modules", icon: "grid", all: true },
  { id: "reporting", label: "Reporting", icon: "reporting",
    desc: "Dashboards and scheduled reports over fleet data." },
  { id: "shared", label: "Shared Services", icon: "shared",
    desc: "The services the modules are built on: the client, its sensors, connections, notifications and playbooks." },
  // Administration is the one group big enough to need columns: fifteen
  // links in a single column is a wall, and the headings do the sorting
  // your eye would otherwise have to.
  //
  // Entries are referenced by label and resolved against the group's
  // modules and their subitems, so a link cannot drift out of step with
  // where it actually goes — there is still exactly one definition of each.
  { id: "admin", label: "Administration", icon: "admin",
    desc: "How mustra itself is configured, and where its data goes.",
    columns: [
      { label: "Permissions", items: ["Access", "Users", "Groups", "Roles", "Computer Groups", "API Tokens"] },
      // No "Administration" entry: it opened the page's first section, so it
      // was a second link to Single Sign-On (or Users, without settings.manage).
      { label: "Configuration", items: ["Single Sign-On", "SCIM", "Break-glass Account", "Network Allowlists", "Telemetry", "Directory", "Branding"] },
      { label: "Agents", items: ["Agent Behavior", "Agent Identity", "Uninstall Password", "macOS MDM", "Message Buffer"] },
      { label: "Operations", items: ["Audit Log", "Logging", "Backup", "About"] },
    ],
    // Modules the columns leave out on purpose. Any other unnamed module is
    // appended to the last column (see openGroupPopout), but the
    // Administration page itself is reached through its sections above.
    omit: ["Administration"] },
  { id: "tools", label: "Tools", icon: "tools",
    desc: "Asking the fleet questions, a shell on one endpoint, and what needs your attention." },
  // Explore is a single destination: Interact's Explore columns (saved
  // queries, dashboards, recent queries), so it is a link, not a popout.
  { id: "explore", label: "Explore", icon: "explore" },
];

const NAV_TREE = [
  { label: "Home", href: "/", icon: "home", group: "home" },
  // No desc, so it is not a module: Home's grid and the Modules popout skip it.
  { label: "Explore", href: "/interact#explore", icon: "star", group: "explore" },
  { label: "Guide", href: "/guide", icon: "alert", group: "tools",
    desc: "Everything the console wants you to know, in one place: what to fix, and what to look at." },
  { label: "Access", href: "/access", icon: "key", group: "admin",
    desc: "What a role may act on, what a module may reach at all, and which operations wait for a second person.", sub: [
      { label: "Approvals", hash: "approvals", icon: "alert", desc: "Operations parked for a decision, and what your own scope is." },
      { label: "Jump Gate", hash: "jump", icon: "key", desc: "Just-in-time access to one endpoint: a reason, an approval, a clock." },
      { label: "Sessions", hash: "sessions", icon: "list", desc: "Every recorded Direct Connect session and what was run in it." },
      { label: "Content Sets", hash: "content", icon: "list", desc: "Collections of sensors, packages, dashboards and saved queries that roles may use." },
      { label: "Action Groups", hash: "actiongroups", icon: "groups", desc: "The ceiling on which endpoints a module may act on, whoever is asking." },
      { label: "Approval Policies", hash: "policies", icon: "settings", desc: "Which operations wait for somebody else before they run." },
    ] },
  { label: "Dashboards", href: "/dashboards", icon: "chart", group: "reporting",
    desc: "Panels over saved queries and module data, drawn as numbers, donuts, bars and history; thresholds that reach the Guide.", sub: [
      { label: "All Dashboards", hash: "list", icon: "list", desc: "Every dashboard you can see, to open, edit or share." },
      { label: "New Dashboard", hash: "new", icon: "chart", desc: "Start an empty dashboard and add panels to it." },
      { label: "Alerts", hash: "alerts", icon: "alert", desc: "Thresholds on dashboard panels that raise a Guide alert." },
    ] },

  { label: "Certificate Manager", href: "/certificates", icon: "certificate", group: "modules",
    desc: "Every X.509 certificate across the fleet, sorted by what breaks next.", sub: [
      { label: "Overview", hash: "overview", icon: "certificate", desc: "Every certificate on your endpoints, soonest to expire first." },
      { label: "New Certificate", hash: "new", icon: "rocket", desc: "Issue a certificate and install it on a server in one go." },
      { label: "Renewals", hash: "renewal", icon: "sync", desc: "Certificates Mustra keeps renewed, and the ones waiting for approval." },
      { label: "Inventory", hash: "inventory", icon: "list", desc: "Every certificate Mustra issued and what became of it, and which endpoints report." },
      { label: "Revoke", hash: "revoke", icon: "alert", desc: "Withdraw trust in a certificate before it expires, optionally replacing it first." },
      { label: "App Credentials", hash: "apps", icon: "key", desc: "Client secrets, SAML and client certificates at Entra ID, Authentik, Okta and Google: remind, renew and download, or renew and push." },
      { label: "Alerts", hash: "alerts", icon: "alert", desc: "Expiry reminders at the days you choose, to the console, Teams, Discord, Slack, webhooks and ServiceNow." },
      { label: "Trusted Roots", hash: "trust", icon: "shield", desc: "Push a certificate authority's root into every endpoint's trust store." },
      { label: "Authorities", hash: "authorities", icon: "key", desc: "Let's Encrypt, Cloudflare, Active Directory and Mustra's own CA: what each is for and its settings." },
    ] },

  { label: "Client Management", href: "/agents", icon: "clients", perm: "deploy.manage", group: "shared",
    desc: "Install agents, manage credentials, and see what version the fleet is on.", sub: [
      { label: "Overview", hash: "overview", icon: "chart", desc: "Agent versions across the fleet, what's behind, and what it all runs on." },
      { label: "Manual Install", hash: "install", icon: "download", desc: "One-line install script for a new endpoint, per OS." },
      { label: "Credential Vault", hash: "vault", icon: "key", desc: "Store SSH passwords or private keys for scan-and-push deploys." },
      { label: "Network Scan & Push", hash: "scan", icon: "radar", desc: "Sweep a subnet for SSH hosts and push the agent to them." },
      { label: "Deployments", hash: "deployments", icon: "list", desc: "Every agent push attempted, running or finished, and how it went." },
      { label: "Client Status", hash: "status", icon: "clients", desc: "Every client's registration and connectivity, exportable as CSV or JSON, with actions on a selection." },
      { label: "Client Health", hash: "health", icon: "chart", desc: "Versions, named health-check failures and settings drift, by group; upgrade the fleet ring by ring." },
      { label: "Profiles", hash: "profiles", icon: "settings", desc: "Settings pushed to groups of agents — sensor interval, log level, random delay — and their upgrade ring." },
      // Self Service lives with Deploy, whose packages it publishes; it is
      // listed here too because it is also what the client shows its user.
      { label: "Self Service", href: "/catalog", hash: "items", icon: "bag", desc: "What endpoints may install themselves (lives under Deploy), and the requests waiting on you." },
    ] },

  { label: "Comply", href: "/compliance", icon: "comply", group: "modules",
    desc: "Benchmark checks and known vulnerabilities across the fleet.", sub: [
      { label: "Findings", hash: "findings", icon: "search", desc: "Every benchmark check result, worst first." },
      { label: "Policies", hash: "policies", icon: "book", desc: "The benchmarks mustra runs, built in or imported." },
      { label: "Vulnerabilities", href: "/risk", hash: "vulns", icon: "alert", desc: "Real CVE matches, filtered through the distribution's own verdict." },
      { label: "Exploitability", href: "/risk", hash: "exploitability", icon: "radar", desc: "The vulnerabilities somebody is known to be using: CISA KEV and EPSS over the fleet's findings." },
      { label: "Levels", href: "/risk", hash: "levels", icon: "chart", desc: "One vulnerability level per endpoint, stated only from a scan under 30 days old." },
      { label: "Remediation", href: "/risk", hash: "remediation", icon: "rocket", desc: "Findings grouped by the package that fixes them, with the pending patch or catalog package that does it." },
    ] },

  { label: "Enforce", href: "/enforce", icon: "lock", group: "modules",
    desc: "Settings that must hold — checked on a timer, and put back when they move.", sub: [
      { label: "Standing", hash: "standing", icon: "chart", desc: "Every policy's state across the fleet, worst first." },
      { label: "Policies", hash: "policies", icon: "book", desc: "What must be true, and the command that makes it true again — typed editors for Windows Firewall, BitLocker, Defender and AppLocker, or your own rules." },
      { label: "Coverage", hash: "coverage", icon: "shield", desc: "Firewall, encryption, antimalware and app-control coverage across the fleet, from the security posture sensor." },
    ] },

  { label: "Connect", href: "/connect", icon: "connect", perm: "settings.manage", group: "shared",
    desc: "Standing exports of mustra's answers to a webhook, a file, or syslog." },

  { label: "API Reference", href: "/api-docs", icon: "list", group: "admin",
    desc: "Every API route and the permission it needs, with a request builder that writes the call in cURL, PowerShell, Python, JavaScript, TypeScript, Go or C#; download the OpenAPI spec for Postman or Insomnia." },

  { label: "Backup", href: "/backup", icon: "database", perm: "settings.manage", group: "admin",
    desc: "A full copy of the control plane's data, on a schedule, and the way back from one." },

  { label: "Threat Briefings", href: "/threats", icon: "alert", group: "reporting",
    desc: "A dashboard per vulnerability being exploited now: which endpoints have it, which versions, how to hunt for it." },

  { label: "Reports", href: "/reports", icon: "book", group: "reporting",
    desc: "A page for somebody who does not open the console — assembled on a schedule and sent where they read.", sub: [
      { label: "Reports", hash: "reports", icon: "book", desc: "What each report covers, where it goes, and when." },
      { label: "Renderings", hash: "renderings", icon: "clock", desc: "Every report as it was when it ran, kept." },
    ] },

  { label: "Deploy", href: "/software", icon: "deploy", perm: "deploy.manage", group: "modules",
    desc: "Install, update and remove software across Windows, macOS and Linux.", sub: [
      { label: "Overview", hash: "overview", icon: "chart", desc: "What the catalog covers and what the fleet is eligible for." },
      { label: "Software Catalog", hash: "catalog", icon: "box", desc: "Publish software releases with platform actions, dependencies, and validation." },
      { label: "Action Packages", hash: "actions", icon: "terminal", desc: "Versioned platform commands with live output and optional sensor verification." },
      { label: "Settings", hash: "settings", icon: "settings", desc: "Configure deployment logs, compression, and endpoint caching." },
      { label: "Installed Software", hash: "discover", icon: "search", desc: "What the fleet already runs — adopt any of it into the catalog." },
      { label: "Deployments", hash: "deployments", icon: "list", desc: "Every software deployment, active and finished, per endpoint." },
      { label: "Schedules", hash: "schedules", icon: "clock", desc: "Run a package on a cadence — nightly, weekly, or once at a set time." },
      { label: "Maintenance Windows", hash: "windows", icon: "clock", desc: "When the endpoints in a group may be touched; deployments outside a window wait." },
      { label: "Templates", hash: "templates", icon: "book", desc: "Saved deployment forms — package, plan, reboot and expiry — to fill in with one pick." },
      { label: "Self Service", href: "/catalog", hash: "items", icon: "bag", desc: "What endpoints may install themselves, and the requests waiting on you." },
    ] },

  { label: "Direct Connect", href: "/shell", icon: "terminal", perm: "deploy.manage", group: "tools",
    desc: "Run commands on an endpoint interactively — every one logged with who ran it." },

  { label: "Discover", href: "/discover", icon: "discover", group: "modules",
    desc: "Everything on the network, and which of it mustra doesn't manage yet." },

  { label: "Backup Status", href: "/backup-status", icon: "database", group: "modules",
    desc: "Every virtual machine's last backup from Proxmox, which are overdue, and which no job covers." },

  { label: "Threat Response", href: "/hunt", icon: "radar", group: "modules",
    desc: "Indicators of compromise, matched against what the fleet reports — some of it as it happens.", sub: [
      { label: "Findings", hash: "findings", icon: "alert", desc: "Where a watched indicator has actually been seen." },
      { label: "Live Activity", hash: "activity", icon: "clock", desc: "The recorder: processes, network connections, DNS, registry changes and logons, as they happen." },
      { label: "Indicators", hash: "indicators", perm: "settings.manage", icon: "list", desc: "Hashes, filenames, processes and addresses worth looking for." },
      { label: "Signals", hash: "signals", perm: "settings.manage", icon: "radar", desc: "Behavioural rules evaluated live on every recorder event — encoded PowerShell, a Run key written, a reverse-shell port." },
    ] },

  { label: "Impact", href: "/impact", icon: "radar", group: "modules",
    desc: "Who can reach what, if an account or an endpoint were compromised.", sub: [
      { label: "Overview", hash: "overview", icon: "chart", desc: "The accounts, groups and endpoints with the most reach, and what to fix first." },
      { label: "Findings", hash: "findings", icon: "alert", desc: "Excessive rights by category: privileged sessions, broad grants, stale accounts." },
      { label: "Users", hash: "users", icon: "user", desc: "Every directory account rated by what it can administer." },
      { label: "Groups", hash: "groups", icon: "users", desc: "Every group rated by what its members inherit." },
      { label: "Endpoints", hash: "endpoints", icon: "clients", desc: "Every endpoint by what a compromise there reaches, and from where it can be reached." },
      { label: "Paths", hash: "paths", icon: "search", desc: "The shortest route from one object to another, one step at a time." },
    ] },
  { label: "Reveal", href: "/reveal", icon: "search", perm: "deploy.manage", group: "modules",
    desc: "Where sensitive data sits on endpoints — card numbers, SSNs, secrets — found where it lives, reported masked.", sub: [
      { label: "Overview", hash: "overview", icon: "chart", desc: "Endpoints with confirmed sensitive data, by pattern and by machine." },
      { label: "Rules", hash: "rules", icon: "book", desc: "What to look for, where, on which endpoints, how often." },
      { label: "Results", hash: "results", icon: "alert", desc: "Every file that matched, with a masked snippet." },
      { label: "Quick Search", hash: "search", icon: "search", desc: "One string or expression, across chosen endpoints, now." },
      { label: "Scans", hash: "scans", icon: "clock", desc: "What each endpoint last scanned, and how it went." },
    ] },
  { label: "Integrity Monitor", href: "/integrity", icon: "integrity", group: "modules",
    desc: "What changed in the watched files, when it happened, and which of it mustra itself caused.", sub: [
      { label: "Changes", hash: "changes", icon: "search", desc: "What the hash baseline says moved, diffed server-side." },
      { label: "Live Events", hash: "events", icon: "clock", desc: "Watched paths as they change, seconds after the write." },
    ] },

  { label: "Interact", href: "/interact", icon: "interact", group: "tools",
    desc: "Query every endpoint and act on the answer.", sub: [
      { label: "Query", hash: "ask", icon: "interact", desc: "Any field the fleet reports, filtered any way, answered from cache." },
      { label: "Query Builder", hash: "builder", icon: "filter", desc: "Build a query from sensors and conditions, no syntax to remember." },
      { label: "Saved Queries", hash: "saved", icon: "star", desc: "Queries worth running again." },
      { label: "Query History", hash: "history", icon: "clock", desc: "Every query anyone has run, and who ran it." },
    ] },

  { label: "Notify", href: "/eun", icon: "alert", group: "shared",
    desc: "Tell the people at the endpoints something, and record what they said back.", sub: [
      { label: "Messages", hash: "messages", perm: "deploy.manage", icon: "list", desc: "Notices and restart prompts, with a preview of what they will see." },
      { label: "Send", hash: "send", perm: "deploy.manage", icon: "rocket", desc: "Deliver a message and track the answers as a deployment." },
    ] },

  { label: "Engage", href: "/engage", icon: "chat", group: "modules",
    desc: "Ask the people who use the fleet how it is going, and score what they say honestly.", sub: [
      { label: "Surveys", hash: "surveys", icon: "list", desc: "The questions you have written, their sentiment score and their response rate." },
      { label: "Send", hash: "send", perm: "deploy.manage", icon: "rocket", desc: "Ask a survey of a computer group, and count who was actually asked." },
    ] },

  { label: "Playbooks", href: "/playbooks", icon: "sync", perm: "deploy.manage", group: "shared",
    desc: "Several things in order, per endpoint — patch, wait for the reboot, verify, tell the person.", sub: [
      { label: "Playbooks", hash: "playbooks", icon: "list", desc: "The flows you have written, and what each one targets." },
      { label: "Runs", hash: "runs", icon: "clock", desc: "Every run, live while it is going and afterwards." },
      { label: "Triggers", hash: "triggers", perm: "deploy.manage", icon: "rocket", desc: "What starts a playbook other than a clock — a Guide item, or something posting to a URL." },
      { label: "Approvals", hash: "approvals", icon: "lock", desc: "Runs stopped at an approval step, waiting on a second person." },
    ] },

  { label: "Sensors", href: "/sensors", icon: "radar", group: "shared",
    desc: "What mustra collects from every endpoint, how it collects it, and whether it is working.", sub: [
      { label: "Catalog", hash: "catalog", icon: "list", desc: "Every sensor, what it answers, and its per-platform mechanism." },
      { label: "Fleet Coverage", hash: "coverage", icon: "chart", desc: "Who is reporting each sensor, and how stale it is." },
    ] },

  { label: "Patch", href: "/patches", icon: "patch", group: "modules",
    desc: "See what's missing across the fleet, deploy fixes, and schedule recurring jobs.", sub: [
      { label: "Overview", hash: "overview", icon: "patch", desc: "Fleet-wide missing-patch visibility, by device and by patch." },
      { label: "Deploy & Schedule", hash: "deploy", perm: "patches.manage", icon: "rocket", desc: "Push patches now, or set up a recurring deployment window." },
      { label: "Deployments", hash: "deployments", perm: "patches.manage", icon: "list", desc: "Every patch deployment, active and inactive, with what it targets." },
      { label: "Recent Activity", hash: "history", perm: "patches.manage", icon: "clock", desc: "History of every patch job that's run, scheduled or ad-hoc." },
      { label: "Patch Lists", hash: "policies", perm: "patches.manage", icon: "list", desc: "Patch lists say what may be applied, block lists what may not; rules over severity, OS, name and age." },
      { label: "Scan Management", hash: "scanmgmt", perm: "patches.manage", icon: "folder", desc: "Define named repo lists and assign them to hosts, sites, or platforms." },
    ] },

  { label: "Performance", href: "/health", icon: "performance", group: "modules",
    desc: "Endpoint health scores, and the risk each endpoint carries weighted by how much it matters.", sub: [
      { label: "Endpoint Health", hash: "health", icon: "performance", desc: "How each machine is actually doing, scored and banded." },
      { label: "Risk Score", hash: "risk", icon: "scale", desc: "What it would cost if an endpoint were compromised." },
    ] },

  // Administration collects everything that configures mustra itself rather
  // than acting on endpoints, which is the reason
  // Computer Groups and the audit log live here rather than as modules of
  // their own. Each subitem carries its own href where the permission
  // gating a route differs (see subHref/primaryHref below).
  { label: "Administration", href: "/settings", icon: "settings", group: "admin",
    desc: "Groups, access, logging, and how mustra itself is configured.", sub: [
      { label: "Computer Groups", href: "/groups", hash: "groups", icon: "groups", desc: "Reusable slices of the fleet, matched live by hostname, OS, or any sensor." },
      { label: "Audit Log", href: "/logs", hash: "audit", icon: "search", desc: "Every significant action, in one chronological record." },
      { label: "Logging", href: "/logs", hash: "settings", perm: "settings.manage", icon: "sliders", desc: "Log level, and live forwarding to syslog, Splunk, or a SIEM." },
      { label: "Integrations", href: "/settings", hash: "integrations", perm: "settings.manage", icon: "plug", desc: "Every outside system Mustra connects to: identity, MDM, ITSM, SIEM, chat, metrics." },
      { label: "Telemetry", href: "/settings", hash: "telemetry", perm: "settings.manage", icon: "chart", desc: "Host metrics from every endpoint, sent to Prometheus with node_exporter's names." },
      { label: "Single Sign-On", href: "/settings", hash: "sso", perm: "settings.manage", icon: "lock", desc: "Configure OIDC SSO against your identity provider." },
      { label: "SCIM", href: "/settings", hash: "scim", perm: "settings.manage", icon: "sync", desc: "Auto-provision users and groups from your identity provider." },
      { label: "Break-glass Account", href: "/settings", hash: "backdoor", perm: "settings.manage", icon: "door", desc: "The local login that still works when SSO is down." },
      { label: "Agent Behavior", href: "/settings", hash: "agent-behavior", perm: "settings.manage", icon: "discover", desc: "How long an agent may go quiet before it's offline, then dropped, and the address agents connect to." },
      { label: "Agent Identity", href: "/settings", hash: "agent-identity", perm: "settings.manage", icon: "key", desc: "The public URL agents download from, update signing, and the legacy shared credential." },
      { label: "Uninstall Password", href: "/settings", hash: "uninstall-password", perm: "settings.manage", icon: "lock", desc: "A password needed to remove the agent from an endpoint." },
      { label: "macOS MDM", href: "/settings", hash: "macos-mdm", perm: "settings.manage", icon: "shield", desc: "MDM enrollment offered to Macs, and macOS updates through Fleet." },
      { label: "Email", href: "/settings", hash: "email", perm: "settings.manage", icon: "mail", desc: "The SMTP account reports and email integrations send through." },
      { label: "Network Allowlists", href: "/settings", hash: "network-allowlists", perm: "settings.manage", icon: "globe", desc: "The internal hosts the server may reach and import from." },
      { label: "Message Buffer", href: "/settings", hash: "message-buffer", perm: "settings.manage", icon: "database", desc: "How long NATS keeps agents' messages while the server is down." },
      { label: "Directory", href: "/settings", hash: "directory", perm: "settings.manage", icon: "users", desc: "Read users, groups and computers from Active Directory for Impact." },
      { label: "Branding", href: "/settings", hash: "environment", perm: "settings.manage", icon: "globe", desc: "The console logo in the top bar, the rail and the menu." },
      { label: "API Tokens", href: "/settings", hash: "tokens", perm: "settings.manage", icon: "plug", desc: "Scoped tokens so scripts can call the same API the console uses." },
      { label: "Users", href: "/admin", hash: "users", perm: "users.manage", icon: "user", desc: "Local and SSO accounts, admin flags, and role assignment." },
      { label: "Groups", href: "/admin", hash: "groups", perm: "users.manage", icon: "users", desc: "SCIM-synced or local groups, membership, and group roles." },
      { label: "Roles", href: "/admin", hash: "roles", perm: "users.manage", icon: "shield", desc: "Named bundles of permissions assignable to a user or group." },
      { label: "About", href: "/settings", hash: "about", perm: "settings.manage", icon: "info", desc: "Build version, server configuration, update check, and changelog." },
    ] },
];


// subHref/primaryHref: a subitem may point at a different route than its
// parent category (see the Administration comment above). primaryHref is
// what the rail icon and the flyout's own category link use — the first
// permission-visible subitem's route, so a viewer only ever gets sent
// somewhere their permissions actually let them load.
function subHref(cat, s) { return s.href || cat.href; }
// primaryHref is where a category's rail icon goes. It prefers the
// category's own route, falling back to the first subitem the viewer can
// reach — which matters for Administration, where /settings and /admin are
// gated by different permissions and someone holding only users.manage
// must land on /admin rather than a 403.
//
// Preferring cat.href is the fix for a real bug: the fallback used to run
// unconditionally, so a subitem needing no permission at the top of the
// list hijacked the icon. Administration's gear went to Computer Groups.
function primaryHref(cat, u) {
  const sub = (cat.sub || []).filter(s => !s.perm || hasPermission(u, s.perm));
  const ownRoute = sub.find(s => subHref(cat, s) === cat.href);
  if (!cat.sub || ownRoute) return cat.href;
  return sub.length ? subHref(cat, sub[0]) : cat.href;
}

// visibleModules: NAV_TREE entries with a `desc` (i.e. real modules, not
// Home itself) that this viewer can actually reach, A to Z -- what the home
// page's Modules grid renders, one card per module. A module's sections
// are a hover away in the rail's Modules popout and one click away on its
// own page, so the grid stays a list of eighteen-odd places rather than
// eighty-five. Each card carries its sidebar group, which is how Home's
// picker sorts them.
function visibleModules(u) {
  const groupLabel = id => (NAV_GROUPS.find(g => g.id === id) || {}).label || "Modules";
  return NAV_TREE.filter(cat => cat.desc && cat.group !== "home" && categoryVisible(cat, u))
    .sort((a, b) => a.label.localeCompare(b.label))
    .map(cat => ({ label: cat.label, icon: cat.icon, desc: cat.desc, href: primaryHref(cat, u),
      category: groupLabel(cat.group) }));
}

// categoryVisible: a category with its own `perm` needs exactly that; one
// without (Patches, Administration) is visible if the viewer holds any
// subitem's permission, or if it has no gated subitems at all (Endpoints).
function categoryVisible(cat, u) {
  if (cat.perm) return hasPermission(u, cat.perm);
  // Every page without a permission of its own reads the fleet; an
  // account without fleet.read is shown only what it holds a permission for.
  if (!hasPermission(u, "fleet.read")) return (cat.sub || []).some(s => s.perm && hasPermission(u, s.perm));
  if (!cat.sub || cat.sub.length === 0) return true;
  return cat.sub.some(s => !s.perm || hasPermission(u, s.perm));
}

// The nav is two separate pieces, matching the reference layout (a fixed
// icon rail; a menu click pops a labeled panel over the dimmed page,
// closing itself once you're done — pinning keeps it open instead):
//   #sidebar-rail   — always visible, icon-only, never resizes.
//   #sidebar-flyout — hidden until opened; a temporary overlay with a
//                     dimming backdrop unless pinned, in which case it
//                     docks permanently and pushes the page content over.
// The flyout is a per-group popout rather than the whole menu.
//
// It used to be one list of everything, opened by a hamburger. That made
// the rail decorative — the icons were shortcuts to pages, and the actual
// navigating happened in a menu that showed all sixteen modules whichever
// icon you had just looked at. Selecting a group and being shown only that
// group's modules is both fewer things to read and an answer to the
// question you asked.
//
// openGroup is the id of the group currently popped out, or "" for none.
let openGroup = "";

function openFlyout() {
  const flyout = document.getElementById("sidebar-flyout");
  const overlay = document.getElementById("sidebar-overlay");
  if (!flyout) return;
  flyout.classList.add("open");
  if (overlay) overlay.classList.add("show");
}
// Hover handling. The popouts open as the pointer reaches a rail icon and
// close a moment after it leaves both the popout and its submenu, so a
// person can sweep rail -> module -> section in one motion and never click
// to open anything. The short delays are what make that forgiving: the
// close delay survives a diagonal path across a gap, and the hover intent
// stops a pointer just passing over the rail from flashing popouts.
let flyoutOpenedAt = 0, flyoutCloseTimer = 0, hoverIntentTimer = 0;
const canHover = () => !!(window.matchMedia && window.matchMedia("(hover: hover) and (pointer: fine)").matches);
function hoverIntent(fn, delay) {
  clearTimeout(hoverIntentTimer);
  hoverIntentTimer = setTimeout(fn, delay == null ? 70 : delay);
}
function cancelHoverIntent() { clearTimeout(hoverIntentTimer); }
function scheduleFlyoutClose() {
  if (!canHover()) return;
  clearTimeout(flyoutCloseTimer);
  flyoutCloseTimer = setTimeout(() => {
    // Keyboard focus inside a popout keeps it open; only the pointer left.
    const f = document.activeElement;
    if (f && f.closest && f.closest("#sidebar-flyout, #sidebar-subflyout") && f.matches(":focus-visible")) return;
    closeFlyout();
  }, 280);
}
function cancelFlyoutClose() { clearTimeout(flyoutCloseTimer); }

// The section submenu beside a module row: the same panel and rows as the
// popout, positioned against the row it belongs to.
function openSubFlyout(rowEl, entry) {
  const sub = document.getElementById("sidebar-subflyout");
  const flyout = document.getElementById("sidebar-flyout");
  if (!sub || !flyout) return;
  rowEl.classList.add("sub-open");
  sub.innerHTML = `<div class="flyout-header"><a class="flyout-title" href="${escapeHtml(safeUrl(entry.href))}">${escapeHtml(entry.label)}</a></div>
    <nav class="flyout-nav">${entry.subs.map(e => `
      <a class="flyout-item ${e.here ? "active" : ""}" href="${escapeHtml(safeUrl(e.href))}" title="${escapeHtml(e.desc || "")}">
        <span class="icon">${icon(e.icon)}</span><span class="flyout-item-label">${escapeHtml(e.label)}</span>
      </a>`).join("")}</nav>`;
  const fr = flyout.getBoundingClientRect(), rr = rowEl.getBoundingClientRect();
  sub.classList.add("open");
  // Beside the popout when it fits; over it on a window too narrow for both.
  sub.style.left = (fr.right + sub.offsetWidth > window.innerWidth ? fr.left : fr.right - 1) + "px";
  const gap = 8;
  const top = Math.max(gap, Math.min(rr.top - 6, window.innerHeight - sub.offsetHeight - gap));
  sub.style.top = top + "px";
  sub.style.maxHeight = (window.innerHeight - top - gap) + "px";
}
function closeSubFlyout() {
  const sub = document.getElementById("sidebar-subflyout");
  if (sub) { sub.classList.remove("open"); sub.innerHTML = ""; }
  document.querySelectorAll("#sidebar-flyout .sub-open").forEach(x => x.classList.remove("sub-open"));
}

// Arrow keys walk a popout: up/down between rows, right into a row's
// sections, left back out (or back to the rail), Home/End to the ends.
function flyoutKeydown(e) {
  const inSub = !!e.target.closest("#sidebar-subflyout");
  const panel = e.target.closest("#sidebar-flyout, #sidebar-subflyout");
  if (!panel) return;
  const links = Array.from(panel.querySelectorAll(".flyout-nav a"));
  const i = links.indexOf(e.target);
  const go = n => { e.preventDefault(); links[(n + links.length) % links.length]?.focus(); };
  if (e.key === "ArrowDown") go(i + 1);
  else if (e.key === "ArrowUp") go(i - 1);
  else if (e.key === "Home") go(0);
  else if (e.key === "End") go(links.length - 1);
  else if (e.key === "ArrowRight" && !inSub && e.target.dataset.sub != null) {
    e.preventDefault();
    document.querySelector("#sidebar-subflyout .flyout-nav a")?.focus();
  } else if (e.key === "ArrowLeft") {
    e.preventDefault();
    if (inSub) document.querySelector("#sidebar-flyout a.sub-open")?.focus();
    else { const btn = document.querySelector(".rail-icon-link.selected"); closeFlyout(); btn?.focus(); }
  }
}

function closeFlyout() {
  const flyout = document.getElementById("sidebar-flyout");
  const overlay = document.getElementById("sidebar-overlay");
  openGroup = "";
  cancelFlyoutClose();
  closeSubFlyout();
  if (!flyout) return;
  flyout.classList.remove("open");
  // Drop the inline position so the next open measures fresh rather than
  // inheriting where the last one happened to sit.
  flyout.style.top = "";
  flyout.style.maxHeight = "";
  if (overlay) overlay.classList.remove("show");
  document.querySelectorAll(".rail-icon-link.selected")
    .forEach(el => el.classList.remove("selected"));
}

// positionFlyoutBeside lines the popout up with the icon that opened it,
// rather than parking every popout at the top of the rail.
//
// Aligning to the icon keeps the thing you clicked and the thing that
// appeared in the same place, so your eye does not have to travel back up
// to the top to read the answer to a question you asked halfway down.
//
// Measured rather than computed from constants: the rail's offset depends
// on whether the identity banner is on, and a second copy of that
// arithmetic is a second thing to get wrong.
function positionFlyoutBeside(btn) {
  const flyout = document.getElementById("sidebar-flyout");
  const header = document.getElementById("app-topbar");
  if (!flyout || !btn) return;

  const gap = 8;
  const iconTop = btn.getBoundingClientRect().top;
  const minTop = header ? header.getBoundingClientRect().bottom + gap : 60;
  const maxTop = Math.max(minTop, window.innerHeight - flyout.offsetHeight - gap);

  const top = Math.min(Math.max(iconTop, minTop), maxTop);
  flyout.style.top = top + "px";
  // Whatever room is left below it, so a tall popout scrolls rather than
  // running off the bottom of the window.
  flyout.style.maxHeight = (window.innerHeight - top - gap) + "px";
}

// renderTopbar injects the full-width top bar above the app shell. It's
// built here rather than sitting in each page's static markup so all five
// pages get it (and any change to it) without hand-editing five files.
// The search box is a fleet-wide endpoint search: on the Endpoints page it
// filters the table live; anywhere else, Enter takes you there with the
// query applied.
function renderTopbar() {
  if (document.getElementById("app-topbar")) return;
  const shell = document.querySelector(".app-shell");
  if (!shell) return;

  const bar = document.createElement("header");
  bar.className = "app-topbar";
  bar.id = "app-topbar";
  bar.innerHTML = `
    <button type="button" class="nav-toggle" id="nav-toggle" aria-label="Open navigation" aria-expanded="false" aria-controls="sidebar-rail">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
    </button>
    <a class="app-topbar-brand" href="/" title="mustra">
      <span class="brand-icon-slot">${MUSTRA_MARK}</span>
      <span class="app-topbar-brand-name">mustra</span>
    </a>
    <div class="app-topbar-search omni" id="omni">
      <div class="omni-modes" role="tablist" aria-label="Search for">${OMNI_MODES.map(m => `
        <button type="button" role="tab" class="omni-mode" data-mode="${escapeHtml(m.id)}" aria-label="${escapeHtml(m.label)}" aria-selected="false">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${/* safe-html: fixed SVG path constants in OMNI_MODES */ m.glyph}</svg>
          <span class="omni-mode-label">${escapeHtml(m.label)}</span>
          <span class="omni-tip" role="tooltip">${escapeHtml(m.tip)}<span class="omni-tip-sep"></span>Shortcut <span class="omni-keys" data-keys-for="${escapeHtml(m.id)}"></span></span>
        </button>`).join("")}
      </div>
      <div class="omni-field">
        <svg class="omni-glass" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
        <input type="search" id="topbar-search" autocomplete="off" spellcheck="false" role="combobox" aria-expanded="false" aria-controls="topbar-search-results" aria-autocomplete="list">
        <button type="button" id="topbar-search-btn" class="omni-chevron" aria-label="Show all" tabindex="-1">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>
        </button>
      </div>
      <div class="search-results" id="topbar-search-results" role="listbox" hidden></div>
    </div>
    <div class="app-topbar-spacer"></div>
    <div class="guide-bell-wrap">
      <button type="button" class="guide-bell" id="guide-bell" aria-label="Guide notifications" aria-expanded="false" aria-haspopup="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21a2 2 0 0 0 4 0"/></svg>
        <span class="guide-badge" id="guide-badge" hidden>0</span>
      </button>
      <!-- A sibling of the button, not a child: the tray carries links and
           a dismiss button, and interactive content inside a <button> is
           both invalid and unreliable to click. -->
      <div class="guide-tray" id="guide-tray" hidden role="dialog" aria-label="Guide"></div>
    </div>
  `;
  document.body.insertBefore(bar, shell);
  wireTopbarSearch();
  wireGuideBell();
  wireNavToggle();
}

// wireNavToggle drives the phone-width menu button. Below 760px the icon
// rail is off-canvas (see app.css); this only toggles a body class that
// slides it in, and closing it also closes any group popout opened from it.
// It never changes what the rail or popout contain. On wider screens the
// button is hidden and the class has no effect.
function setNavOpen(open) {
  document.body.classList.toggle("nav-open", open);
  const btn = document.getElementById("nav-toggle");
  if (btn) {
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    btn.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
  }
  if (!open) closeFlyout();
}

function wireNavToggle() {
  const btn = document.getElementById("nav-toggle");
  if (!btn) return;
  btn.addEventListener("click", () => setNavOpen(!document.body.classList.contains("nav-open")));
  const overlay = document.getElementById("sidebar-overlay");
  if (overlay) overlay.addEventListener("click", () => setNavOpen(false));
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && document.body.classList.contains("nav-open")) setNavOpen(false);
  });
  // A module link navigates away; drop the open state so a back/forward
  // cache restore doesn't come back with the menu covering the page.
  window.addEventListener("pageshow", () => setNavOpen(false));
}

// Guide: what the console wants an operator to know, in one place. The
// bell polls; the tray lists open items most severe first; a dismissed
// item stays dismissed while its condition persists and comes back if the
// condition goes away and returns.
let guideItems = [];

// True for a click on the bell or anywhere inside its tray. Both the bell's
// own outside-click handler and the top bar's closeAll consult it: the top
// bar listens on document too, and without this it hid the tray in the very
// click that opened it, so the bell looked dead however many items it
// showed a count for.
function guideBellClick(e) {
  const t = e && e.target;
  return !!(t && t.closest && t.closest("#guide-bell, #guide-tray"));
}

function wireGuideBell() {
  const bell = document.getElementById("guide-bell");
  const tray = document.getElementById("guide-tray");
  if (!bell) return;
  bell.addEventListener("click", () => {
    const open = tray.hidden;
    tray.hidden = !open;
    bell.setAttribute("aria-expanded", String(open));
    if (open) renderGuideTray();
  });
  document.addEventListener("click", (e) => {
    if (!guideBellClick(e)) { tray.hidden = true; bell.setAttribute("aria-expanded", "false"); }
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { tray.hidden = true; bell.setAttribute("aria-expanded", "false"); } });
  // Not before the account is known: one that may not read the fleet has
  // no Guide to fetch.
  document.addEventListener("mustra:user", () => refreshGuide(), { once: true });
  setInterval(() => { if (!document.hidden) refreshGuide(); }, 60000);
}
async function refreshGuide() {
  if (!currentUser || !hasPermission(currentUser, "fleet.read")) return;
  try {
    const resp = await fetch("/api/guide");
    if (!resp.ok) return;
    const data = await resp.json();
    guideItems = data.items || [];
    const badge = document.getElementById("guide-badge");
    const c = data.counts || {};
    badge.textContent = String(c.open || 0);
    badge.hidden = !(c.open > 0);
    // The name must contain the count the badge shows (WCAG 2.5.3).
    document.getElementById("guide-bell").setAttribute("aria-label",
      c.open > 0 ? `${c.open} open — Guide notifications` : "Guide notifications");
    badge.classList.toggle("calm", !(c.critical > 0 || c.high > 0));
    if (!document.getElementById("guide-tray").hidden) renderGuideTray();
  } catch (e) { /* the bell is a convenience; a failed poll is not news */ }
}
function renderGuideTray() {
  const tray = document.getElementById("guide-tray");
  const items = guideItems;
  tray.innerHTML = `<div class="guide-tray-head"><strong>Guide</strong><span>${escapeHtml(items.length ? items.length + " open" : "nothing needs you")}</span><a href="/guide">All notifications →</a></div>` +
    (items.length === 0 ? '<div class="guide-empty">Nothing outstanding. Stalled jobs, expiring certificates, agents behind, missing Full Disk Access, new sensitive-data findings and critical Impact findings show up here.</div>'
      : items.slice(0, 12).map(n => `<div class="guide-item ${escapeHtml(n.severity)}"><span class="stripe"></span>
          <div><div class="kind">${escapeHtml(n.kind)} · ${escapeHtml(n.source)}</div><div class="title">${escapeHtml(n.title)}</div><div class="detail">${escapeHtml(n.detail || "")}</div></div>
          <div class="u-d-flex u-fd-column u-gap-6 u-ai-flex-end">${n.link ? `<a class="open" href="${escapeHtml(safeUrl(n.link))}">Open →</a>` : ""}<button class="dismiss" data-dismiss="${escapeHtml(n.id)}" title="Dismiss until it changes">dismiss</button></div></div>`).join(""));
  tray.querySelectorAll("[data-dismiss]").forEach(b => b.addEventListener("click", async (e) => {
    e.stopPropagation();
    await fetch(`/api/guide/${encodeURIComponent(b.dataset.dismiss)}/dismiss`, { method: "POST" });
    refreshGuide();
  }));
}

// --- Top bar search ----------------------------------------------------------
//
// One box, four things to look for, each a button with a keyboard shortcut:
// ask a question (handed to Interact), find an endpoint, open a dashboard or
// report, or jump anywhere in the console with a quick link ("Deploy -
// Deployments"). Results drop under the box and answer as you type; arrow
// keys and Enter pick, the chevron lists everything. The shortcuts are the
// defaults below unless the account has its own (Preferences → Keyboard
// shortcuts).
const OMNI_MODES = [
  { id: "ask", short: "Ask", label: "Ask a question", tip: "Ask a question.", keys: "Ctrl+/", placeholder: "Type a question, for example: get os from all machines",
    glyph: '<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2.5"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>' },
  { id: "endpoints", short: "Search", label: "Search for endpoints", tip: "Search for endpoints.", keys: "Ctrl+;", placeholder: "Search for endpoints: hostname, OS, site or IP",
    glyph: '<rect x="3" y="4" width="11" height="9" rx="1"/><path d="M6 17h5M8.5 13v4"/><rect x="16" y="4" width="5" height="14" rx="1"/><path d="M18.5 15h0"/>' },
  { id: "dashboards", short: "Dashboards", label: "Search dashboards and reports", tip: "Search for dashboards and reports.", keys: "Ctrl+'", placeholder: "Search dashboards and reports",
    glyph: '<path d="M5 20V12M10 20V6M15 20v-9M20 20V9"/>' },
  { id: "links", short: "Links", label: "Navigate with quick links", tip: "Navigate with quick links.", keys: "Ctrl+.", placeholder: "Search for available Quick Links",
    glyph: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>' },
];
const OMNI_DEFAULT_KEYS = Object.fromEntries(OMNI_MODES.map(m => [m.id, m.keys]));
let omniKeys = { ...OMNI_DEFAULT_KEYS };

// "Ctrl+/" from a keydown, or "" for a key that is not a shortcut (a bare
// letter, a lone modifier). Cmd counts as Ctrl so the same binding works on
// a Mac.
function shortcutOf(e) {
  if (["Control", "Meta", "Alt", "Shift"].includes(e.key)) return "";
  const mods = [];
  if (e.ctrlKey || e.metaKey) mods.push("Ctrl");
  if (e.altKey) mods.push("Alt");
  if (e.shiftKey) mods.push("Shift");
  if (!mods.length || (mods.length === 1 && mods[0] === "Shift")) return "";
  const key = e.key.length === 1 ? e.key.toUpperCase().replace("?", "/") : e.key;
  return [...mods, key === " " ? "Space" : key].join("+");
}
function normShortcut(k) { return String(k || "").split("+").map(p => p.length === 1 ? p.toUpperCase() : p).join("+"); }
function keysMarkup(k) { return normShortcut(k).split("+").map(p => `<kbd>${escapeHtml(p)}</kbd>`).join(" + "); }
function setOmniKeys(keys) {
  omniKeys = { ...OMNI_DEFAULT_KEYS, ...(keys || {}) };
  document.querySelectorAll("[data-keys-for]").forEach(el => { el.innerHTML = keysMarkup(omniKeys[el.dataset.keysFor]); });
}

function wireTopbarSearch() {
  const box = document.getElementById("omni");
  const input = document.getElementById("topbar-search");
  const results = document.getElementById("topbar-search-results");
  const chevron = document.getElementById("topbar-search-btn");
  if (!box || !input) return;
  let mode = localStorage.getItem("mustra-omni-mode") || "endpoints";
  if (!OMNI_MODES.some(m => m.id === mode)) mode = "endpoints";
  let items = [], highlighted = -1, open = false;
  const cache = {};
  const params = new URLSearchParams(window.location.search);
  if (params.get("q") && mode === "endpoints") input.value = params.get("q");

  async function getJSON(url) { try { const r = await fetch(url); return r.ok ? await r.json() : {}; } catch (e) { return {}; } }
  const sources = {
    async endpoints() {
      cache.agents ??= (await getJSON("/api/agents")).agents || [];
      return cache.agents.map(a => ({ href: "/endpoint/" + encodeURIComponent(a.agent_id), name: a.hostname,
        meta: [a.os, a.site || "—", (a.ips || [])[0] || ""].filter(Boolean).join(" · "), pill: a.online ? "online" : "offline",
        hay: [a.hostname, a.os, a.arch, a.site, a.agent_id, a.platform, ...(a.ips || [])].join(" ") }));
    },
    async dashboards() {
      if (!cache.dash) {
        const [d, r] = await Promise.all([getJSON("/api/dashboards"), getJSON("/api/reports")]);
        cache.dash = [
          ...(d.dashboards || []).map(x => ({ href: "/dashboards#view/" + encodeURIComponent(x.id), name: x.name, meta: "Dashboard", hay: x.name + " " + (x.description || "") + " dashboard" })),
          ...(r.reports || []).map(x => ({ href: "/reports?report=" + encodeURIComponent(x.id) + "#reports", name: x.name, meta: "Report", hay: x.name + " " + (x.description || "") + " report" })),
        ].sort((a, b) => a.name.localeCompare(b.name));
      }
      return cache.dash;
    },
    async links() {
      if (!cache.links) {
        const u = currentUser;
        const out = [];
        for (const cat of NAV_TREE.filter(c => categoryVisible(c, u))) {
          const subs = (cat.sub || []).filter(x => !x.perm || hasPermission(u, x.perm));
          if (!subs.length || cat.href) out.push({ href: cat.href, name: cat.label, meta: "", hay: cat.label + " " + (cat.desc || "") });
          for (const x of subs) out.push({ href: subHref(cat, x) + (x.hash ? "#" + x.hash : ""), name: `${cat.label} - ${x.label}`, meta: "", hay: `${cat.label} ${x.label} ${x.desc || ""}` });
        }
        cache.links = out.filter(x => x.href).sort((a, b) => a.name.localeCompare(b.name));
      }
      return cache.links;
    },
  };

  function setMode(m, focus) {
    // A different mode starts from an empty box: text typed to find an
    // endpoint means nothing to the dashboard list.
    if (m !== mode) input.value = "";
    mode = m;
    localStorage.setItem("mustra-omni-mode", m);
    const def = OMNI_MODES.find(x => x.id === m);
    box.querySelectorAll(".omni-mode").forEach(b => b.setAttribute("aria-selected", String(b.dataset.mode === m)));
    box.dataset.mode = m;
    // Phones get the short form: the long one was cut to "Search f".
    input.placeholder = window.matchMedia("(max-width: 760px)").matches ? (def.short || def.placeholder) : def.placeholder;
    input.setAttribute("aria-label", def.label);
    chevron.hidden = m === "ask" || m === "endpoints";
    if (focus) { input.focus(); input.select(); }
    if (open || input.value) refresh(m === "links" || m === "dashboards");
  }

  function hide() { results.hidden = true; open = false; highlighted = -1; input.setAttribute("aria-expanded", "false"); }
  function render() {
    if (mode === "ask") {
      const q = input.value.trim();
      results.innerHTML = q ? `<a class="search-result highlighted" role="option" href="/interact#ask?q=${encodeURIComponent(q)}"><span class="search-result-name">Ask: ${escapeHtml(q)}</span><span class="search-result-meta">Enter to run in Interact</span></a>`
        : `<div class="search-empty">Ask about the fleet in plain words, e.g. <em>get os from all machines</em> or <em>get installed applications where name contains chrome</em>.</div>`;
    } else if (!items.length) {
      results.innerHTML = `<div class="search-empty">${mode === "endpoints" ? "No endpoint matches that." : mode === "links" ? "No page matches that." : "No dashboard or report matches that."}</div>`;
    } else {
      results.innerHTML = items.map((it, i) => `<a class="search-result ${i === highlighted ? "highlighted" : ""}" role="option" aria-selected="${i === highlighted}" id="omni-opt-${i}" href="${escapeHtml(safeUrl(it.href))}"${isEndpointLink(it.href) ? ' target="_blank" rel="noopener"' : ""}>
        ${it.pill ? `<span class="badge-pill ${escapeHtml(it.pill)}">${escapeHtml(it.pill)}</span>` : ""}<span class="search-result-name">${escapeHtml(it.name)}</span>${it.meta ? `<span class="search-result-meta">${escapeHtml(it.meta)}</span>` : ""}</a>`).join("");
      const cur = results.querySelector(".highlighted"); cur?.scrollIntoView({ block: "nearest" });
      if (cur) input.setAttribute("aria-activedescendant", cur.id); else input.removeAttribute("aria-activedescendant");
    }
    results.hidden = false; open = true; input.setAttribute("aria-expanded", "true");
  }
  async function refresh(showAll) {
    const term = input.value.toLowerCase().trim();
    if (mode === "ask") { if (term || showAll) render(); else hide(); return; }
    if (!term && !showAll) { hide(); return; }
    const list = await sources[mode]();
    const words = term.split(/\s+/).filter(Boolean);
    // Matches in the name first, then those found only in a description.
    const score = it => words.every(w => it.name.toLowerCase().includes(w)) ? 0 : 1;
    items = list.filter(it => words.every(w => it.hay.toLowerCase().includes(w)))
      .map(it => [score(it), it]).sort((a, b) => a[0] - b[0]).map(x => x[1]);
    if (mode === "endpoints") items = items.slice(0, 12);
    highlighted = term && items.length ? 0 : -1;
    render();
  }
  // An endpoint opens in a new tab, so the page being worked in stays put;
  // everything else (pages, dashboards, reports, Ask) opens here.
  function isEndpointLink(href) { return /^\/endpoint\//.test(href || ""); }
  function go(href) {
    hide();
    if (isEndpointLink(href)) {
      // Not the "noopener" feature: with it window.open always returns null,
      // which would read as blocked. Same origin; the opener is cut anyway.
      const w = window.open(href, "_blank");
      if (w) { w.opener = null; input.value = ""; return; }
    }
    window.location.href = href;
  }
  function submit() {
    const term = input.value.trim();
    if (mode === "ask") { if (term) go("/interact#ask?q=" + encodeURIComponent(term)); return; }
    const pick = items[highlighted] || (items.length === 1 ? items[0] : null);
    if (pick) { go(pick.href); return; }
    if (mode === "endpoints") go(term ? "/?q=" + encodeURIComponent(term) : "/");
  }

  // On a phone only the current mode's button shows; tapping it opens the
  // others as a menu, so the field keeps the width.
  const narrow = window.matchMedia("(max-width: 760px)");
  const modes = box.querySelector(".omni-modes");
  box.querySelectorAll(".omni-mode").forEach(b => b.addEventListener("click", () => {
    if (narrow.matches && b.dataset.mode === mode && !modes.classList.contains("is-open")) { modes.classList.add("is-open"); return; }
    modes.classList.remove("is-open");
    setMode(b.dataset.mode, true);
  }));
  document.addEventListener("click", e => { if (!e.target.closest(".omni-modes")) modes.classList.remove("is-open"); });
  input.addEventListener("input", () => refresh(false));
  input.addEventListener("focus", () => { if (input.value) refresh(false); });
  chevron.addEventListener("mousedown", e => e.preventDefault());
  // A result opened in a new tab leaves this page as it was: close the list.
  results.addEventListener("click", e => {
    const a = e.target.closest("a.search-result[target=_blank]");
    if (a) setTimeout(() => { hide(); input.value = ""; input.blur(); }, 0);
  });
  chevron.addEventListener("click", () => { if (open) hide(); else { input.focus(); refresh(true); } });
  input.addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); submit(); return; }
    if (e.key === "Escape") { if (open) hide(); else input.blur(); return; }
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    if (!open) { refresh(true); return; }
    if (!items.length) return;
    highlighted = e.key === "ArrowDown" ? Math.min(highlighted + 1, items.length - 1) : Math.max(highlighted - 1, 0);
    render();
  });
  document.addEventListener("click", e => { if (!e.target.closest("#omni")) hide(); });
  // The shortcuts work from anywhere, including inside other fields: they
  // need Ctrl (or Cmd), so they never eat ordinary typing.
  document.addEventListener("keydown", e => {
    const k = shortcutOf(e);
    if (!k) return;
    const m = OMNI_MODES.find(x => normShortcut(omniKeys[x.id]) === k);
    if (!m) return;
    e.preventDefault();
    setMode(m.id, true);
    if (m.id === "links" || m.id === "dashboards") refresh(true);
  });
  setOmniKeys(omniKeys);
  setMode(mode, false);
}

// applyBranding swaps every brand mark for the admin-uploaded logo, once
// /api/me tells us there is one. The default mark stays in the markup so
// the chrome renders correctly before that response lands (and for anyone
// who never uploads one).
function applyBranding(u) {
  if (!u || !u.logo_url) return;
  document.querySelectorAll(".brand-icon-slot").forEach(slot => {
    slot.innerHTML = `<img class="brand-logo-img" src="${escapeHtml(safeUrl(u.logo_url))}" alt="">`;
  });
}

// renderSidebarShell builds the static chrome for both pieces — called
// immediately so the rail (and its theme toggle) works without waiting on
// /api/me, unlike the nav content itself (which needs permissions to
// decide what to show).
function renderSidebarShell() {
  const rail = document.getElementById("sidebar-rail");
  const flyout = document.getElementById("sidebar-flyout");
  if (!rail || !flyout) return;

  renderTopbar();

  // No hamburger. It opened a menu of everything, which made the rail
  // decorative — you picked an icon and then had to find the module again
  // in a list that ignored what you had picked. The rail icons are the menu
  // now.
  // No brand mark at the top of the rail either. The top bar already
  // carries it, and the rail is sticky under a 52px topbar, so the mark sat
  // half-clipped behind it — a logo you can only see the bottom of is worse
  // than none. Home is the first icon and goes to the same place.
  // Two navigation landmarks on every page: each needs its own name, or
  // a screen reader's landmark list shows "navigation" twice.
  rail.setAttribute("aria-label", "Navigation rail");
  flyout.setAttribute("aria-label", "Module sections");
  rail.innerHTML = `
    <nav class="rail-nav" id="rail-nav" aria-label="Modules"></nav>
    <div class="rail-footer">
      <a class="rail-icon-link${window.location.pathname === "/help" ? " active" : ""}" href="/help" title="Help" aria-label="Help"${window.location.pathname === "/help" ? ' aria-current="page"' : ""}>${railIcon("help")}</a>
      <button type="button" class="rail-icon-link" id="rail-settings-btn" title="Preferences" aria-label="Preferences">${railIcon("settings")}</button>
    </div>
  `;
  // The foot of the rail is Preferences (theme, palette, time zone), where
  // Tanium keeps its settings gear. It replaced a bare light/dark toggle;
  // the same switch is the first thing in Preferences.
  document.getElementById("rail-settings-btn").addEventListener("click", openPreferences);
  flyout.innerHTML = `
    <div class="flyout-header" id="flyout-header"></div>
    <nav class="flyout-nav" id="flyout-nav" aria-label="Module sections"></nav>
  `;

  // The section submenu lives beside the popout, not inside it, so the
  // popout's own scrolling never clips it.
  let sub = document.getElementById("sidebar-subflyout");
  if (!sub) {
    sub = document.createElement("aside");
    sub.className = "sidebar-flyout sidebar-subflyout";
    sub.id = "sidebar-subflyout";
    flyout.after(sub);
  }

  document.getElementById("sidebar-overlay").addEventListener("click", closeFlyout);
  // Choosing a module closes the popout so it doesn't linger over the page
  // it just took you to.
  for (const panel of [flyout, sub]) {
    panel.addEventListener("click", (e) => {
      if (e.target.closest("a")) closeFlyout();
    });
    panel.addEventListener("mouseenter", cancelFlyoutClose);
    panel.addEventListener("mouseleave", scheduleFlyoutClose);
    panel.addEventListener("keydown", flyoutKeydown);
  }
  // A popout row without sections closes the submenu as the pointer arrives.
  flyout.addEventListener("mouseover", e => {
    const a = e.target.closest("a.flyout-link");
    if (a) closeSubFlyout();
  });
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeFlyout(); });
}

function expandedCategories() {
  try { return new Set(JSON.parse(localStorage.getItem("mustra-nav-expanded") || "[]")); } catch (e) { return new Set(); }
}
function saveExpandedCategories(set) {
  try { localStorage.setItem("mustra-nav-expanded", JSON.stringify(Array.from(set))); } catch (e) {}
}

// renderSidebarNav fills in the rail's icons and the flyout's labeled
// tree, once the viewer's permissions are known (called from loadUser()).
// A category or subcategory with a `perm` is simply omitted if the viewer
// doesn't hold it — same policy the server enforces on the route itself,
// so there are no dead links to a 403.
// resolveNavEntry finds one labelled entry inside a group — either a module
// or one of a module's subitems — and returns where it goes.
//
// Referenced by label rather than duplicated into the column definition so
// there stays exactly one definition of each destination. A label that
// matches nothing returns null and is simply not drawn: a column entry
// pointing nowhere is worse than a shorter column, and it also means a
// subitem the viewer lacks permission for disappears rather than 403ing.
function resolveNavEntry(group, label, u) {
  const mods = NAV_TREE.filter(c => (c.group || "admin") === group.id && categoryVisible(c, u));
  const path = window.location.pathname;
  const hash = window.location.hash.replace("#", "");

  for (const cat of mods) {
    if (cat.label === label) {
      return { label: cat.label, href: primaryHref(cat, u), desc: cat.desc, here: path === cat.href };
    }
    for (const sub of cat.sub || []) {
      if (sub.label !== label) continue;
      if (sub.perm && !hasPermission(u, sub.perm)) return null;
      const href = subHref(cat, sub);
      return {
        label: sub.label,
        href: href + (sub.hash ? "#" + sub.hash : ""),
        desc: sub.desc,
        here: path === href && (!sub.hash || hash === sub.hash),
      };
    }
  }
  return null;
}

// The saved dashboards listed in the Dashboards popout; null until fetched.
let navDashboards = null;

function renderSidebarNav(u) {
  const railNav = document.getElementById("rail-nav");
  const flyoutNav = document.getElementById("flyout-nav");
  if (!railNav || !flyoutNav) return;
  const path = window.location.pathname;
  const hash = window.location.hash.replace("#", "");
  const expanded = expandedCategories();
  const cats = NAV_TREE.filter(cat => categoryVisible(cat, u));

  // A category is "on this page" if the current path matches its own href
  // or any of its subitems' (possibly different) href — Administration's
  // subitems split across /settings and /admin, so either counts.
  function catOnThisPage(cat) {
    return path === cat.href || (cat.sub || []).some(s => subHref(cat, s) === path);
  }

  // Modules for one group, permission-filtered. The all-modules group holds
  // every real module (anything with a description), alphabetically.
  const groupModules = g => g.all
    ? cats.filter(c => c.desc && c.group !== "home").sort((a, b) => a.label.localeCompare(b.label))
    : cats.filter(c => (c.group || "admin") === g.id);
  const visibleGroups = NAV_GROUPS.filter(g => groupModules(g).length > 0);
  // The all-modules icon is "you are here" only for the modules filed under
  // it; a module that has its own group (Interact under Tools) lights that
  // group's icon instead, never both.
  const groupOnThisPage = g => g.all
    ? cats.some(c => c.group === g.id && catOnThisPage(c))
    : groupModules(g).some(catOnThisPage);

  // One module's sections as popout entries, or [] when it has none.
  function sectionEntries(cat) {
    return (cat.sub || []).filter(sn => !sn.perm || hasPermission(u, sn.perm)).map(sn => {
      const href = subHref(cat, sn);
      return {
        label: sn.label, desc: sn.desc, icon: sn.icon || cat.icon,
        href: href + (sn.hash ? "#" + sn.hash : ""),
        here: path === href && (!sn.hash || hash === sn.hash),
      };
    });
  }

  // What a group's popout would contain: its modules when there are
  // several (each carrying its sections for the hover submenu), and that
  // module's own sections when there is only one.
  //
  // Popping out the sections matters — Interact is one module with three
  // sections, and sending someone straight to the page meant the rail could
  // not show them Query / Saved Queries / Query History at all. The rule is
  // simply "show whatever is one level down", whatever that happens to be.
  function popoutEntries(g) {
    const entries = popoutModuleEntries(g);
    // Dashboards also lists the dashboards themselves, so the one you want
    // is one click from anywhere rather than two and a scan of a table.
    if (entries && g.id === "reporting" && navDashboards && navDashboards.length) {
      entries.push({ heading: "Saved dashboards" });
      for (const d of navDashboards) {
        entries.push({ label: d.name, desc: d.description || "", icon: "chart",
          href: `/dashboards#view/${encodeURIComponent(d.id)}`, here: path === "/dashboards" && hash === `view/${d.id}` });
      }
    }
    return entries;
  }
  function popoutModuleEntries(g) {
    const mods = groupModules(g);
    if (mods.length > 1 || g.all) {
      return mods.map(cat => ({
        label: cat.label, desc: cat.desc, icon: cat.icon,
        href: primaryHref(cat, u), here: catOnThisPage(cat),
        subs: sectionEntries(cat),
      }));
    }
    if (mods.length === 1) {
      const subs = sectionEntries(mods[0]);
      if (subs.length > 0) return subs;
    }
    return null; // nothing one level down — the icon is just a link
  }

  railNav.innerHTML = visibleGroups.map(g => {
    const mods = groupModules(g);
    const active = groupOnThisPage(g);
    // A group with nothing one level down navigates directly rather than
    // popping out: a popout listing a single destination is a click spent
    // being told what you already chose. Home, Guide and Dashboards each
    // qualify, which is why they are three groups and not one.
    if (!popoutEntries(g)) {
      return `<a href="${escapeHtml(safeUrl(primaryHref(mods[0], u)))}" class="rail-icon-link ${active ? "active" : ""}"
                 title="${escapeHtml(g.label)}" data-tip="${escapeHtml(g.label)}">${railIcon(g.icon)}</a>`;
    }
    return `<button type="button" class="rail-icon-link ${active ? "active" : ""}" data-group="${escapeHtml(g.id)}"
                    title="${escapeHtml(g.label)}" aria-haspopup="true" aria-expanded="false">${railIcon(g.icon)}</button>`;
  }).join("");

  // One row of any popout. Every popout draws its rows here, so they all
  // look and behave the same: label, the module's icon, the description as
  // a tooltip, and a chevron when there are sections to hover into.
  const row = (e, i) => e.heading
    ? `<div class="flyout-heading">${escapeHtml(e.heading)}</div>`
    : `<a class="flyout-item ${e.here ? "active" : ""}" href="${escapeHtml(safeUrl(e.href))}"
          title="${escapeHtml(e.desc || "")}" ${e.subs && e.subs.length ? `data-sub="${/* safe-html: array index */ i}" aria-haspopup="true"` : ""}>
         <span class="icon">${icon(e.icon)}</span>
         <span class="flyout-item-label">${escapeHtml(e.label)}</span>
         ${e.subs && e.subs.length ? `<span class="flyout-chevron" aria-hidden="true">›</span>` : ""}
       </a>`;

  function openGroupPopout(btn, viaKeyboard) {
    const id = btn.dataset.group;
    const g = NAV_GROUPS.find(x => x.id === id);
    if (!g) return;
    if (openGroup === id) return;

    document.querySelectorAll(".rail-icon-link.selected").forEach(el => el.classList.remove("selected"));
    btn.classList.add("selected");
    railNav.querySelectorAll("[data-group]").forEach(b =>
      b.setAttribute("aria-expanded", b === btn ? "true" : "false"));
    openGroup = id;
    closeSubFlyout();

    document.getElementById("flyout-header").innerHTML =
      `<span class="flyout-title" title="${escapeHtml(g.desc || "")}">${escapeHtml(g.label)}</span>`;

    const flyout = document.getElementById("sidebar-flyout");
    flyout.classList.toggle("wide", !!g.columns);

    if (g.columns) {
      // Columns order this group; they do not decide what is in it. A
      // module the columns do not name is appended to the last one rather
      // than dropped -- silently omitting it is how Backup shipped with a
      // page, a permission and no way to reach it but typing the URL.
      const named = new Set(g.columns.flatMap(col => col.items));
      const unlisted = NAV_TREE
        .filter(c => (c.group || "admin") === g.id && categoryVisible(c, u) && !named.has(c.label) && !(g.omit || []).includes(c.label))
        .map(c => c.label);
      const columns = unlisted.length
        ? g.columns.map((col, i) => i === g.columns.length - 1
            ? { ...col, items: col.items.concat(unlisted) } : col)
        : g.columns;

      flyoutNav.innerHTML = `<div class="flyout-columns">` + columns.map(col => {
        const entries = col.items.map(label => resolveNavEntry(g, label, u)).filter(Boolean);
        if (entries.length === 0) return "";
        return `
          <div class="flyout-col">
            <div class="flyout-col-head">${escapeHtml(col.label)}</div>
            ${entries.map(e => `
              <a class="flyout-link ${e.here ? "active" : ""}" href="${escapeHtml(safeUrl(e.href))}"
                 title="${escapeHtml(e.desc || "")}">${escapeHtml(e.label)}</a>`).join("")}
          </div>`;
      }).join("") + `</div>`;
    } else {
      let entries = [];
      const draw = () => {
        entries = popoutEntries(g) || [];
        flyoutNav.innerHTML = entries.map(row).join("");
        paintIcons(flyoutNav);
        wireSubRows(flyoutNav, i => entries[i]);
      };
      draw();
      // Fetched on first open (and refreshed each open after) so a new
      // dashboard appears without a reload; the sections show meanwhile.
      if (id === "reporting") {
        fetch("/api/dashboards").then(r => r.ok ? r.json() : null).then(d => {
          if (!d) return;
          navDashboards = (d.dashboards || []).map(x => ({ id: x.id, name: x.name, description: x.description }))
            .sort((a, b) => a.name.localeCompare(b.name));
          if (openGroup === "reporting") draw();
        }).catch(() => {});
      }
    }

    openFlyout();
    positionFlyoutBeside(btn);
    if (viaKeyboard) flyoutNav.querySelector("a")?.focus();
  }

  // Hovering a row with sections shows them beside it; so does focusing it
  // from the keyboard. The submenu is one element shared by every popout.
  function wireSubRows(nav, entryAt) {
    nav.querySelectorAll("a.flyout-item").forEach(a => {
      const show = () => {
        nav.querySelectorAll("a.flyout-item.sub-open").forEach(x => x.classList.remove("sub-open"));
        if (a.dataset.sub == null) { closeSubFlyout(); return; }
        const e = entryAt(Number(a.dataset.sub));
        if (e) openSubFlyout(a, e);
      };
      // Only a real pointer or the keyboard opens the sections. A tap fires
      // mouseenter and focus too; opening the submenu there changed the page
      // mid-tap, so iOS treated the tap as a hover and dropped the click --
      // the menu closed and the module never opened. On touch a tap goes to
      // the module, whose sections are its tabs.
      a.addEventListener("mouseenter", () => { if (canHover()) hoverIntent(show); });
      a.addEventListener("focus", () => { if (canHover() || a.matches(":focus-visible")) show(); });
    });
  }

  railNav.querySelectorAll("[data-group]").forEach(btn => {
    btn.addEventListener("click", e => {
      e.stopPropagation();
      cancelFlyoutClose();
      // A click on the icon whose popout is already open closes it -- unless
      // hover opened it a moment ago, when the click is the same intent.
      if (openGroup === btn.dataset.group) {
        if (Date.now() - flyoutOpenedAt > 400) closeFlyout();
        return;
      }
      openGroupPopout(btn, e.detail === 0);
      flyoutOpenedAt = Date.now();
    });
    // Hover opens on a pointer that can hover; touch keeps click-to-open.
    btn.addEventListener("mouseenter", () => {
      if (!canHover()) return;
      cancelFlyoutClose();
      hoverIntent(() => { if (openGroup !== btn.dataset.group) { openGroupPopout(btn); flyoutOpenedAt = Date.now(); } }, openGroup ? 0 : 90);
    });
    btn.addEventListener("mouseleave", () => { cancelHoverIntent(); scheduleFlyoutClose(); });
    btn.addEventListener("keydown", e => {
      if (e.key === "ArrowRight" || e.key === "ArrowDown") { e.preventDefault(); openGroupPopout(btn, true); }
    });
  });
  // Links on the rail close any popout as the pointer passes over them, so
  // sliding down the rail always shows what is under the pointer.
  railNav.querySelectorAll("a.rail-icon-link").forEach(a => {
    a.addEventListener("mouseenter", () => { if (canHover() && openGroup) { cancelHoverIntent(); closeFlyout(); } });
  });
}

// renderPageHead draws the header every module page opens with: the
// module's mark, an eyebrow naming the product, the page's own name at
// display size, and any page-level actions on the right. Driven from
// NAV_TREE so a page's icon and description never drift from its menu
// entry.
function renderPageHead(containerID, href, opts) {
  const el = document.getElementById(containerID);
  if (!el) return;
  opts = opts || {};
  const cat = NAV_TREE.find(c => c.href === href) || {};
  el.className = "page-head";
  el.innerHTML = `
    <div class="page-head-mark">${icon(opts.icon || cat.icon)}</div>
    <div class="page-head-text">
      <h1 class="page-title">${escapeHtml(opts.title || cat.label || "")}</h1>
      ${(opts.sub || cat.desc) ? `<div class="page-sub">${escapeHtml(opts.sub || cat.desc)}</div>` : ""}
    </div>
    <div class="page-head-actions" id="${escapeHtml(containerID)}-actions"></div>
  `;
  addPageHelpLink(el, href);
}

// The guide index, fetched once per page load; each guide names the pages
// it explains, so a page header can link to its own.
let helpIndexPromise = null;
function helpIndex() {
  if (!helpIndexPromise) {
    helpIndexPromise = fetch("/api/help").then(r => r.ok ? r.json() : { guides: [] }).then(d => d.guides || []).catch(() => []);
  }
  return helpIndexPromise;
}

// Pages that draw their own header (Client Management, Patch,
// Administration, an endpoint) get the same link, in a row of its own at
// the top of the page.
async function addFallbackHelpLink() {
  if (document.querySelector(".page-head") || location.pathname === "/help") return;
  const main = document.querySelector("main");
  if (!main) return;
  const path = location.pathname.startsWith("/endpoint/") ? "/endpoint" : location.pathname;
  const guide = (await helpIndex()).find(g => (g.pages || []).includes(path));
  if (!guide || document.querySelector(".page-help-link") || document.querySelector(".page-head")) return;
  const row = document.createElement("div");
  row.className = "page-help-row";
  const a = document.createElement("a");
  a.className = "page-help-link";
  a.href = "/help#" + encodeURIComponent(guide.slug);
  a.title = "Step-by-step guide: " + guide.title;
  a.innerHTML = /* safe-html: fixed icon markup and a fixed label */ icon("info") + "<span>Guide</span>";
  row.appendChild(a);
  main.prepend(row);
}

async function addPageHelpLink(head, href) {
  if (!href || href === "/help") return;
  const guide = (await helpIndex()).find(g => (g.pages || []).includes(href));
  if (!guide || head.querySelector(".page-help-link")) return;
  document.querySelectorAll(".page-help-row").forEach(r => r.remove());
  const a = document.createElement("a");
  a.className = "page-help-link";
  a.href = "/help#" + encodeURIComponent(guide.slug);
  a.title = "Step-by-step guide: " + guide.title;
  a.innerHTML = /* safe-html: fixed icon markup and a fixed label */ icon("info") + "<span>Guide</span>";
  head.appendChild(a);
}

// initFolds makes any .fold section collapsible, remembering each one's
// state per browser. Wrapped in try/catch because a private window throws
// on localStorage rather than returning empty.
function initFolds() {
  document.querySelectorAll(".fold").forEach(fold => {
    const key = "mustra-fold-" + (fold.id || "");
    let collapsed = false;
    try { collapsed = localStorage.getItem(key) === "1"; } catch (e) {}
    if (collapsed) fold.classList.add("collapsed");
    const head = fold.querySelector(".fold-head");
    if (!head || head.dataset.bound) return;
    head.dataset.bound = "1";
    head.addEventListener("click", () => {
      const nowCollapsed = fold.classList.toggle("collapsed");
      try { localStorage.setItem(key, nowCollapsed ? "1" : "0"); } catch (e) {}
    });
  });
}

// renderQuickLinks draws a module's own subcategories as a labeled row of
// shortcuts at the top of its page — the same set the flyout lists, but
// reachable without opening the menu. Driven by NAV_TREE so a new
// subcategory appears here the moment it's added, already permission-gated.
// `extra` appends cross-module links a page wants to offer alongside them.
function renderQuickLinks(containerID, categoryHref, u, extra) {
  const el = document.getElementById(containerID);
  if (!el) return;
  const cat = NAV_TREE.find(c => c.href === categoryHref);
  if (!cat) return;
  const own = (cat.sub || [])
    .filter(s => !s.perm || hasPermission(u, s.perm))
    .map(s => ({ href: `${subHref(cat, s)}#${s.hash}`, icon: s.icon || cat.icon, label: s.label }));
  const related = extra || [];
  if (own.length + related.length === 0) { el.innerHTML = ""; return; }
  // The module's own sections first; pages in other modules follow under
  // "Related", so a link that leaves the module (Patches → Risk &
  // Compliance) no longer reads as one of its sections.
  const link = (l, cls = "") => `<a class="quick-link${/* safe-html: a fixed class name from this function */ cls}" href="${escapeHtml(safeUrl(l.href))}"><span class="ql-icon">${icon(l.icon)}</span>${escapeHtml(l.label)}</a>`;
  el.innerHTML = `
    <div class="quick-links-title">Quick links</div>
    <div class="quick-links">
      ${own.map(l => link(l)).join("")}
      ${related.length ? `<span class="quick-links-related-group"><span class="quick-links-related" role="separator" aria-label="Related pages in other modules">Related</span>${related.map(l => link(l, " is-related")).join("")}</span>` : ""}
    </div>
  `;
}

// initModuleSections powers the persistent secondary sidebar a module page
// (Administration, Patches) shows next to its content — a fixed list of
// this module's sections, and only the one matching the URL hash rendered
// in <main> at a time (falling back to the first item). `items` is
// pre-filtered by the calling page to whatever the viewer's permissions
// actually unlock, since that varies by page (e.g. Administration's items
// split across settings.manage and users.manage).
// renderModuleSubnav draws a whole category's sections, including the ones
// that live on other routes. Administration spans /settings, /admin,
// /groups and /logs; a subnav that only understood same-page hashes left
// three of those pages with no way back, which is exactly how Computer
// Groups ended up looking like a dead end.
// siblingModuleLinks lists the other modules in this one's group.
//
// The popout and this sidebar both say "Administration" and meant different
// things by it: the popout draws the whole group, this drew one module's own
// sections. Access, Connect, Reports and Backup were in the popout and
// absent from the list beside the page, which reads as the list being wrong
// rather than as two different scopes.
function siblingModuleLinks(cat, u, path) {
  const group = cat.group || "admin";
  // "Modules" holds every module with no group of its own; listing a dozen
  // unrelated modules as siblings would bury the page's own sections.
  if (group === "modules") return "";
  const own = new Set((cat.sub || []).map(s => s.label));
  const siblings = NAV_TREE.filter(c =>
    c !== cat && (c.group || "admin") === group && !own.has(c.label) && categoryVisible(c, u));
  if (!siblings.length) return "";
  return `<div class="module-subnav-head">Also in ${escapeHtml(cat.label)}</div>` +
    siblings.map(c => {
      const href = primaryHref(c, u);
      const active = path === c.href;
      return `<a href="${escapeHtml(safeUrl(href))}" ` +
             `class="module-subnav-link ${active ? "active" : ""}">${escapeHtml(c.label)}</a>`;
    }).join("");
}

// The section menu's pin (see .subnav-pin in app.css). Drawn into the menu
// each time it renders; the state is the subnav-unpinned class on <html>.
const SUBNAV_KEY = "mustra-subnav-unpinned";
try { if (localStorage.getItem(SUBNAV_KEY) === "1") document.documentElement.classList.add("subnav-unpinned"); } catch (e) {}
function decorateSubnav(nav) {
  // An icon beside every section, from the same NAV_TREE entries the
  // flyout and Quick links draw theirs from.
  nav.querySelectorAll(".module-subnav-link").forEach(a => {
    if (!a.title) { const d = subnavDescFor(a.textContent.trim()); if (d) a.title = d; }
    if (a.querySelector(".ic")) return;
    const name = subnavIconFor(a.textContent.trim());
    if (name) a.insertAdjacentHTML("afterbegin", icon(name));
  });
  const unpinned = document.documentElement.classList.contains("subnav-unpinned");
  const pin = document.createElement("button");
  pin.type = "button"; pin.className = "subnav-pin";
  pin.setAttribute("aria-pressed", String(!unpinned));
  pin.title = unpinned ? "Pin this menu open" : "Unpin this menu: it folds to the side and the page takes the width";
  pin.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${unpinned
    ? '<path d="M9 4h6l-1 6 3 3H7l3-3z"/><path d="M12 13v7"/>'
    : '<path d="M9 4h6l-1 6 3 3H7l3-3z"/><path d="M12 13v7"/><path d="M4 4l16 16"/>'}</svg>${unpinned ? "Pin" : "Unpin"}`;
  pin.addEventListener("click", () => {
    const now = !document.documentElement.classList.toggle("subnav-unpinned");
    try { localStorage.setItem(SUBNAV_KEY, now ? "0" : "1"); } catch (e) {}
    pin.blur();
    decorateSubnav(nav);
  });
  nav.querySelector(":scope > .subnav-pin")?.remove();
  nav.querySelector(":scope > .subnav-tab")?.remove();
  nav.prepend(pin);
  const tab = document.createElement("span");
  tab.className = "subnav-tab"; tab.setAttribute("aria-hidden", "true");
  tab.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg>';
  nav.append(tab);
}

function renderModuleSubnav(catHref, u) {
  const nav = document.getElementById("module-subnav");
  if (!nav) return;
  const cat = NAV_TREE.find(c => c.href === catHref);
  if (!cat || !cat.sub) return;
  const path = window.location.pathname;

  function render() {
    // "#builder?q=…" is the builder section with a query handed to it.
    const hash = window.location.hash.replace("#", "").split("?")[0];
    const visible = cat.sub.filter(s => !s.perm || hasPermission(u, s.perm));
    // The one section this URL shows: the hash's, or with no (or an
    // unknown) hash the page's first. Treating "no hash" as matching every
    // section once marked all of a page's entries active at the same time.
    const onPage = cat.sub.filter(s => subHref(cat, s) === path);
    const want = onPage.some(s => s.hash === hash) ? hash : (onPage[0] || {}).hash;
    nav.innerHTML = visible
      .map(s => {
        const href = subHref(cat, s);
        const active = href === path && s.hash === want;
        return `<a href="${escapeHtml(safeUrl(href))}#${escapeHtml(s.hash)}" ` +
               `class="module-subnav-link ${active ? "active" : ""}">${escapeHtml(s.label)}</a>`;
      }).join("") + siblingModuleLinks(cat, u, path);
    decorateSubnav(nav);
    // Only toggle sections that actually exist on this page.
    const sections = document.querySelectorAll(".module-section");
    if (sections.length > 0) {
      sections.forEach(el => { el.hidden = el.id !== `section-${want}`; });
    }
    revealActiveSubnavLink(nav);
  }
  window.addEventListener("hashchange", render);
  render();
}

function initModuleSections(items) {
  const nav = document.getElementById("module-subnav");
  if (!nav || !items || items.length === 0) return;
  // An item with an href is a link to a section on another page, listed
  // here because it belongs with this module too.
  const here = items.filter(i => !i.href);
  function currentHash() {
    const h = window.location.hash.replace("#", "").split("?")[0];
    return here.some(i => i.hash === h) ? h : here[0].hash;
  }
  function render() {
    const active = currentHash();
    nav.innerHTML = items.map(i =>
      `<a href="${escapeHtml(i.href ? safeUrl(i.href) : "")}#${escapeHtml(i.hash)}" class="module-subnav-link ${!i.href && i.hash === active ? "active" : ""}">${escapeHtml(i.label)}</a>`
    ).join("");
    decorateSubnav(nav);
    document.querySelectorAll(".module-section").forEach(el => {
      el.hidden = el.id !== `section-${active}`;
    });
    revealActiveSubnavLink(nav);
  }
  window.addEventListener("hashchange", render);
  render();
}

// revealActiveSubnavLink scrolls the section strip sideways so the active
// entry is visible. On a phone the strip scrolls horizontally, and an
// active section further along (Software, Deployments) started off-screen.
// Only the strip's own scrollLeft moves: scrollIntoView would also scroll
// the page.
function revealActiveSubnavLink(nav) {
  const a = nav && nav.querySelector(".module-subnav-link.active");
  if (!a || nav.scrollWidth <= nav.clientWidth) return;
  const nr = nav.getBoundingClientRect(), ar = a.getBoundingClientRect();
  if (ar.left >= nr.left && ar.right <= nr.right) return;
  nav.scrollLeft += (ar.left - nr.left) - (nr.width - ar.width) / 2;
}

// --- Local error log -------------------------------------------------
//
// A "Local Error Log" in the profile menu is a good idea worth borrowing:
// when a console page misbehaves, the person who saw it is rarely the
// person who can open a browser devtools console, and by the time anyone
// asks, the error is gone. Capturing client-side errors where the user can
// read them back turns "it broke earlier" into something reportable.
//
// Kept in localStorage, capped, and per-browser — these are this viewer's
// errors, not the fleet's, and shipping them to the server would make a
// logging pipeline out of what is meant to be a glovebox.
const ERROR_LOG_KEY = "mustra-error-log";
const ERROR_LOG_MAX = 50;

function recordLocalError(kind, message, detail) {
  try {
    const log = readLocalErrors();
    log.unshift({ at: new Date().toISOString(), kind, message: String(message || ""), detail: String(detail || "") });
    localStorage.setItem(ERROR_LOG_KEY, JSON.stringify(log.slice(0, ERROR_LOG_MAX)));
  } catch (e) { /* a private window throws rather than returning empty */ }
}

function readLocalErrors() {
  try { return JSON.parse(localStorage.getItem(ERROR_LOG_KEY) || "[]"); } catch (e) { return []; }
}

function clearLocalErrors() {
  try { localStorage.removeItem(ERROR_LOG_KEY); } catch (e) {}
}

window.addEventListener("error", e => {
  recordLocalError("error", e.message, `${e.filename || "?"}:${e.lineno || 0}`);
});
window.addEventListener("unhandledrejection", e => {
  recordLocalError("promise", (e.reason && e.reason.message) || e.reason, "unhandled rejection");
});

// --- Top bar: notifications and the profile menu ----------------------
//
// Both live top-right on every page, injected here rather than added to
// each page's markup: there are eighteen pages, and an identity control
// that only appears on some of them is worse than none, because "where do I
// sign out" becomes page-dependent.
//
// They mount *inside* .app-topbar, after the Guide bell, rather than
// floating over the window. As a fixed overlay anchored 14px from the right
// this group landed exactly on top of the Guide bell, which is anchored to
// the same edge by the bar's own padding — the profile avatar covered it.
// In the flow the bar lays all three out itself and nothing can collide.

function installTopBar() {
  if (document.getElementById("mustra-topbar")) return;
  // renderSidebarShell() builds .app-topbar synchronously on load and this
  // runs after /api/me resolves, so the host is always there on the pages
  // that load app.js — all of which carry the shell. Login does not.
  const host = document.getElementById("app-topbar");
  if (!host) return;
  const bar = document.createElement("div");
  bar.className = "topbar";
  bar.id = "mustra-topbar";
  bar.innerHTML = `
    <button class="topbar-btn" id="notif-btn" title="Notifications" aria-label="Notifications" aria-haspopup="true" aria-expanded="false">
      ${icon("alert")}<span class="topbar-badge" id="notif-badge" hidden>0</span>
    </button>
    <span class="topbar-sep"></span>
    <button class="topbar-btn" id="profile-btn" title="Account" aria-label="Account" aria-haspopup="true" aria-expanded="false">
      <span class="avatar" id="profile-initials">·</span>
    </button>
    <div class="topbar-menu" id="notif-menu" hidden></div>
    <div class="topbar-menu" id="profile-menu" hidden></div>
  `;
  host.appendChild(bar);

  const closeAll = (e) => {
    ["notif-menu", "profile-menu"].forEach(id => { document.getElementById(id).hidden = true; });
    ["notif-btn", "profile-btn"].forEach(id => document.getElementById(id).setAttribute("aria-expanded", "false"));
    // These buttons stop the click from reaching the document, so the Guide
    // bell's own outside-click handler never runs — without this, opening
    // the profile menu leaves the tray open underneath it. The bell's own
    // clicks do reach here, though, so they are exempt: closing on them
    // undid the open the same click had just performed.
    const tray = document.getElementById("guide-tray");
    if (tray && !tray.hidden && !guideBellClick(e)) {
      tray.hidden = true;
      document.getElementById("guide-bell")?.setAttribute("aria-expanded", "false");
    }
  };
  const toggle = (btnID, menuID, onOpen) => {
    const btn = document.getElementById(btnID), menu = document.getElementById(menuID);
    btn.addEventListener("click", e => {
      e.stopPropagation();
      const wasOpen = !menu.hidden;
      closeAll();
      if (!wasOpen) {
        menu.hidden = false;
        btn.setAttribute("aria-expanded", "true");
        if (onOpen) onOpen();
      }
    });
    menu.addEventListener("click", e => e.stopPropagation());
  };
  toggle("profile-btn", "profile-menu");
  toggle("notif-btn", "notif-menu", loadNotifications);
  document.addEventListener("click", closeAll);
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeAll(); });
}

function initialsFor(u) {
  const src = (u.display_name || u.username || "?").trim();
  const parts = src.split(/[\s._-]+/).filter(Boolean);
  const letters = parts.length >= 2 ? parts[0][0] + parts[1][0] : src.slice(0, 2);
  return letters.toUpperCase();
}

function renderProfileMenu(u) {
  const identity = u.email
    ? `${u.email}${u.display_name ? ` [${u.display_name}]` : ""}`
    : (u.display_name ? `${u.username} [${u.display_name}]` : u.username);

  const initials = initialsFor(u);
  document.getElementById("profile-initials").textContent = initials;
  document.getElementById("profile-btn").title = identity;
  // The accessible name starts with what the button shows (WCAG 2.5.3), so
  // a speech user saying the initials they see activates it.
  document.getElementById("profile-btn").setAttribute("aria-label", `${initials} — account menu for ${identity}`);

  document.getElementById("profile-menu").innerHTML = `
    <div class="menu-identity">${escapeHtml(identity)}</div>
    <div class="menu-sep"></div>
    <div class="menu-row"><span class="menu-label">Persona:</span>
      <span class="avatar small">${escapeHtml(initialsFor(u))}</span>
      <span>${escapeHtml(u.persona || "Default Persona")}</span></div>
    <div class="menu-sep"></div>
    <button class="menu-item" id="menu-prefs" type="button">Preferences</button>
    <button class="menu-item" id="menu-errors" type="button">Local Error Log</button>
    ${u.is_admin || (u.permissions || []).includes("settings.manage") ? '<a class="menu-item" href="/settings#about">About mustra</a>' : ""}
    <form method="POST" action="/logout" class="menu-form"><button class="menu-item" type="submit">Sign Out</button></form>
  `;
  document.getElementById("menu-prefs").addEventListener("click", openPreferences);
  document.getElementById("menu-errors").addEventListener("click", openErrorLog);
  showVersions(u);
}

// showVersions: the server's and the agent's versions in a footer at the
// bottom right of every page. (The profile menu used to repeat them, with
// the sign-in times; it now holds only what the user acts on.)
let versionInfo = null;
async function showVersions(u) {
  if (!hasPermission(u, "fleet.read")) return;
  if (!versionInfo) {
    try { const r = await fetch("/api/version"); if (r.ok) versionInfo = await r.json(); } catch (e) { /* not worth an error */ }
  }
  const v = versionInfo;
  if (!v) return;
  const main = document.querySelector(".app-shell main");
  if (main && !document.getElementById("app-version-foot")) {
    const f = document.createElement("footer");
    f.id = "app-version-foot";
    f.className = "app-version-foot";
    f.textContent = `mustra ${v.server || "dev"} · agent ${v.agent || "—"}`;
    main.appendChild(f);
  }
}

// --- Preferences and the error log ------------------------------------

// askPatchApply is the Apply patches dialog: which devices, and whether to
// restart them afterwards. Resolves to {restart_mode, restart_warn_minutes}
// (restart_mode "" means none) or null when cancelled. The last choice is
// remembered in this browser; the first default is not to restart, so a
// server is never rebooted by accident.
//
// opts.only offers a choice of what to install, for a remediation that can
// update just the affected packages: {label, hint, /* html-param: callers
// pass markup they escaped */ detailHTML}. The choice then carries
// scope "only" (the default) or "all".
function askPatchApply(hostnames, opts) {
  const only = opts && opts.only;
  const saved = (() => { try { return JSON.parse(localStorage.getItem("mustra-patch-restart") || "null") || {}; } catch (e) { return {}; } })();
  const mode0 = ["", "if_required", "always"].includes(saved.mode) ? saved.mode : "";
  const warn0 = [1, 5, 15, 30, 60].includes(saved.warn) ? saved.warn : 5;
  const shown = hostnames.slice(0, 6).map(h => `<span class="pa-host">${escapeHtml(h)}</span>`).join("") +
    (hostnames.length > 6 ? `<span class="pa-more">+${escapeHtml(hostnames.length - 6)} more</span>` : "");
  const opt = (v, title, hint) => `<label class="pa-opt"><input type="radio" name="pa-restart" value="${escapeHtml(v)}"${v === mode0 ? " checked" : ""}>
    <span><b>${escapeHtml(title)}</b><span class="pa-hint">${escapeHtml(hint)}</span></span></label>`;
  return new Promise(resolve => {
    let done = false;
    const finish = v => { if (!done) { done = true; resolve(v); } };
    openModal(hostnames.length === 1 ? `Apply patches to ${hostnames[0]}` : `Apply patches to ${hostnames.length} devices`, `
      ${hostnames.length > 1 ? `<div class="pa-hosts">${shown}</div>` : ""}
      ${only ? `<fieldset class="pa-group"><legend>What to install</legend>
        <label class="pa-opt"><input type="radio" name="pa-scope" value="only" checked>
          <span><b>${escapeHtml(only.label)}</b><span class="pa-hint">${escapeHtml(only.hint || "")}</span>${/* safe-html: the caller builds it from escaped values (html-param above) */ only.detailHTML || ""}</span></label>
        <label class="pa-opt"><input type="radio" name="pa-scope" value="all">
          <span><b>Everything pending</b><span class="pa-hint">Every update the patch lists allow, as on the Patch page.</span></span></label>
      </fieldset>
      <p class="modal-note">This can take several minutes per device.</p>`
      : `<p class="modal-note">Installs every pending patch the patch lists allow. This can take several minutes per device.</p>`}
      <fieldset class="pa-group"><legend>After the updates install</legend>
        ${opt("", "Don't restart", "The device reports if a restart is still needed.")}
        ${opt("if_required", "Restart if the updates need it", "Only devices whose updates ask for a restart.")}
        ${opt("always", "Restart afterwards", "Every device restarts once its updates are in, needed or not.")}
      </fieldset>
      <div class="pa-warn" id="pa-warn">
        <label for="pa-warn-min">Warn whoever is signed in</label>
        <select id="pa-warn-min">${[1, 5, 15, 30, 60].map(m => `<option value="${escapeHtml(m)}"${m === warn0 ? " selected" : ""}>${escapeHtml(m)} minute${m === 1 ? "" : "s"} before restarting</option>`).join("")}</select>
        <div class="pa-hint">Uses the operating system's own restart countdown and warning. Nothing restarts if the updates fail.</div>
      </div>
      <div class="modal-actions u-d-flex u-gap-8 u-mt-16">
        <button class="primary" id="pa-go" type="button">Apply patches</button>
        <button class="tiny" id="pa-cancel" type="button">Cancel</button>
      </div>`, wrap => {
      const mode = () => wrap.querySelector('input[name="pa-restart"]:checked')?.value || "";
      const sync = () => { wrap.querySelector("#pa-warn").hidden = mode() === ""; };
      wrap.querySelectorAll('input[name="pa-restart"]').forEach(r => r.addEventListener("change", sync)); sync();
      const gone = new MutationObserver(() => { if (!wrap.isConnected) { gone.disconnect(); finish(null); } });
      gone.observe(document.body, { childList: true });
      wrap.querySelector("#pa-cancel").addEventListener("click", () => wrap.remove());
      wrap.querySelector("#pa-go").addEventListener("click", () => {
        const choice = { restart_mode: mode(), restart_warn_minutes: Number(wrap.querySelector("#pa-warn-min").value) };
        if (only) choice.scope = wrap.querySelector('input[name="pa-scope"]:checked')?.value || "only";
        try { localStorage.setItem("mustra-patch-restart", JSON.stringify({ mode: choice.restart_mode, warn: choice.restart_warn_minutes })); } catch (e) {}
        finish(choice);
        wrap.remove();
      });
      wrap.querySelector("#pa-go").focus();
    });
  });
}

// applyPatchesTo POSTs one device's apply with the dialog's choice and
// returns the message to show; errors come back as plain text.
async function applyPatchesTo(agentId, choice) {
  const resp = await fetch(`/api/agents/${encodeURIComponent(agentId)}/apply-patches`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(choice || {}) });
  const text = await resp.text();
  let data = {}; try { data = JSON.parse(text); } catch (e) {}
  if (!resp.ok) throw new Error(data.error || text.trim() || resp.statusText);
  const restart = !choice || !choice.restart_mode ? "" : choice.restart_mode === "always" ? ` · will restart after a ${choice.restart_warn_minutes}-minute warning` : ` · will restart if needed, after a ${choice.restart_warn_minutes}-minute warning`;
  return (data.message || "patch job started") + restart;
}

function openModal(title, /* html-param: callers pass markup they escaped */ bodyHTML, onMount) {
  document.getElementById("mustra-modal")?.remove();
  const wrap = document.createElement("div");
  wrap.className = "modal-wrap";
  wrap.id = "mustra-modal";
  wrap.innerHTML = `
    <div class="modal">
      <div class="modal-head"><h3>${escapeHtml(title)}</h3>
        <button class="modal-close" type="button" aria-label="Close">✕</button></div>
      <div class="modal-body">${bodyHTML}</div>
    </div>`;
  document.body.appendChild(wrap);
  const close = () => wrap.remove();
  wrap.querySelector(".modal-close").addEventListener("click", close);
  wrap.addEventListener("click", e => { if (e.target === wrap) close(); });
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
  });
  if (onMount) onMount(wrap);
}

let userPrefs = null;

// Applying preferences is separate from editing them: they are applied on
// every page load, long before anyone opens the dialog.
function applyPreferences(p) {
  userPrefs = p;
  window.mustraTheme?.set(p.theme, prefsPalette(p));
  document.dispatchEvent(new CustomEvent("mustra:theme"));
  renderEnvironmentBanner();
  startIdleTimer();
  applyLandingPage(p);
  setOmniKeys(p.shortcuts);
}

// A landing page only fires on the way in from the home page, and only once
// per session. Redirecting on every visit to "/" would make Home
// unreachable for anyone who set one.
function applyLandingPage(p) {
  if (!p.landing_page || p.landing_page === "/") return;
  // Only a page of this console: a stored preference must not navigate
  // anywhere else, or to a javascript: URL.
  if (!/^\/[^/\\]/.test(p.landing_page) || safeUrl(p.landing_page) === "#") return;
  if (window.location.pathname !== "/") return;
  try {
    if (sessionStorage.getItem("mustra-landed") === "1") return;
    sessionStorage.setItem("mustra-landed", "1");
  } catch (e) { return; }
  window.location.replace(p.landing_page);
}

// The identity banner across the top: who you are and what you are acting
// as. Worth having in a console that can act on a whole fleet, and worth
// being able to switch off when you are sharing your screen.
function renderEnvironmentBanner() {
  const existing = document.getElementById("env-banner");
  if (!userPrefs || !userPrefs.show_environment_details || !currentUser) {
    if (existing) existing.remove();
    document.body.classList.remove("has-env-banner");
    return;
  }
  const who = currentUser.email
    ? `${currentUser.email}${currentUser.display_name ? ` [${currentUser.display_name}]` : ""}`
    : currentUser.username;
  const el = existing || document.createElement("div");
  el.id = "env-banner";
  el.className = "env-banner";
  el.setAttribute("role", "region");
  el.setAttribute("aria-label", "Signed-in identity");
  el.innerHTML = `<span>${escapeHtml(who)}</span>
    <span>Persona: ${escapeHtml(currentUser.persona || "Default Persona")}</span>`;
  if (!existing) document.body.prepend(el);
  document.body.classList.add("has-env-banner");
}

// Idle sign-out. Enforced in the browser for responsiveness, but the value
// lives on the account -- an idle timeout kept only in localStorage is one
// anyone can clear by opening a private window.
let idleTimer = null;
function startIdleTimer() {
  const mins = userPrefs ? userPrefs.sign_out_after_minutes : 0;
  ["mousemove", "keydown", "click", "scroll"].forEach(evt =>
    document.removeEventListener(evt, bumpIdle, { passive: true }));
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
  if (!mins || mins <= 0) return;
  ["mousemove", "keydown", "click", "scroll"].forEach(evt =>
    document.addEventListener(evt, bumpIdle, { passive: true }));
  bumpIdle();
}
function bumpIdle() {
  if (idleTimer) clearTimeout(idleTimer);
  const mins = userPrefs ? userPrefs.sign_out_after_minutes : 0;
  if (!mins) return;
  idleTimer = setTimeout(() => {
    const f = document.createElement("form");
    f.method = "POST";
    f.action = "/logout";
    document.body.appendChild(f);
    f.submit();
  }, mins * 60000);
}

// The palette as theme.js takes it, from the account's preferences.
function prefsPalette(p) {
  return { id: p.palette || "mustra", custom: p.custom_palette || null };
}

let preferencesLoaded = Promise.resolve();

async function loadPreferences() {
  try {
    const resp = await fetch("/api/preferences");
    if (!resp.ok) return;
    applyPreferences(await resp.json());
  } catch (e) { /* the console still works on defaults */ }
}

async function savePreferences(p) {
  const resp = await fetch("/api/preferences", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(p),
  });
  if (!resp.ok) throw new Error("could not save");
  applyPreferences(await resp.json());
}

// The theme-file seed names, with the aliases an uploaded file may use.
const PALETTE_SEED_LABELS = { bg: "Page", surface: "Cards", text: "Text", muted: "Muted text", accent: "Accent" };
const PALETTE_SEED_ALIASES = {
  bg: ["bg", "background", "page"], surface: ["surface", "card", "cards"],
  text: ["text", "foreground"], muted: ["muted", "text_muted", "muted_text", "textMuted"],
  accent: ["accent", "primary", "link"],
};

// parseThemeFile turns an uploaded theme file into a custom palette, or
// throws with a message that says what is wrong with it.
function parseThemeFile(text) {
  let doc;
  try { doc = JSON.parse(text); } catch (e) { throw new Error("that file is not JSON"); }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("a theme file is a JSON object");
  const mode = m => {
    const src = doc[m];
    if (!src || typeof src !== "object") return null;
    const seeds = {};
    for (const [key, names] of Object.entries(PALETTE_SEED_ALIASES)) {
      const hit = names.find(n => typeof src[n] === "string");
      if (!hit) return null;
      let v = src[hit].trim().toLowerCase();
      if (/^#[0-9a-f]{3}$/.test(v)) v = "#" + v.slice(1).split("").map(c => c + c).join("");
      seeds[key] = v;
    }
    return window.mustraTheme.validSeeds(seeds);
  };
  const dark = mode("dark"), light = mode("light");
  if (!dark && !light) {
    throw new Error("no usable colors: it needs a \"dark\" or \"light\" object with bg, surface, text, muted and accent as #rrggbb");
  }
  const name = typeof doc.name === "string" && doc.name.trim() ? doc.name.trim().slice(0, 40) : "Uploaded";
  return { name, dark, light };
}

// mountAppearance wires the Mode switch, the palette grid and the custom
// editor in the Preferences dialog. Every change previews at once.
function mountAppearance(wrap, p) {
  const T = window.mustraTheme;
  const state = {
    mode: p.theme || "system",
    palette: p.palette || "mustra",
    custom: p.custom_palette ? JSON.parse(JSON.stringify(p.custom_palette)) : null,
  };
  const grid = wrap.querySelector("#pf-palettes");
  const editor = wrap.querySelector("#pf-custom");
  const status = wrap.querySelector("#pf-cp-status");
  if (!T) {
    grid.textContent = "Colors could not load; reload the page.";
    editor.classList.add("is-hidden");
    return { value: () => ({ theme: state.mode }), reset() {} };
  }

  const preview = () => T.preview(state.mode, { id: state.palette, custom: state.custom });
  const mode = () => T.effectiveMode(state.mode);
  // A new custom palette starts from whatever was selected, so it opens as
  // a complete, readable theme rather than five black squares.
  const ensureCustom = () => {
    if (state.custom) return;
    const base = { id: state.palette === "custom" ? "mustra" : state.palette };
    const seed = m => T.seedsFor(base, m) || T.palettes.mustra[m];
    state.custom = { name: "My colors", dark: { ...seed("dark") }, light: { ...seed("light") } };
  };

  const swatch = seeds => {
    const sw = document.createElement("span");
    sw.className = "pc-swatch";
    sw.style.background = seeds.bg;
    const card = document.createElement("span");
    card.className = "pc-card";
    card.style.background = seeds.surface;
    card.style.borderColor = seeds.muted;
    const l1 = document.createElement("span");
    l1.className = "pc-line";
    l1.style.background = seeds.text;
    const l2 = document.createElement("span");
    l2.className = "pc-line short";
    l2.style.background = seeds.muted;
    const dot = document.createElement("span");
    dot.className = "pc-dot";
    dot.style.background = seeds.accent;
    card.append(l1, l2, dot);
    sw.append(card);
    return sw;
  };

  const renderGrid = () => {
    grid.textContent = "";
    const m = mode();
    const entries = Object.entries(T.palettes).map(([id, pal]) => [id, pal.name, pal[m]]);
    const customSeeds = state.custom && T.validSeeds(state.custom[m]);
    entries.push(["custom", state.custom?.name || "Custom", customSeeds || null]);
    for (const [id, name, seeds] of entries) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "palette-card";
      b.setAttribute("role", "radio");
      b.setAttribute("aria-checked", String(state.palette === id));
      b.dataset.id = id;
      if (seeds) b.append(swatch(seeds));
      else {
        const plus = document.createElement("span");
        plus.className = "pc-swatch pc-new";
        plus.textContent = "+";
        b.append(plus);
      }
      const label = document.createElement("span");
      label.className = "pc-name";
      label.textContent = id === "custom" && !state.custom ? "Custom" : name;
      b.append(label);
      b.addEventListener("click", () => {
        if (id === "custom") ensureCustom();
        state.palette = id;
        render();
      });
      grid.append(b);
    }
  };

  const renderEditor = () => {
    editor.classList.toggle("is-hidden", state.palette !== "custom");
    if (state.palette !== "custom" || !state.custom) return;
    const nameInput = wrap.querySelector("#pf-cp-name");
    if (document.activeElement !== nameInput) nameInput.value = state.custom.name || "";
    const modes = wrap.querySelector("#pf-cp-modes");
    modes.textContent = "";
    for (const m of ["dark", "light"]) {
      const col = document.createElement("fieldset");
      col.className = "cp-mode" + (m === mode() ? " current" : "");
      const legend = document.createElement("legend");
      legend.textContent = m === "dark" ? "Dark mode" : "Light mode";
      col.append(legend);
      const seeds = T.validSeeds(state.custom[m]);
      if (!seeds) {
        const add = document.createElement("button");
        add.type = "button";
        add.className = "tiny";
        add.textContent = "Add " + m + " colors";
        add.addEventListener("click", () => {
          state.custom[m] = { ...(T.seedsFor({ id: "mustra" }, m) || T.palettes.mustra[m]) };
          render();
        });
        const none = document.createElement("div");
        none.className = "pref-hint";
        none.textContent = "Not set: " + m + " mode uses the built-in colors.";
        col.append(none, add);
        modes.append(col);
        continue;
      }
      for (const key of T.seeds) {
        const row = document.createElement("label");
        row.className = "cp-row";
        const input = document.createElement("input");
        input.type = "color";
        input.value = seeds[key];
        input.addEventListener("input", () => {
          state.custom[m] = { ...T.validSeeds(state.custom[m]), [key]: input.value.toLowerCase() };
          code.textContent = input.value.toLowerCase();
          preview();
          renderProblems(col, m);
          renderGrid();
        });
        const text = document.createElement("span");
        text.textContent = PALETTE_SEED_LABELS[key];
        const code = document.createElement("code");
        code.textContent = seeds[key];
        row.append(input, text, code);
        col.append(row);
      }
      const issues = document.createElement("ul");
      issues.className = "cp-issues";
      col.append(issues);
      modes.append(col);
      renderProblems(col, m);
    }
  };
  const renderProblems = (col, m) => {
    const list = col.querySelector(".cp-issues");
    if (!list) return;
    list.textContent = "";
    const seeds = T.validSeeds(state.custom?.[m]);
    const found = seeds ? T.problems(seeds) : [];
    for (const pr of found) {
      const li = document.createElement("li");
      li.textContent = "Hard to read: " + pr.message;
      list.append(li);
    }
  };

  const renderMode = () => {
    wrap.querySelectorAll("#pf-mode button").forEach(b => {
      b.setAttribute("aria-checked", String(b.dataset.mode === state.mode));
    });
  };
  const render = () => { renderMode(); renderGrid(); renderEditor(); preview(); };

  wrap.querySelectorAll("#pf-mode button").forEach(b => b.addEventListener("click", () => {
    state.mode = b.dataset.mode;
    render();
  }));
  wrap.querySelector("#pf-cp-name").addEventListener("input", e => {
    if (!state.custom) return;
    state.custom.name = e.target.value.slice(0, 40);
    renderGrid();
  });
  const file = wrap.querySelector("#pf-cp-file");
  wrap.querySelector("#pf-cp-upload").addEventListener("click", () => file.click());
  file.addEventListener("change", async () => {
    const f = file.files && file.files[0];
    file.value = "";
    if (!f) return;
    if (f.size > 64 * 1024) { status.textContent = "that file is too large for a theme"; return; }
    try {
      state.custom = parseThemeFile(await f.text());
      state.palette = "custom";
      status.textContent = "loaded “" + state.custom.name + "”: Save to keep it";
      render();
    } catch (e) {
      status.textContent = e.message;
    }
  });
  wrap.querySelector("#pf-cp-download").addEventListener("click", () => {
    if (!state.custom) return;
    const doc = { name: state.custom.name || "My colors" };
    for (const m of ["dark", "light"]) {
      const seeds = T.validSeeds(state.custom[m]);
      if (seeds) doc[m] = seeds;
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2) + "\n"], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = (doc.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "theme") + ".mustra-theme.json";
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  render();
  return {
    value: () => ({ theme: state.mode, palette: state.palette, custom_palette: state.custom }),
    reset() { state.mode = "system"; state.palette = "mustra"; render(); },
  };
}

// Laid out to match the dialog people already know: the two numeric
// settings with their units, then the dropdowns, then the toggles, then
// Reset above Save/Cancel.
function openPreferences() {
  const p = userPrefs || {
    results_complete_percent: 99, sign_out_after_minutes: 180, theme: "system",
    landing_page: "/", hide_error_results: true, show_environment_details: true,
  };
  const pages = [["/", "Home"], ["/interact", "Interact"], ["/agents", "Endpoints"],
    ["/patches", "Patch"], ["/software", "Deploy"], ["/sensors", "Sensors"],
    ["/comply", "Comply"], ["/health", "Performance"]];

  openModal("Edit Preferences", `
    <div class="pref-field">
      <label for="pf-complete">Query Results Complete <span class="pref-help" title="How much of the fleet must have answered before a query's results are called complete. Not 100 by default because one permanently unreachable endpoint would make every query look unfinished forever.">?</span></label>
      <div class="pref-unit"><input id="pf-complete" type="number" min="1" max="100" value="${escapeHtml(p.results_complete_percent)}"><span>percent</span></div>
    </div>

    <div class="pref-field">
      <label for="pf-idle">Sign Out After User Inactivity</label>
      <div class="pref-unit"><input id="pf-idle" type="number" min="0" max="1440" value="${escapeHtml(p.sign_out_after_minutes)}"><span>minutes</span></div>
      <div class="pref-hint">0 never signs you out. Stored on your account, not in this browser.</div>
    </div>

    <div class="pref-field" id="pf-mfa" hidden>
      <label id="pf-mfa-label">Two-step sign-in</label>
      <div class="pf-mfa" aria-labelledby="pf-mfa-label" aria-live="polite"></div>
    </div>

    <div class="pref-field">
      <label id="pf-mode-label">Mode</label>
      <div class="seg" id="pf-mode" role="radiogroup" aria-labelledby="pf-mode-label">
        <button type="button" role="radio" data-mode="system">System</button>
        <button type="button" role="radio" data-mode="light">Light</button>
        <button type="button" role="radio" data-mode="dark">Dark</button>
      </div>
    </div>

    <div class="pref-field">
      <label id="pf-palette-label">Colors</label>
      <div class="palette-grid" id="pf-palettes" role="radiogroup" aria-labelledby="pf-palette-label"></div>
      <div class="pref-hint">Follows you to every page and every machine you sign in on.</div>
      <div class="custom-palette" id="pf-custom">
        <div class="cp-name">
          <label for="pf-cp-name">Name</label>
          <input id="pf-cp-name" type="text" maxlength="40" placeholder="My colors">
        </div>
        <div class="cp-modes" id="pf-cp-modes"></div>
        <div class="cp-actions">
          <button class="tiny" id="pf-cp-upload" type="button">Upload theme file</button>
          <button class="tiny" id="pf-cp-download" type="button">Download theme file</button>
          <input id="pf-cp-file" type="file" accept=".json,application/json" class="cp-file">
          <span class="scan-status" id="pf-cp-status" role="status"></span>
        </div>
        <div class="pref-hint">A theme file is JSON with a <code>dark</code> and/or <code>light</code> object,
          each holding <code>bg</code>, <code>surface</code>, <code>text</code>, <code>muted</code> and
          <code>accent</code> as <code>#rrggbb</code>. Download one to start from.</div>
      </div>
    </div>

    <div class="pref-field">
      <label for="pf-lang">Language</label>
      <select id="pf-lang" disabled><option>(Browser Language)</option></select>
      <div class="pref-hint">mustra is English-only today. The control is here rather than hidden so it is
        obvious the setting exists and is not yet doing anything.</div>
    </div>

    <div class="pref-field">
      <label for="pf-landing">Landing Page <span class="pref-help" title="Where signing in takes you.">?</span></label>
      <select id="pf-landing">
        ${pages.map(([href, label]) =>
          `<option value="${escapeHtml(href)}"${p.landing_page === href ? " selected" : ""}>${escapeHtml(label)}</option>`).join("")}
      </select>
    </div>

    <div class="pref-field">
      <label for="pf-timestamps">Timestamps</label>
      <select id="pf-timestamps">
        <option value="server"${p.timestamps !== "local" ? " selected" : ""}>Server time${serverTZ.zone ? " (" + escapeHtml(serverTZ.zone) + ")" : ""}</option>
        <option value="local"${p.timestamps === "local" ? " selected" : ""}>My local time</option>
      </select>
      <div class="pref-hint">Which clock every date in the console is drawn on. Server time is the default
        because the audit log, the agent logs and journalctl are all on it, and comparing two of them
        should not need arithmetic. The zone is always printed either way.</div>
    </div>

    <div class="pref-field">
      <label id="pf-keys-label">Keyboard shortcuts</label>
      <div class="pf-keys" role="group" aria-labelledby="pf-keys-label">${OMNI_MODES.map(m => `
        <div class="pf-key-row"><span>${escapeHtml(m.label)}</span><button type="button" class="pf-key" data-mode="${escapeHtml(m.id)}"></button></div>`).join("")}
      </div>
      <div class="pref-hint">Click a shortcut, then press the keys you want (Ctrl or Cmd plus a key). Escape cancels; Backspace puts the default back.</div>
    </div>

    <div class="pref-checks">
      <label><input type="checkbox" id="pf-hideerr"${p.hide_error_results ? " checked" : ""}> Hide Error Results from Queries</label>
      <label><input type="checkbox" id="pf-envdetails"${p.show_environment_details ? " checked" : ""}> Show Environment Details</label>
    </div>

    <div class="modal-actions">
      <button class="tiny" id="pf-reset" type="button">Reset</button>
    </div>
    <div class="modal-actions u-d-flex u-gap-8 u-mt-14">
      <button class="primary" id="pf-save" type="button">Save</button>
      <button class="tiny" id="pf-cancel" type="button">Cancel</button>
      <span class="scan-status" id="pf-status"></span>
    </div>
  `, wrap => {
    const appearance = mountAppearance(wrap, p);
    mountMFA(wrap.querySelector("#pf-mfa"));
    const keys = { ...OMNI_DEFAULT_KEYS, ...(p.shortcuts || {}) };
    const drawKeys = () => wrap.querySelectorAll(".pf-key").forEach(b => {
      if (!b.classList.contains("is-recording")) b.innerHTML = keysMarkup(keys[b.dataset.mode]);
    });
    // Recording a shortcut takes the next key combination, in the capture
    // phase so the console's own shortcuts do not act on it.
    wrap.querySelectorAll(".pf-key").forEach(b => b.addEventListener("click", () => {
      wrap.querySelectorAll(".pf-key.is-recording").forEach(x => x.classList.remove("is-recording"));
      b.classList.add("is-recording"); b.textContent = "Press keys…";
      const status = wrap.querySelector("#pf-status");
      const onKey = e => {
        e.preventDefault(); e.stopImmediatePropagation();
        const done = () => { document.removeEventListener("keydown", onKey, true); b.classList.remove("is-recording"); drawKeys(); };
        if (e.key === "Escape") { done(); return; }
        if (e.key === "Backspace" || e.key === "Delete") { keys[b.dataset.mode] = OMNI_DEFAULT_KEYS[b.dataset.mode]; done(); return; }
        const k = shortcutOf(e);
        if (!k) return;
        const clash = OMNI_MODES.find(m => m.id !== b.dataset.mode && normShortcut(keys[m.id]) === k);
        if (clash) { status.textContent = `${k} is already ${clash.label}.`; return; }
        status.textContent = "";
        keys[b.dataset.mode] = k; done();
      };
      document.addEventListener("keydown", onKey, true);
    }));
    drawKeys();
    const read = () => ({
      ...(userPrefs || {}),
      results_complete_percent: Number(wrap.querySelector("#pf-complete").value) || 99,
      sign_out_after_minutes: Number(wrap.querySelector("#pf-idle").value) || 0,
      ...appearance.value(),
      landing_page: wrap.querySelector("#pf-landing").value,
      timestamps: wrap.querySelector("#pf-timestamps").value,
      hide_error_results: wrap.querySelector("#pf-hideerr").checked,
      show_environment_details: wrap.querySelector("#pf-envdetails").checked,
      // Only the ones that differ from the defaults are stored, so a changed
      // default reaches everyone who never customised it.
      shortcuts: Object.fromEntries(Object.entries(keys).filter(([id, k]) => normShortcut(k) !== normShortcut(OMNI_DEFAULT_KEYS[id]))),
    });
    // Appearance previews live, because picking colours you cannot see is
    // a guess; everything else waits for Save. However the dialog closes
    // (Cancel, the X, Escape, a click outside) without Save, the preview is
    // undone.
    let saved = false;
    const closed = new MutationObserver(() => {
      if (wrap.isConnected) return;
      closed.disconnect();
      if (!saved) window.mustraTheme?.revert();
    });
    closed.observe(document.body, { childList: true });
    wrap.querySelector("#pf-reset").addEventListener("click", () => {
      wrap.querySelector("#pf-complete").value = 99;
      wrap.querySelector("#pf-idle").value = 180;
      wrap.querySelector("#pf-landing").value = "/";
      wrap.querySelector("#pf-hideerr").checked = true;
      wrap.querySelector("#pf-envdetails").checked = true;
      Object.assign(keys, OMNI_DEFAULT_KEYS); drawKeys();
      appearance.reset();
    });
    wrap.querySelector("#pf-cancel").addEventListener("click", () => wrap.remove());
    wrap.querySelector("#pf-save").addEventListener("click", async () => {
      const status = wrap.querySelector("#pf-status");
      const btn = wrap.querySelector("#pf-save");
      try {
        await withButtonState(btn, () => savePreferences(read()));
      } catch (e) {
        status.textContent = "could not save";
        return;
      }
      saved = true;
      // Long enough to see the check, short enough not to wait for it.
      setTimeout(() => wrap.remove(), 650);
    });
  });
}

// Two-step sign-in for a local account, managed in place in Preferences:
// it acts at once rather than on Save, because turning it on is a
// conversation with the authenticator app, not a field. SSO accounts are
// told where theirs lives; API tokens never see the section.
function mountMFA(field) {
  const box = field.querySelector(".pf-mfa");
  const api = async (path, body) => {
    const r = await fetch("/api/me/mfa" + path, body === undefined ? {} :
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
    return r.json();
  };
  const codeInput = id => `<input id="${escapeHtml(id)}" class="pf-mfa-code" type="text" inputmode="numeric" autocomplete="one-time-code"
    maxlength="24" placeholder="123 456" aria-label="Code from your authenticator app" spellcheck="false">`;
  const showCodes = codes => {
    box.innerHTML = `
      <p class="pf-mfa-state"><span class="pf-mfa-dot is-on" aria-hidden="true"></span>On. Save these recovery codes now; each signs you in once if you lose your phone, and they are not shown again.</p>
      <ol class="mfa-codes">${codes.map(c => `<li><code>${escapeHtml(c)}</code></li>`).join("")}</ol>
      <div class="pf-mfa-row"><button class="tiny" type="button" data-copy>Copy</button>
        <button class="tiny" type="button" data-dl>Download .txt</button>
        <button class="tiny" type="button" data-done>Done</button><span class="scan-status" role="status"></span></div>`;
    const said = box.querySelector(".scan-status");
    box.querySelector("[data-copy]").addEventListener("click", async () => {
      await navigator.clipboard.writeText(codes.join("\n")); said.textContent = "Copied";
    });
    box.querySelector("[data-dl]").addEventListener("click", () => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([`mustra recovery codes for ${location.host}\n\n${codes.join("\n")}\n`], { type: "text/plain" }));
      a.download = "mustra-recovery-codes.txt"; a.click(); URL.revokeObjectURL(a.href);
    });
    box.querySelector("[data-done]").addEventListener("click", draw);
  };
  // A step that needs a current code: the input, a confirm button, and
  // the error under it.
  const ask = (label, danger, run) => {
    const row = document.createElement("div");
    row.className = "pf-mfa-ask";
    row.innerHTML = `${codeInput("pf-mfa-ask")}<button class="tiny${danger ? " danger" : ""}" type="button">${escapeHtml(label)}</button>
      <button class="tiny" type="button" data-cancel>Cancel</button><div class="pf-mfa-err" role="alert"></div>`;
    box.querySelector(".pf-mfa-ask")?.remove();
    box.append(row);
    const input = row.querySelector("input"), err = row.querySelector(".pf-mfa-err");
    input.focus();
    const go = async () => {
      err.textContent = "";
      try { await run(input.value); } catch (e) { err.textContent = e.message; input.select(); }
    };
    row.querySelector("button").addEventListener("click", go);
    input.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); go(); } });
    row.querySelector("[data-cancel]").addEventListener("click", () => row.remove());
  };
  async function draw() {
    let st;
    try { st = await api(""); } catch (e) { return; }
    if (!st.applies) {
      if (currentUser && currentUser.source && currentUser.source !== "local" && currentUser.source !== "api-token") {
        field.hidden = false;
        box.innerHTML = '<p class="pref-hint">You sign in through single sign-on, so your identity provider decides two-step sign-in.</p>';
      }
      return;
    }
    field.hidden = false;
    if (!st.available) {
      box.innerHTML = '<p class="pref-hint">Unavailable: this server has no credential encryption key to protect the secret.</p>';
      return;
    }
    if (st.enabled) {
      const low = st.recovery_codes_left <= 2;
      box.innerHTML = `
        <p class="pf-mfa-state"><span class="pf-mfa-dot is-on" aria-hidden="true"></span>On since ${escapeHtml(fmtDate(st.enabled_at))}
          <span class="pf-mfa-sep" aria-hidden="true">·</span><span class="${low ? "pf-mfa-low" : ""}">${escapeHtml(st.recovery_codes_left)} recovery code${st.recovery_codes_left === 1 ? "" : "s"} left</span></p>
        <div class="pf-mfa-row"><button class="tiny" type="button" data-new>New recovery codes</button>
          ${st.required ? "" : '<button class="tiny danger" type="button" data-off>Turn off</button>'}</div>
        ${st.required ? '<div class="pref-hint">Required for local accounts on this server. Moving to a new phone? An administrator can reset it.</div>' : ""}`;
      box.querySelector("[data-new]").addEventListener("click", () =>
        ask("Make new codes", false, async code => showCodes((await api("/recovery-codes", { code })).recovery_codes)));
      box.querySelector("[data-off]")?.addEventListener("click", () =>
        ask("Turn off", true, async code => { await api("/disable", { code }); draw(); }));
      return;
    }
    box.innerHTML = `
      <p class="pf-mfa-state"><span class="pf-mfa-dot" aria-hidden="true"></span>Off${st.required ? " — required, so you will set it up at your next sign-in" : ""}</p>
      <div class="pf-mfa-row"><button class="tiny" type="button" data-setup>Set up</button></div>
      <div class="pref-hint">After your password, sign-in asks for a code from an authenticator app.</div>`;
    box.querySelector("[data-setup]").addEventListener("click", async () => {
      let setup;
      try { setup = await api("/setup", {}); } catch (e) { box.querySelector(".pref-hint").textContent = e.message; return; }
      box.innerHTML = `
        <div class="pf-mfa-setup">
          <div class="mfa-qr">${/* safe-html: an SVG the server draws from integers only (qrSVG) */ setup.qr_svg}</div>
          <div class="pf-mfa-setup-text">
            <p>Scan this with an authenticator app, then enter the 6-digit code it shows.</p>
            <details class="mfa-manual"><summary>Can’t scan it? Enter the key</summary><code class="mfa-secret">${escapeHtml(setup.secret)}</code></details>
          </div>
        </div>`;
      ask("Turn on", false, async code => showCodes((await api("/enable", { code })).recovery_codes));
    });
  }
  draw();
}

function openErrorLog() {
  const errs = readLocalErrors();
  openModal("Local Error Log", `
    <p class="modal-note">Errors this browser hit while using the console, newest first. They are stored on this
      machine only and never sent anywhere — copy one into a bug report if something misbehaved.</p>
    ${errs.length === 0
      ? '<p class="empty">No errors recorded.</p>'
      : `<div class="errlog">${errs.map(e => `
          <div class="errlog-row">
            <div class="errlog-when">${escapeHtml(fmtTime(e.at))} · ${escapeHtml(e.kind)}</div>
            <div class="errlog-msg">${escapeHtml(e.message)}</div>
            ${e.detail ? `<div class="errlog-detail">${escapeHtml(e.detail)}</div>` : ""}
          </div>`).join("")}</div>`}
    <div class="modal-actions"><button class="tiny" id="err-clear" type="button">Clear log</button></div>
  `, wrap => {
    wrap.querySelector("#err-clear").addEventListener("click", () => { clearLocalErrors(); openErrorLog(); });
  });
}

// --- Notifications ----------------------------------------------------

const NOTIF_POLL_MS = 60000;

async function refreshNotificationBadge() {
  try {
    const resp = await fetch("/api/notifications/count");
    if (!resp.ok) return;
    const n = (await resp.json()).unread || 0;
    const badge = document.getElementById("notif-badge");
    if (!badge) return;
    badge.hidden = n === 0;
    // Past ten the exact number stops changing any decision, and a
    // three-digit badge wrecks the icon row.
    badge.textContent = n > 10 ? "10+" : String(n);
    document.getElementById("notif-btn").classList.toggle("has-unread", n > 0);
  } catch (e) { /* a blip should not break the page chrome */ }
}
setInterval(refreshNotificationBadge, NOTIF_POLL_MS);

async function loadNotifications() {
  const menu = document.getElementById("notif-menu");
  menu.innerHTML = '<div class="menu-empty">loading…</div>';
  let data;
  try {
    const resp = await fetch("/api/notifications");
    if (!resp.ok) { menu.innerHTML = '<div class="menu-empty">could not load notifications</div>'; return; }
    data = await resp.json();
  } catch (e) {
    menu.innerHTML = '<div class="menu-empty">could not load notifications</div>';
    return;
  }
  const items = data.notifications || [];
  menu.innerHTML = `
    <div class="menu-head">
      <span>Notifications</span>
      ${data.unread ? `<button class="menu-link" id="notif-read-all" type="button">Mark all read</button>` : ""}
    </div>
    ${items.length === 0
      ? '<div class="menu-empty">Nothing to report. Deployments that fail or time out show up here.</div>'
      : `<div class="notif-list">${items.map(n => `
          <a class="notif ${n.read ? "" : "unread"} sev-${escapeHtml(n.severity)}"
             href="${escapeHtml(safeUrl(n.link || "#"))}" data-notif="${escapeHtml(n.id)}">
            <div class="notif-top">
              <span class="notif-title">${escapeHtml(n.title)}</span>
              <span class="notif-when">${fmtAgo(n.created_at)}</span>
            </div>
            ${n.source ? `<div class="notif-src">${escapeHtml(n.source)}</div>` : ""}
            ${n.body ? `<div class="notif-body">${escapeHtml(n.body)}</div>` : ""}
          </a>`).join("")}</div>`}
  `;
  const readAll = document.getElementById("notif-read-all");
  if (readAll) {
    readAll.addEventListener("click", async () => {
      await fetch("/api/notifications/all/read", { method: "POST" });
      refreshNotificationBadge();
      loadNotifications();
    });
  }
  menu.querySelectorAll("[data-notif]").forEach(a => {
    a.addEventListener("click", () => {
      // Fire-and-forget: navigation is the point, and waiting on the mark
      // would make an already-slow click slower for no benefit.
      fetch(`/api/notifications/${encodeURIComponent(a.dataset.notif)}/read`, { method: "POST" });
    });
  });
}

// currentUser is populated by loadUser() and read by pages that need to
// know the viewer's permissions (e.g. to hide an "Apply patches" button).
let currentUser = null;

async function loadUser() {
  const resp = await fetch("/api/me");
  if (resp.status === 401) { window.location.href = "/login"; return; }
  const u = await resp.json();
  currentUser = u;
  // An account that may not read the fleet gets no endpoint search, no
  // Guide bell and no lookups it would only be refused.
  const canRead = hasPermission(u, "fleet.read");
  document.documentElement.classList.toggle("no-fleet-read", !canRead);
  if (canRead) loadIdNums();
  // After the page's own handler has drawn its header, if it has one.
  setTimeout(addFallbackHelpLink, 0);

  // No sidebar chip any more: identity lives in the top-right menu, which
  // is on every page, and the flyout is now a per-group popout that would
  // have carried a copy of your own name into every group.
  setServerTimeZone(u);
  installTopBar();
  renderProfileMenu(u);
  refreshNotificationBadge();
  preferencesLoaded = loadPreferences();
  applyBranding(u);
  renderSidebarNav(u);
  // Pages listen for this in a script after app.js, sometimes behind another
  // external script. If /api/me answers while the parser is still waiting on
  // that script (a cache miss, as after every deploy), the event would fire
  // before the page listens, and the page would never build: a blank module
  // until a refresh. Every page's listener is in place by DOMContentLoaded.
  if (document.readyState === "loading") {
    await new Promise(resolve => document.addEventListener("DOMContentLoaded", resolve, { once: true }));
  }
  document.dispatchEvent(new CustomEvent("mustra:user", { detail: u }));
  // Pages build their own markup in that handler, so paint again after it.
  paintIcons();
}

function hasPermission(u, perm) {
  return !!(u && (u.is_admin || (u.permissions || []).includes(perm)));
}

// --- Charts ---
//
// Small, dependency-free marks built from plain elements rather than a
// charting library: every chart here plots one measure, so the whole job is
// a proportional length plus a directly-rendered value. Each bar carries a
// hover tooltip; none carry a value axis, because a directly-labeled bar
// would only have it repeat itself.

function vizTooltipEl() {
  let el = document.getElementById("viz-tooltip");
  if (!el) {
    el = document.createElement("div");
    el.id = "viz-tooltip";
    el.className = "viz-tooltip";
    el.hidden = true;
    document.body.appendChild(el);
  }
  return el;
}

// attachVizTooltips wires every [data-hint] mark in a container to the
// shared tooltip. Hit target is the whole row/column, not just the fill, so
// a one-pixel bar is still hoverable.
function attachVizTooltips(container) {
  const tip = vizTooltipEl();
  container.querySelectorAll("[data-hint]").forEach(el => {
    el.addEventListener("mouseenter", () => {
      tip.textContent = el.dataset.hint;
      tip.hidden = false;
    });
    el.addEventListener("mousemove", (e) => {
      tip.style.left = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8) + "px";
      tip.style.top = (e.clientY + 16) + "px";
    });
    el.addEventListener("mouseleave", () => { tip.hidden = true; });
  });
}

// A chart of one category isn't a chart — it's a number. Renders the value
// as a line of text instead of a lone bar.
function renderSingleValue(el, row, unit) {
  el.innerHTML = `<div class="chart-single"><b>${escapeHtml(row.value.toLocaleString())}</b> ${escapeHtml(unit || "")} — ${escapeHtml(row.label)}</div>`;
}

// rows: [{label, value, hint?}] — horizontal bars, best when the category
// names are long (package names, hostnames), since they stay level.
function hBarChart(el, rows, opts) {
  opts = opts || {};
  if (rows.length === 0) {
    el.innerHTML = `<div class="chart-empty">${escapeHtml(opts.empty || "nothing to show yet")}</div>`;
    return;
  }
  if (rows.length === 1 && opts.collapseSingle !== false) {
    renderSingleValue(el, rows[0], opts.unit);
    return;
  }
  const max = Math.max(1, ...rows.map(r => r.value));
  el.innerHTML = rows.map(r => `
    <div class="hbar-row" data-hint="${escapeHtml(r.hint || `${r.label}: ${r.value.toLocaleString()} ${opts.unit || ""}`.trim())}">
      <div class="hbar-label">${escapeHtml(r.label)}${r.tag ? `<span class="hbar-tag">${escapeHtml(r.tag)}</span>` : ""}</div>
      <div class="hbar-track"><div class="hbar-fill"${sx(`width:${(r.value / max) * 100}%${r.color ? ";background:" + r.color : ""}`)}></div></div>
      <div class="hbar-value">${escapeHtml(r.value.toLocaleString())}</div>
    </div>
  `).join("");
  attachVizTooltips(el);
}

// cols: [{label, value, color?, hint?}] — columns, for a short ordered set
// of buckets where the labels are small enough to sit flat under the axis.
function columnChart(el, cols, opts) {
  opts = opts || {};
  if (cols.length === 0) {
    el.innerHTML = `<div class="chart-empty">${escapeHtml(opts.empty || "nothing to show yet")}</div>`;
    return;
  }
  const max = Math.max(1, ...cols.map(c => c.value));
  el.innerHTML = `<div class="columns">` + cols.map(c => `
    <div class="column" data-hint="${escapeHtml(c.hint || `${c.label}: ${c.value.toLocaleString()} ${opts.unit || ""}`.trim())}">
      <div class="column-value">${escapeHtml(c.value.toLocaleString())}</div>
      <div class="column-plot">
        <div class="column-bar"${sx(`height:${Math.max(2, (c.value / max) * 100)}%${c.color ? ";background:" + c.color : ""}`)}></div>
      </div>
      <div class="column-label">${escapeHtml(c.label)}</div>
    </div>
  `).join("") + `</div>`;
  attachVizTooltips(el);
}

// segments: [{label, value, color}] — one stacked bar plus a legend that
// always spells out the count and share, so a status color never has to be
// interpreted on its own.
// A segment may carry a `key`, and the caller an `onSelect` — the count
// then becomes a button in both the bar and the legend. The question a
// status bar always provokes is "which ones are those?", and a number that
// cannot be clicked leaves the reader to go and filter a table by hand.
// `selected` marks the live drill-down so the bar shows what the page below
// it is currently filtered to, and clicking it again clears the filter.
function stackedStatusBar(barEl, legendEl, segments, opts) {
  opts = opts || {};
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const shown = segments.filter(s => s.value > 0);
  const onSelect = typeof opts.onSelect === "function" ? opts.onSelect : null;
  // An empty segment drills into nothing, so it stays a plain label.
  const drills = s => !!(onSelect && s.key && s.value > 0);
  const hintOf = s => escapeHtml(`${s.label}: ${s.value.toLocaleString()} (${pctOf(s.value, total)})`);

  barEl.innerHTML = total === 0
    ? `<div class="readiness-seg u-flex-1 u-bg-viz-none"></div>`
    : shown.map(s => drills(s)
        ? `<button type="button" class="readiness-seg${opts.selected === s.key ? " selected" : ""}"
                  ${sx(`flex:${s.value};background:${s.color}`)} data-hint="${hintOf(s)}"
                   data-pick="${escapeHtml(s.key)}" aria-label="${hintOf(s)}"></button>`
        : `<div class="readiness-seg"${sx(`flex:${s.value};background:${s.color}`)}
                data-hint="${hintOf(s)}"></div>`
      ).join("");

  legendEl.innerHTML = segments.map(s => {
    const body = `
      <div class="readiness-chip"${sx(`background:${s.color}`)}></div>
      <div>
        <div class="readiness-count">${escapeHtml(s.value.toLocaleString())}<span class="readiness-pct">${pctOf(s.value, total)}</span></div>
        <div class="readiness-label">${escapeHtml(s.label)}</div>
      </div>`;
    if (!drills(s)) return `<div class="readiness-item">${body}</div>`;
    const on = opts.selected === s.key;
    return `<button type="button" class="readiness-item readiness-pick${on ? " selected" : ""}"
                    data-pick="${escapeHtml(s.key)}" aria-pressed="${on}"
                    title="${on ? "Clear this filter" : escapeHtml(`Show the ${s.label.toLowerCase()} endpoints`)}">${body}</button>`;
  }).join("");

  if (onSelect) {
    for (const root of [barEl, legendEl]) {
      root.querySelectorAll("[data-pick]").forEach(el => el.addEventListener("click", () => {
        onSelect(el.dataset.pick === opts.selected ? "" : el.dataset.pick);
      }));
    }
  }
  attachVizTooltips(barEl);
}

function pctOf(value, total) {
  if (!total) return "0%";
  const pct = (value / total) * 100;
  if (pct > 0 && pct < 1) return "<1%";
  return Math.round(pct) + "%";
}

// --- DataTable: sortable/filterable/configurable-column tables ---
//
// Retrofits a plain server-rendered <table> (thead + tbody, one <tr> per
// row) with click-to-sort headers, a per-column text filter row, and a
// "Columns" popover to show/hide/reorder columns — all state persisted in
// localStorage per table so it survives a reload. Operates on the DOM
// tbody already produced by each page's own render*() function rather
// than requiring a data-driven rewrite of every table on the site: call
// dt.refresh() after you regenerate a table's tbody.innerHTML and sort/
// filter/column state is reapplied automatically.
//
// A cell can opt into a non-text sort key via `data-sort="<value>"` (used
// for timestamps rendered as "5m ago" and the like) — otherwise the cell's
// text content is used, parsed as a number when it looks like one.
//
// Not suited for a table whose rows come in attached pairs (e.g. a data
// row plus a hidden detail row directly below it) — reordering would
// separate them. None of mustra's sortable tables do that today; skip this
// for any that do in the future.
function initDataTable(table, opts) {
  if (!table || table.dataset.dtInit) return table && table._dt;
  table.dataset.dtInit = "1";
  const storageKey = "mustra-dt-" + (opts && opts.storageKey || table.id || "table");

  let state = { order: null, hidden: [], filters: {}, sortCol: null, sortDir: 1 };
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
    if (saved) state = Object.assign(state, saved);
  } catch (e) {}

  const headRow = table.tHead && table.tHead.rows[0];
  if (!headRow) return null;
  const originalHeaders = [...headRow.cells];
  const colCount = originalHeaders.length;
  if (!state.order || state.order.length !== colCount) state.order = originalHeaders.map((_, i) => i);
  state.hidden = (state.hidden || []).filter(i => i < colCount);

  function saveState() {
    try { localStorage.setItem(storageKey, JSON.stringify(state)); } catch (e) {}
  }

  function dataRows() {
    return [...table.tBodies[0].rows].filter(r => r.cells.length >= colCount && !r.classList.contains("empty-row"));
  }

  // --- filter row ---
  const filterRow = document.createElement("tr");
  filterRow.className = "dt-filter-row";
  originalHeaders.forEach((th, idx) => {
    const td = document.createElement("td");
    const input = document.createElement("input");
    input.type = "search";
    input.placeholder = "filter…";
    input.className = "dt-filter-input";
    input.value = state.filters[idx] || "";
    input.addEventListener("input", () => {
      if (input.value) state.filters[idx] = input.value; else delete state.filters[idx];
      saveState();
      applyFilter();
    });
    td.appendChild(input);
    filterRow.appendChild(td);
    th._dtFilterCell = td;
  });
  table.tHead.appendChild(filterRow);
  // In a table that scrolls inside its box the header row is sticky; the
  // filter row sticks just below it, at the header's measured height, so
  // the column filters stay in reach however far the list is scrolled.
  if (headRow && typeof ResizeObserver === "function") {
    const setHead = () => table.style.setProperty("--dt-head-h", headRow.getBoundingClientRect().height + "px");
    new ResizeObserver(setHead).observe(headRow);
    setHead();
  }

  function applyFilter() {
    const active = Object.entries(state.filters);
    dataRows().forEach(row => {
      const match = active.every(([idx, needle]) => {
        const td = row.cells[+idx];
        const hay = (td ? td.textContent : "").toLowerCase();
        return hay.includes(needle.toLowerCase());
      });
      row.style.display = match ? "" : "none";
    });
  }

  // --- sort ---
  // A full-string match, not parseFloat's partial-parse behavior — parseFloat
  // happily reads "10.0" out of "10.0.0.3" (an IP) or "2026" out of an ISO
  // timestamp and calls that a number, which collapses lots of distinct
  // values down to the same (or a near-identical) sort key and makes
  // sorting look like a no-op. Only a string that is ENTIRELY one number
  // (optionally comma-grouped, optionally a trailing %) counts as numeric.
  const plainNumberPattern = /^-?[\d,]+(\.\d+)?%?$/;
  // Four dot-separated 1-3 digit octets, optionally followed by more
  // comma-joined addresses (the Endpoints table's IPs column) — sorted by
  // the first address as a proper 32-bit integer, not lexicographically
  // (which would put "10.0.0.10" before "10.0.0.3").
  const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/;

  function numericKeyFor(t) {
    const ip = t.match(ipv4Pattern);
    if (ip) {
      return ((+ip[1]) * 16777216) + ((+ip[2]) * 65536) + ((+ip[3]) * 256) + (+ip[4]);
    }
    if (plainNumberPattern.test(t)) {
      return parseFloat(t.replace(/,/g, ""));
    }
    return null;
  }

  function sortValue(row, colIdx) {
    const td = row.cells[colIdx];
    if (!td) return "";
    if (td.dataset.sort !== undefined) {
      const raw = td.dataset.sort;
      const n = numericKeyFor(raw.trim());
      return n === null ? raw.toLowerCase() : n;
    }
    const t = td.textContent.trim();
    const n = numericKeyFor(t);
    return n === null ? t.toLowerCase() : n;
  }

  function applySort() {
    if (state.sortCol === null) return;
    const tbody = table.tBodies[0];
    const rows = dataRows();
    rows.sort((a, b) => {
      const av = sortValue(a, state.sortCol), bv = sortValue(b, state.sortCol);
      if (av < bv) return -1 * state.sortDir;
      if (av > bv) return 1 * state.sortDir;
      return 0;
    });
    rows.forEach(r => tbody.appendChild(r));
  }

  originalHeaders.forEach((th, idx) => {
    th.classList.add("dt-sortable");
    const arrow = document.createElement("span");
    arrow.className = "dt-sort-arrow";
    th.appendChild(arrow);
    th.addEventListener("click", (e) => {
      if (e.target.closest(".dt-columns-btn")) return;
      if (state.sortCol === idx) state.sortDir *= -1; else { state.sortCol = idx; state.sortDir = 1; }
      saveState();
      refresh();
    });
  });

  function updateSortArrows() {
    originalHeaders.forEach((th, idx) => {
      const arrow = th.querySelector(".dt-sort-arrow");
      arrow.textContent = state.sortCol === idx ? (state.sortDir > 0 ? " ▴" : " ▾") : "";
    });
  }

  // --- column order/visibility ---
  function applyOrderAndVisibility() {
    state.order.forEach(origIdx => headRow.appendChild(originalHeaders[origIdx]));
    state.order.forEach(origIdx => filterRow.appendChild(originalHeaders[origIdx]._dtFilterCell));
    originalHeaders.forEach((th, idx) => {
      const hidden = state.hidden.includes(idx);
      th.style.display = hidden ? "none" : "";
      th._dtFilterCell.style.display = hidden ? "none" : "";
    });
    dataRows().forEach(row => {
      const cells = [...row.cells];
      state.order.forEach(origIdx => row.appendChild(cells[origIdx]));
      cells.forEach((td, idx) => { td.style.display = state.hidden.includes(idx) ? "none" : ""; });
    });
  }

  // --- columns popover ---
  const wrap = document.createElement("div");
  wrap.className = "dt-columns-wrap";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "dt-columns-btn";
  btn.textContent = "⚙ Columns";
  btn.setAttribute("aria-haspopup", "true");
  btn.setAttribute("aria-expanded", "false");
  const popover = document.createElement("div");
  popover.className = "dt-columns-popover";
  popover.hidden = true;
  wrap.append(btn, popover);

  function renderPopover() {
    popover.innerHTML = "";
    const list = document.createElement("ul");
    list.className = "dt-columns-list";
    state.order.forEach((origIdx, pos) => {
      const li = document.createElement("li");
      li.draggable = true;
      li.dataset.origIdx = String(origIdx);
      const label = originalHeaders[origIdx].textContent.replace(/[⚙▴▾]/g, "").trim() || ("Column " + (origIdx + 1));
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = !state.hidden.includes(origIdx);
      cb.addEventListener("change", () => {
        state.hidden = state.hidden.filter(i => i !== origIdx);
        if (!cb.checked) state.hidden.push(origIdx);
        saveState();
        refresh();
      });
      li.appendChild(cb);
      const span = document.createElement("span");
      span.textContent = " " + label;
      span.className = "dt-drag-handle";
      li.appendChild(span);
      list.appendChild(li);

      li.addEventListener("dragstart", (e) => { e.dataTransfer.setData("text/plain", String(pos)); li.classList.add("dragging"); });
      li.addEventListener("dragend", () => li.classList.remove("dragging"));
      li.addEventListener("dragover", (e) => e.preventDefault());
      li.addEventListener("drop", (e) => {
        e.preventDefault();
        const fromPos = parseInt(e.dataTransfer.getData("text/plain"), 10);
        const moved = state.order.splice(fromPos, 1)[0];
        const toPos = [...list.children].indexOf(li);
        state.order.splice(toPos, 0, moved);
        saveState();
        applyOrderAndVisibility();
        renderPopover();
      });
    });
    popover.appendChild(list);
    const resetBtn = document.createElement("button");
    resetBtn.type = "button";
    resetBtn.className = "dt-columns-reset";
    resetBtn.textContent = "Reset";
    resetBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      state.order = originalHeaders.map((_, i) => i);
      state.hidden = [];
      saveState();
      if (table._colResize) table._colResize.reset();
      refresh();
      renderPopover();
    });
    popover.appendChild(resetBtn);
  }

  const setOpen = (open) => {
    popover.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
    if (open) renderPopover();
  };
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    setOpen(popover.hidden);
  });
  popover.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => setOpen(false));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !popover.hidden) { setOpen(false); btn.focus(); }
  });

  // Place the columns button just above the table, right-aligned.
  const toolbar = document.createElement("div");
  toolbar.className = "dt-toolbar";

  // As cards (see initResponsiveTables) the headings are gone, and with
  // them the click-to-sort; this select stands in for them.
  const sortSelect = document.createElement("select");
  sortSelect.className = "dt-sort-select";
  sortSelect.setAttribute("aria-label", "Sort rows by");
  function renderSortSelect() {
    const opts = ['<option value="">Sort by…</option>'];
    state.order.forEach(idx => {
      if (state.hidden.includes(idx)) return;
      const name = originalHeaders[idx].textContent.replace(/[⚙▴▾]/g, "").trim();
      if (!name) return;
      opts.push(`<option value="${/* safe-html: a column index */ idx}:1">Sort: ${escapeHtml(name)} ▴</option>`,
        `<option value="${/* safe-html: a column index */ idx}:-1">Sort: ${escapeHtml(name)} ▾</option>`);
    });
    sortSelect.innerHTML = opts.join("");
    sortSelect.value = state.sortCol === null ? "" : `${state.sortCol}:${state.sortDir}`;
  }
  sortSelect.addEventListener("change", () => {
    const [col, dir] = sortSelect.value.split(":");
    state.sortCol = sortSelect.value ? +col : null;
    state.sortDir = sortSelect.value ? +dir : 1;
    saveState();
    refresh();
  });
  toolbar.append(sortSelect, wrap);
  const host = table.closest(".table-scroll") || table;
  host.parentNode.insertBefore(toolbar, host);

  function refresh() {
    applyOrderAndVisibility();
    applySort();
    applyFilter();
    updateSortArrows();
    renderSortSelect();
    if (table._colResize) table._colResize.apply();
  }
  makeColumnsResizable(table, (opts && opts.storageKey) || table.id || "table");
  makeHeadersReorderable(table, th => { const i = originalHeaders.indexOf(th); return i < 0 ? null : i; }, (from, to, after) => {
    const f = +from, t = +to;
    state.order = state.order.filter(i => i !== f);
    let at = state.order.indexOf(t);
    if (after) at++;
    state.order.splice(at, 0, f);
    saveState();
    refresh();
    if (!popover.hidden) renderPopover();
  });
  refresh();

  const dt = { refresh };
  table._dt = dt;
  return dt;
}

// showToast: a short message in the corner that goes away on its own, so a
// save is visibly confirmed wherever the button was. kind: "ok" (green),
// "error" (red) or "info". Announced to screen readers as a status.
function showToast(text, kind) {
  let host = document.getElementById("toast-host");
  if (!host) {
    host = document.createElement("div");
    host.id = "toast-host";
    host.setAttribute("role", "status");
    host.setAttribute("aria-live", "polite");
    document.body.appendChild(host);
  }
  const t = document.createElement("div");
  t.className = "toast toast-" + (kind || "info");
  const icon = document.createElement("span");
  icon.className = "toast-icon";
  icon.textContent = kind === "error" ? "!" : kind === "ok" ? "✓" : "i";
  const msg = document.createElement("span");
  msg.textContent = text;
  t.append(icon, msg);
  t.addEventListener("click", () => t.remove());
  host.appendChild(t);
  while (host.children.length > 3) host.firstChild.remove();
  setTimeout(() => { t.classList.add("toast-out"); setTimeout(() => t.remove(), 300); }, kind === "error" ? 8000 : 4000);
}

// makeHeadersReorderable: drag a column header onto another to move the
// column there (before or after it, by which half it is dropped on).
// getKey names a header's column (null: not movable); onMove(from, to,
// after) applies the move. Pointer events rather than HTML drag and drop:
// Firefox will not start a native drag from a button inside a header, and
// touch screens need it too. A short press is still a click (sort); a
// press on a resize grip or a control is left alone.
function makeHeadersReorderable(table, getKey, onMove) {
  const headRow = table && table.tHead && table.tHead.rows[0];
  if (!headRow || headRow.dataset.reorderInit) return;
  headRow.dataset.reorderInit = "1";
  const clear = () => headRow.querySelectorAll(".dt-drop-before, .dt-drop-after, .dt-col-dragging")
    .forEach(el => el.classList.remove("dt-drop-before", "dt-drop-after", "dt-col-dragging"));
  headRow.addEventListener("pointerdown", e => {
    if (e.button !== 0 || table.dataset.resizing) return;
    if (e.target.closest(".col-resizer, input, select, textarea, a")) return;
    const th = e.target.closest("th");
    if (!th || th.parentElement !== headRow || getKey(th) == null) return;
    const startX = e.clientX, startY = e.clientY;
    let dragging = false, target = null, after = false;
    const move = ev => {
      if (!dragging) {
        if (Math.abs(ev.clientX - startX) < 8 && Math.abs(ev.clientY - startY) < 8) return;
        dragging = true;
        th.classList.add("dt-col-dragging");
        document.body.classList.add("dt-col-moving");
      }
      ev.preventDefault();
      headRow.querySelectorAll(".dt-drop-before, .dt-drop-after").forEach(el => el.classList.remove("dt-drop-before", "dt-drop-after"));
      target = null;
      for (const c of headRow.cells) {
        if (c === th || getKey(c) == null || c.style.display === "none") continue;
        const r = c.getBoundingClientRect();
        if (ev.clientX >= r.left && ev.clientX <= r.right) {
          target = c; after = ev.clientX > r.left + r.width / 2;
          c.classList.add(after ? "dt-drop-after" : "dt-drop-before");
          break;
        }
      }
    };
    const up = () => {
      document.removeEventListener("pointermove", move);
      document.removeEventListener("pointerup", up);
      document.removeEventListener("pointercancel", up);
      document.body.classList.remove("dt-col-moving");
      clear();
      if (!dragging) return;
      // The click that ends a drag is not a sort.
      // It fires right after pointerup, before any timer; if it doesn't
      // come, the guard is gone before the next real click.
      const eat = ev => { ev.stopPropagation(); ev.preventDefault(); window.removeEventListener("click", eat, true); };
      window.addEventListener("click", eat, true);
      setTimeout(() => window.removeEventListener("click", eat, true), 0);
      if (target) onMove(String(getKey(th)), String(getKey(target)), after);
    };
    document.addEventListener("pointermove", move);
    document.addEventListener("pointerup", up);
    document.addEventListener("pointercancel", up);
  });
}

// makeColumnsResizable: drag a header's right edge to set its column's
// width, double-click the edge to fit the widest content. Widths are kept
// in localStorage per table, keyed by the column's name (th.dataset.colKey
// or its text), so they follow a column that is moved or hidden. Until a
// column is sized the table lays itself out as before. A <th> with
// data-no-resize keeps its width.
function makeColumnsResizable(table, key) {
  const headRow = table && table.tHead && table.tHead.rows[0];
  if (!headRow) return null;
  const storageKey = "mustra-colw-" + key;
  let widths = {};
  try { widths = JSON.parse(localStorage.getItem(storageKey) || "{}") || {}; } catch (e) { widths = {}; }
  const save = () => { try { localStorage.setItem(storageKey, JSON.stringify(widths)); } catch (e) {} };
  const colKey = th => th.dataset.colKey || (th._colKey = th._colKey || (th.textContent || "").replace(/[▴▾⚙]/g, "").trim() || "col" + th.cellIndex);
  const visible = () => [...headRow.cells].filter(th => th.style.display !== "none");

  // Fixed layout from the header row: every visible column gets its saved
  // width or, if it has none yet, the width it has now.
  function apply() {
    if (!Object.keys(widths).length) {
      table.classList.remove("cols-sized");
      table.style.tableLayout = ""; table.style.width = "";
      [...headRow.cells].forEach(th => { th.style.width = ""; });
      return;
    }
    table.style.tableLayout = ""; table.style.width = "";
    const cells = visible();
    const natural = cells.map(th => th.getBoundingClientRect().width);
    // A column that isn't resizable (row buttons, a checkbox) keeps the
    // width its page's stylesheet gives it, whatever else is resized.
    const ws = cells.map((th, i) => th.dataset.noResize !== undefined
      ? Math.ceil(natural[i])
      : (widths[colKey(th)] || Math.ceil(natural[i])));
    // Narrower than its box: one column takes the rest, so the table still
    // reaches the right edge while fixed columns (a row's buttons) stay
    // their size: the visible column marked data-flex, else the last
    // resizable one. That stretch is not saved.
    const box = (table.parentElement && table.parentElement.clientWidth) || 0;
    let total = ws.reduce((a, b) => a + b, 0);
    if (box > total && ws.length) {
      let i = cells.findIndex(th => th.dataset.flex !== undefined && th.dataset.noResize === undefined);
      if (i < 0) { i = cells.length - 1; while (i > 0 && cells[i].dataset.noResize !== undefined) i--; }
      ws[i] += box - total; total = box;
    }
    cells.forEach((th, i) => { th.style.width = ws[i] + "px"; });
    table.style.tableLayout = "fixed";
    table.style.width = total + "px";
    table.classList.add("cols-sized");
  }
  function freeze() { // before the first drag: keep every column where it is
    // Not the column that takes the leftover space (its width may include
    // that stretch) nor fixed columns: those are worked out on every apply.
    const cells = visible();
    let last = cells.findIndex(th => th.dataset.flex !== undefined && th.dataset.noResize === undefined);
    if (last < 0) { last = cells.length - 1; while (last > 0 && cells[last].dataset.noResize !== undefined) last--; }
    cells.forEach((th, i) => {
      if (i === last) return;
      const k = colKey(th);
      if (!widths[k] && th.dataset.noResize === undefined) widths[k] = Math.ceil(th.getBoundingClientRect().width);
    });
  }
  function setWidth(th, w) {
    widths[colKey(th)] = Math.max(36, Math.round(w));
    apply();
  }

  // The widest thing in the column: each cell's content measured on one
  // line, plus the cell's own padding.
  const measurer = document.createElement("div");
  measurer.style.cssText = "position:absolute;left:-10000px;top:0;visibility:hidden;white-space:nowrap;width:max-content";
  function contentWidth(th) {
    const idx = th.cellIndex;
    const cells = [th];
    for (const body of table.tBodies) for (const row of [...body.rows].slice(0, 500)) {
      const c = row.cells[idx];
      if (c && row.cells.length === headRow.cells.length && row.style.display !== "none") cells.push(c);
    }
    document.body.appendChild(measurer);
    let max = 0;
    for (const c of cells) {
      const cs = getComputedStyle(c);
      measurer.style.font = cs.font;
      measurer.innerHTML = "";
      for (const n of c.childNodes) if (!(n.classList && n.classList.contains("col-resizer"))) measurer.appendChild(n.cloneNode(true));
      const pad = parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight) + parseFloat(cs.borderLeftWidth) + parseFloat(cs.borderRightWidth);
      max = Math.max(max, measurer.scrollWidth + pad + (c === th ? 10 : 2));
    }
    measurer.remove();
    return Math.ceil(max);
  }
  function fit(th) {
    freeze();
    setWidth(th, Math.min(contentWidth(th), 900));
    save();
  }

  [...headRow.cells].forEach(th => {
    if (th.dataset.noResize !== undefined || th.querySelector(".col-resizer")) return;
    if (getComputedStyle(th).position === "static") th.style.position = "relative";
    const grip = document.createElement("span");
    grip.className = "col-resizer";
    grip.title = "Drag to resize · double-click to fit";
    grip.setAttribute("aria-hidden", "true");
    grip.addEventListener("click", e => e.stopPropagation());
    grip.addEventListener("dblclick", e => { e.preventDefault(); e.stopPropagation(); fit(th); });
    grip.addEventListener("pointerdown", e => {
      if (e.button !== 0) return;
      e.preventDefault(); e.stopPropagation();
      freeze(); apply();
      const startX = e.clientX, startW = th.getBoundingClientRect().width;
      grip.setPointerCapture(e.pointerId);
      table.classList.add("col-resizing");
      table.dataset.resizing = "1";
      const move = ev => setWidth(th, startW + ev.clientX - startX);
      const up = () => {
        grip.removeEventListener("pointermove", move);
        table.classList.remove("col-resizing");
        delete table.dataset.resizing;
        save();
      };
      grip.addEventListener("pointermove", move);
      grip.addEventListener("pointerup", up, { once: true });
      grip.addEventListener("pointercancel", up, { once: true });
    });
    th.appendChild(grip);
  });

  const api = {
    apply,
    reset() { widths = {}; save(); apply(); },
  };
  table._colResize = api;
  apply();
  return api;
}

renderSidebarShell();
paintIcons();
loadUser();
initAccessibilityRepairs();
initResponsiveTables();

// --- accessibility repairs ---------------------------------------------------
//
// Pages build much of their markup at runtime, page by page, and two shapes
// recur that leave assistive technology guessing:
//
//   - a `.field` whose <label> is a sibling of its control but not tied to
//     it, so the control has no accessible name;
//   - a scrolling table wrapper with nothing focusable inside, which a
//     keyboard user cannot scroll at all.
//
// Fixing every template by hand would miss the next one, so the shared
// shell repairs both wherever they appear, now and as pages re-render.
// Markup that already names its control is left exactly as it is.
const A11Y_CONTROL = "input:not([type=hidden]), select, textarea";
const A11Y_FOCUSABLE = "a[href], button, input, select, textarea, [tabindex]";
const A11Y_SCROLLERS = ".table-scroll, .affected-scroll, .scroll-x, pre";
let a11yIds = 0;

function a11yHasName(el) {
  if (el.getAttribute("aria-label") || el.getAttribute("aria-labelledby")) return true;
  if (el.closest("label")) return true;
  return !!(el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`));
}

function a11yLinkFieldLabels(root) {
  root.querySelectorAll(".field > label:not([for])").forEach(label => {
    if (label.querySelector(A11Y_CONTROL)) return; // wraps its control already
    const control = label.parentElement.querySelector(A11Y_CONTROL);
    if (!control || a11yHasName(control)) return;
    if (!control.id) control.id = `a11y-field-${++a11yIds}`;
    label.htmlFor = control.id;
  });
}

function a11yScrollers(root) {
  root.querySelectorAll(A11Y_SCROLLERS).forEach(el => {
    const scrolls = el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1;
    if (!scrolls || el.hasAttribute("tabindex") || el.querySelector(A11Y_FOCUSABLE)) return;
    el.tabIndex = 0;
    if (!el.getAttribute("aria-label") && el.tagName !== "PRE") {
      const panel = el.closest(".panel, section");
      const heading = panel && panel.querySelector("h2, h3");
      el.setAttribute("role", "region");
      el.setAttribute("aria-label", heading ? heading.textContent.trim() : "Scrollable table");
    }
  });
}

function initAccessibilityRepairs() {
  let queued = false;
  const run = () => {
    queued = false;
    a11yLinkFieldLabels(document);
    a11yScrollers(document);
  };
  const queue = () => { if (!queued) { queued = true; requestAnimationFrame(run); } };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", queue);
  else queue();
  new MutationObserver(queue).observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener("resize", queue);
}

// --- responsive tables ---------------------------------------------------------
//
// A table too wide for its box turns into a stack of cards, one per row,
// each cell labelled with its column's heading. Whether a table fits is
// measured, not guessed from the viewport: a seven-column table is too wide
// for a tablet, a two-column one fits a phone, and a table in a narrow
// dashboard panel is narrow on any screen. Pages keep rendering ordinary
// tables; like the repairs above, this finds them wherever they appear and
// follows them as they re-render. Only a wrapper or table with class `cards`
// does this now: every other table stays a compact table that scrolls
// sideways and down inside its box, on a phone as on a desktop.
const RT_WRAPPERS = ".table-scroll, .dl-table-wrap, .dv-scroll, .affected-scroll, .scroll-x";
const rtState = new WeakMap(); // wrapper -> { width, dirty }

function rtTable(wrap) {
  const t = wrap.firstElementChild;
  return t && t.tagName === "TABLE" && t.tHead && t.tHead.rows.length && t.tBodies.length
    && (wrap.classList.contains("cards") || t.classList.contains("cards")) ? t : null;
}

function rtHeadings(table) {
  // The first header row names the columns; data-table adds a filter row
  // under it, which names nothing. Colspans widen a heading over columns.
  const names = [];
  for (const th of table.tHead.rows[0].cells) {
    if (th.style.display === "none") { names.push(null); continue; }
    const name = th.textContent.replace(/[⚙▴▾]/g, "").replace(/\s+/g, " ").trim();
    for (let i = 0; i < th.colSpan; i++) names.push(name);
  }
  return names;
}

function rtLabel(table) {
  const names = rtHeadings(table);
  for (const row of table.tBodies[0].rows) {
    let col = 0;
    for (const td of row.cells) {
      const full = td.colSpan >= names.length;
      td.classList.toggle("rt-full", full);
      const label = full ? "" : (names[col] || "");
      if (td.dataset.label !== label) td.dataset.label = label;
      col += td.colSpan;
    }
  }
}

function rtFit(wrap, table) {
  // Measure as a table: if it would overflow its box, it becomes cards.
  wrap.classList.remove("rt-cards");
  // Columns somebody sized are meant to be wider than the box: scroll,
  // don't fold into cards, unless the screen really is a phone's.
  const cards = table.offsetWidth > wrap.clientWidth + 1 &&
    !(table.classList.contains("cols-sized") && window.innerWidth > 760);
  wrap.classList.toggle("rt-cards", cards);
  const bar = wrap.previousElementSibling;
  if (bar && bar.classList.contains("dt-toolbar")) bar.classList.toggle("rt-cards-on", cards);
}

function initResponsiveTables() {
  let queued = false, observer;
  const run = () => {
    queued = false;
    document.querySelectorAll(RT_WRAPPERS).forEach(wrap => {
      const table = rtTable(wrap);
      if (!table) return;
      let st = rtState.get(wrap);
      if (!st) { st = { width: -1, dirty: true }; rtState.set(wrap, st); resizes.observe(wrap); }
      const width = wrap.clientWidth;
      if (!width) return; // hidden: measured once it is shown
      if (!st.dirty && width === st.width) return;
      st.dirty = false; st.width = width;
      rtLabel(table);
      rtFit(wrap, table);
    });
    observer.takeRecords(); // our own class and label changes are not news
  };
  const queue = () => { if (!queued) { queued = true; requestAnimationFrame(run); } };
  const resizes = new ResizeObserver(queue);
  observer = new MutationObserver(records => {
    for (const r of records) {
      const el = r.target.nodeType === 1 ? r.target : r.target.parentElement;
      const wrap = el && el.closest(RT_WRAPPERS);
      const st = wrap && rtState.get(wrap);
      if (st) st.dirty = true;
    }
    queue();
  });
  observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", queue);
  else queue();
}

// An explicit row group is one predicate. Unmarked conditions retain the
// existing endpoint-wide semantics when loading older groups and queries.
function sameRowRules(rules) {
  const groups = new Map(), out = [];
  for (const r of rules) {
    const i = r.field.indexOf('.');
    if (i < 0 || r.field.endsWith('.count') || r.field.slice(i + 1).startsWith('_')) { out.push(r); continue; }
    const sensor = r.field.slice(0, i);
    if (!groups.has(sensor)) groups.set(sensor, []);
    groups.get(sensor).push(r);
  }
  for (const [sensor, children] of groups) out.push({field:sensor+'._row',op:'same_row',value:JSON.stringify(children)});
  return out;
}

// mountChecklist turns a container into a bounded, scrollable list of
// checkboxes with search, select/deselect all, invert and a "selected only"
// view. It replaces wrapping rows of bare checkboxes and multi-selects that
// needed ctrl-click: past a dozen entries those stop being scannable, and a
// multi-select loses every choice to one click without the modifier.
//
// items: [{value, label, hint?, key?, group?}] — group gives sections with a
// tri-state header that selects the whole section. noneText is what an
// empty selection *means* ("whole fleet", "read-only role"), shown in place
// of "0 selected" because for these fields none is a deliberate answer.
// emptyHTML is caller-escaped markup shown when there are no items at all.
//
// Returns {values(), setValues(list), setItems(items)}; the container fires
// a bubbling "change" event whenever the selection changes.
function mountChecklist(container, opts) {
  opts = opts || {};
  let items = [];
  let selected = new Set();
  let query = "";
  let onlySelected = false;
  const uid = "cl" + Math.random().toString(36).slice(2, 8);

  container.classList.add("checklist");
  container.innerHTML = `
    <div class="checklist-bar">
      <label class="checklist-search">${icon("search")}<input type="search" placeholder="${escapeHtml(opts.searchPlaceholder || "Search")}" aria-label="${escapeHtml(opts.searchPlaceholder || "Search")}"></label>
      <div class="checklist-actions" role="toolbar" aria-label="${escapeHtml((opts.label || "Selection") + " actions")}">
        <button type="button" class="checklist-btn" data-act="all">Select all</button>
        <button type="button" class="checklist-btn" data-act="none">Deselect all</button>
        <button type="button" class="checklist-btn" data-act="invert">Invert</button>
        <label class="checklist-toggle"><input type="checkbox" data-act="only"> Selected only</label>
      </div>
    </div>
    <div class="checklist-box" tabindex="0" role="group" aria-label="${escapeHtml(opts.label || "Options")}"></div>
    <div class="checklist-foot"><span class="checklist-count" aria-live="polite"></span></div>`;
  const box = container.querySelector(".checklist-box");
  const search = container.querySelector(".checklist-search input");
  const count = container.querySelector(".checklist-count");
  const allBtn = container.querySelector('[data-act="all"]');
  const noneBtn = container.querySelector('[data-act="none"]');

  const matches = it => {
    if (onlySelected && !selected.has(it.value)) return false;
    if (!query) return true;
    return [it.label, it.key, it.hint, it.group].some(s => s && String(s).toLowerCase().includes(query));
  };
  const visible = () => items.filter(matches);

  function emit() { container.dispatchEvent(new Event("change", { bubbles: true })); }

  function updateCount() {
    const n = items.filter(it => selected.has(it.value)).length;
    count.textContent = n === 0 && opts.noneText
      ? `None selected — ${opts.noneText}`
      : `${n} of ${items.length} selected`;
    count.classList.toggle("is-none", n === 0);
    const filtered = !!query || onlySelected;
    allBtn.textContent = filtered ? "Select shown" : "Select all";
    noneBtn.textContent = filtered ? "Deselect shown" : "Deselect all";
    container.querySelectorAll(".checklist-btn").forEach(b => { b.disabled = items.length === 0; });
    // Section headers are tri-state: a half-ticked section says "some of
    // these" without making anyone expand it to find out which.
    box.querySelectorAll(".checklist-group").forEach(g => {
      const vals = JSON.parse(g.dataset.values);
      const on = vals.filter(v => selected.has(v)).length;
      const head = g.querySelector(".checklist-group-head input");
      head.checked = on > 0 && on === vals.length;
      head.indeterminate = on > 0 && on < vals.length;
      g.querySelector(".checklist-group-count").textContent = `${on}/${vals.length}`;
    });
  }

  function render() {
    if (items.length === 0) {
      box.innerHTML = `<div class="checklist-empty">${/* safe-html: emptyHTML is caller-escaped markup (documented above) */ opts.emptyHTML || "Nothing to choose from yet."}</div>`;
      updateCount();
      return;
    }
    const shown = visible();
    if (shown.length === 0) {
      box.innerHTML = `<div class="checklist-empty">${onlySelected && !query ? "Nothing selected." : "No matches for “" + escapeHtml(query) + "”."}</div>`;
      updateCount();
      return;
    }
    const groups = new Map();
    for (const it of shown) {
      const g = it.group || "";
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(it);
    }
    let html = "";
    let n = 0;
    for (const [g, list] of groups) {
      const rows = list.map(it => {
        const id = `${uid}-${n++}`;
        return `<label class="checklist-item" for="${id}">
          <input type="checkbox" id="${id}" value="${escapeHtml(it.value)}"${selected.has(it.value) ? " checked" : ""}>
          <span class="checklist-text">
            <span class="checklist-label">${escapeHtml(it.label)}${it.key && it.key !== it.label ? ` <code>${escapeHtml(it.key)}</code>` : ""}</span>
            ${it.hint ? `<span class="checklist-hint">${escapeHtml(it.hint)}</span>` : ""}
          </span>
        </label>`;
      }).join("");
      html += g
        ? `<div class="checklist-group" data-values="${escapeHtml(JSON.stringify(list.map(it => it.value)))}">
             <label class="checklist-group-head"><input type="checkbox" aria-label="Select every item in ${escapeHtml(g)}"><span>${escapeHtml(g)}</span><span class="checklist-group-count"></span></label>
             ${rows}
           </div>`
        : rows;
    }
    box.innerHTML = html;
    updateCount();
  }

  box.addEventListener("change", e => {
    const t = e.target;
    if (!(t instanceof HTMLInputElement)) return;
    if (t.closest(".checklist-group-head")) {
      const vals = JSON.parse(t.closest(".checklist-group").dataset.values);
      vals.forEach(v => t.checked ? selected.add(v) : selected.delete(v));
      box.querySelectorAll(".checklist-item input").forEach(c => { if (vals.includes(c.value)) c.checked = t.checked; });
    } else {
      t.checked ? selected.add(t.value) : selected.delete(t.value);
      // "Selected only" drops a row the moment it is unticked; redraw so
      // the list never shows an unticked row in a selected-only view.
      if (onlySelected && !t.checked) { render(); emit(); return; }
    }
    updateCount();
    emit();
  });
  search.addEventListener("input", () => { query = search.value.trim().toLowerCase(); render(); });
  container.querySelector(".checklist-bar").addEventListener("click", e => {
    const act = e.target.closest("button[data-act]")?.dataset.act;
    if (!act) return;
    const shown = visible();
    if (act === "all") shown.forEach(it => selected.add(it.value));
    if (act === "none") shown.forEach(it => selected.delete(it.value));
    if (act === "invert") shown.forEach(it => selected.has(it.value) ? selected.delete(it.value) : selected.add(it.value));
    render();
    emit();
  });
  container.querySelector('[data-act="only"]').addEventListener("change", e => { onlySelected = e.target.checked; render(); });

  const api = {
    values: () => items.filter(it => selected.has(it.value)).map(it => it.value),
    setValues(list) { selected = new Set(list || []); render(); },
    setItems(list) {
      items = list || [];
      // Keep a selection made before the items arrived (an edit opened
      // while the list was still loading) rather than dropping it.
      render();
    },
  };
  api.setItems(opts.items || []);
  container._checklist = api;
  return api;
}

// --- icons everywhere --------------------------------------------------
//
// Colour comes from what a thing is, not where it sits: patching is always
// blue, risk always red, time always amber, so a heading, a tile and a
// section entry about the same idea read alike across the console. The
// hues are VS Code's own theme colours, so they sit well on the Modern
// palette and hold up on the others.

const ICON_HUES = {
  patch: "#4daafc", bug: "#f14c4c", alert: "#f48771", clients: "#3794ff", clock: "#cca700", deploy: "#e5813b",
  box: "#e5813b", comply: "#73c991", users: "#c586c0", user: "#c586c0", certificate: "#d7ba7d", globe: "#4ec9b0",
  search: "#9cdcfe", chart: "#b180d7", shield: "#f48771", settings: "#a0a7b4", key: "#dcdcaa", list: "#9da5b4",
  database: "#4ec9b0", performance: "#f472b6", tag: "#75beff", signal: "#73c991", plug: "#f14c4c", layers: "#b180d7",
  rocket: "#e5813b", radar: "#4ec9b0", download: "#4daafc", book: "#d7ba7d", sync: "#75beff", lock: "#dcdcaa",
  terminal: "#89d185", connect: "#4ec9b0", integrity: "#73c991", interact: "#75beff", discover: "#4ec9b0",
  grid: "#9da5b4", home: "#4daafc", chat: "#c586c0", star: "#cca700", folder: "#d7ba7d", scale: "#a0a7b4",
  groups: "#3794ff", sliders: "#a0a7b4", door: "#f48771", info: "#75beff", bag: "#e5813b", cpu: "#b180d7",
};
function iconHue(name) { return ICON_HUES[name] || "#75beff"; }

// What a heading or tile is about, by its words. First match wins, so the
// specific ideas come before the general ones ("patch compliance" is about
// patching before it is about compliance).
const TOPIC_ICONS = [
  [/offline|disconnect|unreachable/i, "plug"],
  [/online|connected|reporting now/i, "signal"],
  [/patch|windows update|missing update/i, "patch"],
  [/vulnerab|cve|exploit|kev|epss/i, "bug"],
  [/certificate/i, "certificate"],
  [/distinct|layer|ring/i, "layers"],
  [/version|rollout|release|behind/i, "tag"],
  [/maintenance|window|schedul|timeline|history|recent|over time|when/i, "clock"],
  [/deploy|package|software|install|catalog|self service/i, "deploy"],
  [/benchmark|complian|policy|policies|posture/i, "comply"],
  [/threat|ioc|integrity|security|incident/i, "shield"],
  [/alert|notif|guide|warning|failing|drift/i, "alert"],
  [/user|people|account|admin|logon|session|request|approval/i, "users"],
  [/site|network|interface|neighbo|subnet|scan|discover/i, "globe"],
  [/credential|vault|key|secret|access|token/i, "key"],
  [/query|question|search|sensor|live/i, "search"],
  [/backup|database|storage|disk/i, "database"],
  [/performance|health|cpu|memory/i, "performance"],
  [/architecture|hardware|platform|operating|cpu/i, "cpu"],
  [/setting|profile|config|preference/i, "settings"],
  [/log|audit|event|activity/i, "list"],
  [/dashboard|chart|overview|status|summary|fleet|count|total/i, "chart"],
  [/endpoint|device|computer|client|agent|machine|asset/i, "clients"],
];
function topicIcon(text) {
  for (const [re, name] of TOPIC_ICONS) if (re.test(text)) return name;
  return "";
}

function subnavDescFor(label) {
  for (const c of NAV_TREE) for (const s of (c.sub || [])) if (s.label === label) return s.desc || "";
  return "";
}

function subnavIconFor(label) {
  for (const c of NAV_TREE) for (const s of (c.sub || [])) if (s.label === label) return s.icon || "";
  return topicIcon(label) || "list";
}

// Module colours for the Home tiles: each module its own, like apps on a
// home screen.
const MODULE_HUES = {
  "/access": "#dcdcaa", "/settings": "#a0a7b4", "/backup": "#4ec9b0", "/backup-status": "#73c991", "/threats": "#f14c4c", "/certificates": "#d7ba7d", "/agents": "#3794ff",
  "/compliance": "#73c991", "/connect": "#4ec9b0", "/dashboards": "#b180d7", "/deploy": "#e5813b", "/shell": "#89d185",
  "/discover": "#4ec9b0", "/enforce": "#f14c4c", "/engage": "#c586c0", "/guide": "#cca700", "/impact": "#f48771",
  "/integrity": "#73c991", "/interact": "#75beff", "/eun": "#cca700", "/patches": "#4daafc", "/performance": "#f472b6",
  "/playbooks": "#4ec9b0", "/reports": "#9cdcfe", "/reveal": "#c586c0", "/sensors": "#4ec9b0", "/hunt": "#f14c4c",
};
function moduleHue(m) { return MODULE_HUES[m.href] || iconHue(m.icon); }

// Operating systems by their marks. Filled brand glyphs, unlike the line
// set: a logo drawn as an outline stops reading as the logo.
const OS_LOGOS = {
  apple: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M16.4 12.7c0-2.4 2-3.6 2.1-3.7-1.2-1.7-3-1.9-3.6-1.9-1.5-.2-3 .9-3.8.9s-2-.9-3.3-.9c-1.7 0-3.3 1-4.2 2.5-1.8 3.1-.5 7.7 1.3 10.2.9 1.2 1.9 2.6 3.2 2.6 1.3-.1 1.8-.8 3.3-.8s2 .8 3.3.8c1.4 0 2.3-1.3 3.1-2.5 1-1.4 1.4-2.8 1.4-2.9-.1 0-2.8-1-2.8-4.3zM14 5.6c.7-.8 1.2-2 1-3.1-1 0-2.2.7-2.9 1.5-.6.7-1.2 1.9-1 3 1.1.1 2.2-.6 2.9-1.4z"/></svg>',
  windows: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#00a4ef" d="M2.5 4.6 10.3 3.5v7.6H2.5zM11.3 3.4 21.5 2v9.1H11.3zM2.5 12.1h7.8v7.6l-7.8-1.1zM11.3 12.1h10.2V21l-10.2-1.4z"/></svg>',
  raspberrypi: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#75a928" d="M5.6 2.4c2.2.1 4.6 1.2 5.9 3.2-1.9.5-4.2-.2-5.9-3.2zM18.4 2.4c-2.2.1-4.6 1.2-5.9 3.2 1.9.5 4.2-.2 5.9-3.2z"/><g fill="#c51a4a"><circle cx="12" cy="8.6" r="2.5"/><circle cx="8.3" cy="10.6" r="2.4"/><circle cx="15.7" cy="10.6" r="2.4"/><circle cx="12" cy="13.2" r="2.6"/><circle cx="7.7" cy="14.6" r="2.3"/><circle cx="16.3" cy="14.6" r="2.3"/><circle cx="9.9" cy="18.1" r="2.4"/><circle cx="14.1" cy="18.1" r="2.4"/><circle cx="12" cy="20.6" r="1.9"/></g></svg>',
  // Distribution marks: Simple Icons (CC0), in each project's colour; the
  // darkest switch to the text colour so they show on dark themes.
  debian: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#A81D33" d="M13.88 12.685c-.4 0 .08.2.601.28.14-.1.27-.22.39-.33a3.001 3.001 0 01-.99.05m2.14-.53c.23-.33.4-.69.47-1.06-.06.27-.2.5-.33.73-.75.47-.07-.27 0-.56-.8 1.01-.11.6-.14.89m.781-2.05c.05-.721-.14-.501-.2-.221.07.04.13.5.2.22M12.38.31c.2.04.45.07.42.12.23-.05.28-.1-.43-.12m.43.12l-.15.03.14-.01V.43m6.633 9.944c.02.64-.2.95-.38 1.5l-.35.181c-.28.54.03.35-.17.78-.44.39-1.34 1.22-1.62 1.301-.201 0 .14-.25.19-.34-.591.4-.481.6-1.371.85l-.03-.06c-2.221 1.04-5.303-1.02-5.253-3.842-.03.17-.07.13-.12.2a3.551 3.552 0 012.001-3.501 3.361 3.362 0 013.732.48 3.341 3.342 0 00-2.721-1.3c-1.18.01-2.281.76-2.651 1.57-.6.38-.67 1.47-.93 1.661-.361 2.601.66 3.722 2.38 5.042.27.19.08.21.12.35a4.702 4.702 0 01-1.53-1.16c.23.33.47.66.8.91-.55-.18-1.27-1.3-1.48-1.35.93 1.66 3.78 2.921 5.261 2.3a6.203 6.203 0 01-2.33-.28c-.33-.16-.77-.51-.7-.57a5.802 5.803 0 005.902-.84c.44-.35.93-.94 1.07-.95-.2.32.04.16-.12.44.44-.72-.2-.3.46-1.24l.24.33c-.09-.6.74-1.321.66-2.262.19-.3.2.3 0 .97.29-.74.08-.85.15-1.46.08.2.18.42.23.63-.18-.7.2-1.2.28-1.6-.09-.05-.28.3-.32-.53 0-.37.1-.2.14-.28-.08-.05-.26-.32-.38-.861.08-.13.22.33.34.34-.08-.42-.2-.75-.2-1.08-.34-.68-.12.1-.4-.3-.34-1.091.3-.25.34-.74.54.77.84 1.96.981 2.46-.1-.6-.28-1.2-.49-1.76.16.07-.26-1.241.21-.37A7.823 7.824 0 0017.702 1.6c.18.17.42.39.33.42-.75-.45-.62-.48-.73-.67-.61-.25-.65.02-1.06 0C15.082.73 14.862.8 13.8.4l.05.23c-.77-.25-.9.1-1.73 0-.05-.04.27-.14.53-.18-.741.1-.701-.14-1.431.03.17-.13.36-.21.55-.32-.6.04-1.44.35-1.18.07C9.6.68 7.847 1.3 6.867 2.22L6.838 2c-.45.54-1.96 1.611-2.08 2.311l-.131.03c-.23.4-.38.85-.57 1.261-.3.52-.45.2-.4.28-.6 1.22-.9 2.251-1.16 3.102.18.27 0 1.65.07 2.76-.3 5.463 3.84 10.776 8.363 12.006.67.23 1.65.23 2.49.25-.99-.28-1.12-.15-2.08-.49-.7-.32-.85-.7-1.34-1.13l.2.35c-.971-.34-.57-.42-1.361-.67l.21-.27c-.31-.03-.83-.53-.97-.81l-.34.01c-.41-.501-.63-.871-.61-1.161l-.111.2c-.13-.21-1.52-1.901-.8-1.511-.13-.12-.31-.2-.5-.55l.14-.17c-.35-.44-.64-1.02-.62-1.2.2.24.32.3.45.33-.88-2.172-.93-.12-1.601-2.202l.15-.02c-.1-.16-.18-.34-.26-.51l.06-.6c-.63-.74-.18-3.102-.09-4.402.07-.54.53-1.1.88-1.981l-.21-.04c.4-.71 2.341-2.872 3.241-2.761.43-.55-.09 0-.18-.14.96-.991 1.26-.7 1.901-.88.7-.401-.6.16-.27-.151 1.2-.3.85-.7 2.421-.85.16.1-.39.14-.52.26 1-.49 3.151-.37 4.562.27 1.63.77 3.461 3.011 3.531 5.132l.08.02c-.04.85.13 1.821-.17 2.711l.2-.42M9.54 13.236l-.05.28c.26.35.47.73.8 1.01-.24-.47-.42-.66-.75-1.3m.62-.02c-.14-.15-.22-.34-.31-.52.08.32.26.6.43.88l-.12-.36m10.945-2.382l-.07.15c-.1.76-.34 1.511-.69 2.212.4-.73.65-1.541.75-2.362M12.45.12c.27-.1.66-.05.95-.12-.37.03-.74.05-1.1.1l.15.02M3.006 5.142c.07.57-.43.8.11.42.3-.66-.11-.18-.1-.42m-.64 2.661c.12-.39.15-.62.2-.84-.35.44-.17.53-.2.83"/></svg>',
  ubuntu: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#E95420" d="M17.61.455a3.41 3.41 0 0 0-3.41 3.41 3.41 3.41 0 0 0 3.41 3.41 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41zM12.92.8C8.923.777 5.137 2.941 3.148 6.451a4.5 4.5 0 0 1 .26-.007 4.92 4.92 0 0 1 2.585.737A8.316 8.316 0 0 1 12.688 3.6 4.944 4.944 0 0 1 13.723.834 11.008 11.008 0 0 0 12.92.8zm9.226 4.994a4.915 4.915 0 0 1-1.918 2.246 8.36 8.36 0 0 1-.273 8.303 4.89 4.89 0 0 1 1.632 2.54 11.156 11.156 0 0 0 .559-13.089zM3.41 7.932A3.41 3.41 0 0 0 0 11.342a3.41 3.41 0 0 0 3.41 3.409 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41zm2.027 7.866a4.908 4.908 0 0 1-2.915.358 11.1 11.1 0 0 0 7.991 6.698 11.234 11.234 0 0 0 2.422.249 4.879 4.879 0 0 1-.999-2.85 8.484 8.484 0 0 1-.836-.136 8.304 8.304 0 0 1-5.663-4.32zm11.405.928a3.41 3.41 0 0 0-3.41 3.41 3.41 3.41 0 0 0 3.41 3.41 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41z"/></svg>',
  redhat: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#EE0000" d="M16.009 13.386c1.577 0 3.86-.326 3.86-2.202a1.765 1.765 0 0 0-.04-.431l-.94-4.08c-.216-.898-.406-1.305-1.982-2.093-1.223-.625-3.888-1.658-4.676-1.658-.733 0-.947.946-1.822.946-.842 0-1.467-.706-2.255-.706-.757 0-1.25.515-1.63 1.576 0 0-1.06 2.99-1.197 3.424a.81.81 0 0 0-.028.245c0 1.162 4.577 4.974 10.71 4.974m4.101-1.435c.218 1.032.218 1.14.218 1.277 0 1.765-1.984 2.745-4.593 2.745-5.895.004-11.06-3.451-11.06-5.734a2.326 2.326 0 0 1 .19-.925C2.746 9.415 0 9.794 0 12.217c0 3.969 9.405 8.861 16.851 8.861 5.71 0 7.149-2.582 7.149-4.62 0-1.605-1.387-3.425-3.887-4.512"/></svg>',
  fedora: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#51A2DA" d="M12.001 0C5.376 0 .008 5.369.004 11.992H.002v9.287h.002A2.726 2.726 0 0 0 2.73 24h9.275c6.626-.004 11.993-5.372 11.993-11.997C23.998 5.375 18.628 0 12 0zm2.431 4.94c2.015 0 3.917 1.543 3.917 3.671 0 .197.001.395-.03.619a1.002 1.002 0 0 1-1.137.893 1.002 1.002 0 0 1-.842-1.175 2.61 2.61 0 0 0 .013-.337c0-1.207-.987-1.672-1.92-1.672-.934 0-1.775.784-1.777 1.672.016 1.027 0 2.046 0 3.07l1.732-.012c1.352-.028 1.368 2.009.016 1.998l-1.748.013c-.004.826.006.677.002 1.093 0 0 .015 1.01-.016 1.776-.209 2.25-2.124 4.046-4.424 4.046-2.438 0-4.448-1.993-4.448-4.437.073-2.515 2.078-4.492 4.603-4.469l1.409-.01v1.996l-1.409.013h-.007c-1.388.04-2.577.984-2.6 2.47a2.438 2.438 0 0 0 2.452 2.439c1.356 0 2.441-.987 2.441-2.437l-.001-7.557c0-.14.005-.252.02-.407.23-1.848 1.883-3.256 3.754-3.256z"/></svg>',
  centos: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12.076.066L8.883 3.28H3.348v5.434L0 12.01l3.349 3.298v5.39h5.374l3.285 3.236 3.285-3.236h5.43v-5.374L24 12.026l-3.232-3.252V3.321H15.31zm0 .749l2.49 2.506h-1.69v6.441l-.8.805-.81-.815V3.28H9.627zm-8.2 2.991h4.483L6.485 5.692l4.253 4.279v.654H9.94L5.674 6.423l-1.798 1.77zm5.227 0h1.635v5.415l-3.509-3.53zm4.302.043h1.687l1.83 1.842-3.517 3.539zm2.431 0h4.404v4.394l-1.83-1.842-4.241 4.267h-.764v-.69l4.261-4.287zm2.574 3.3l1.83 1.843v1.676h-5.327zm-12.735.013l3.515 3.462H3.876v-1.69zM3.348 9.454v1.697h6.377l.871.858-.782.77H3.35v1.786L.753 12.01zm17.42.068l2.488 2.503-2.533 2.55v-1.796h-6.41l-.75-.754.825-.83h6.38zm-9.502.978l.81.815.186-.188.614-.618v.686h.768l-.825.83.75.754h-.719v.808l-.842-.83-.741.73v-.707h-.7l.781-.77-.188-.186-.682-.672h.788zm-7.39 2.807h5.402l-3.603 3.55-1.798-1.772zm6.154 0h.708v.7l-4.404 4.338 1.852 1.824h-4.31v-4.342l1.798 1.77zm3.348 0h.715l4.317 4.343.186-.187 1.599-1.61v4.316h-4.366l1.853-1.825-.188-.185-4.116-4.054zm1.46 0h5.357v1.798l-1.785 1.796zm-2.83.191l.842.829v6.37h1.691l-2.532 2.495-2.533-2.495h1.79V14.23zm-1.27 1.251v5.42H8.939l-1.852-1.823zm2.64.097l3.552 3.499-1.853 1.825h-1.7z"/></svg>',
  rocky: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#10B981" d="M23.332 15.957c.433-1.239.668-2.57.668-3.957 0-6.627-5.373-12-12-12S0 5.373 0 12c0 3.28 1.315 6.251 3.447 8.417L15.62 8.245l3.005 3.005zm-2.192 3.819l-5.52-5.52L6.975 22.9c1.528.706 3.23 1.1 5.025 1.1 3.661 0 6.94-1.64 9.14-4.224z"/></svg>',
  alma: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M23.994 15.133c.079 1.061-.668 1.927-1.69 2.005a1.8 1.8 0 0 1-1.928-1.651c-.078-1.062.63-1.849 1.691-1.967 1.023-.078 1.849.59 1.927 1.613zm-12.623 4.955c-.944 0-1.73.786-1.73 1.809 0 1.14.747 1.848 1.887 1.848.904-.04 1.691-.865 1.691-1.809 0-.983-.904-1.848-1.848-1.848zm1.061-9.675c-.039-.865-.078-1.73.08-2.556.156-.944.314-1.887.904-2.674.707-.983 1.809-.944 2.399.118.314.511.432 1.062.471 1.652 0 .354.158.432.472.393.944-.157 1.888-.157 2.792.197.118.039.236.118.394 0 .314-.276.393-1.652.196-2.006-.354-.63-.904-.55-1.455-.55-.629.039-1.18-.158-1.612-.67-.393-.471-.511-1.06-.59-1.65-.04-.276-.079-.512-.315-.709-.55-.55-1.809-.432-2.477.118-2.556 2.045-2.989 5.467-1.534 8.18.04.118.118.236.275.157zm7.984 3.658c.354-.511.865-.747 1.415-.983a.973.973 0 0 0 .59-.472c.354-.669-.078-1.81-.747-2.36-2.595-2.006-5.938-1.612-8.18.433-.118.078-.157.196-.078.314.786-.236 1.612-.472 2.477-.51.905-.08 1.848-.158 2.753.235 1.14.472 1.337 1.534.472 2.36-.393.393-.905.668-1.455.825-.315.08-.354.236-.236.551.354.865.59 1.77.472 2.753-.04.157-.079.275.078.393.354.236 1.691 0 1.967-.275.511-.472.314-1.023.196-1.534-.157-.63-.078-1.219.276-1.73zm-7.197-2.045c-.118-.079-.197-.118-.315 0 .472.708.905 1.455 1.259 2.241.314.866.668 1.73.55 2.714-.118 1.18-1.1 1.69-2.123 1.101-.511-.275-.905-.669-1.22-1.14-.196-.276-.393-.276-.629-.08-.747.63-1.533 1.102-2.516 1.26-.158 0-.315 0-.394.157-.118.393.472 1.612.826 1.809.59.354 1.062 0 1.534-.276.55-.314 1.101-.432 1.73-.236.59.197.983.63 1.337 1.102.158.196.315.353.63.432.747.197 1.77-.59 2.084-1.376 1.18-3.028-.157-6.135-2.753-7.708zm-2.556 2.438c.472-.669.826-1.416.983-2.202-.157-.04-.197.04-.315.078-.904.944-1.848 1.849-3.067 2.478-.472.236-.983.433-1.534.433-.865 0-1.376-.551-1.298-1.416a2.92 2.92 0 0 1 .787-1.849c.236-.275.236-.432-.04-.668-.786-.55-1.494-1.22-1.848-2.124-.078-.275-.275-.275-.51-.157a4.293 4.293 0 0 0-.434.236c-1.022.63-1.14 1.416-.275 2.28.63.63.944 1.338.708 2.203-.118.433-.354.747-.63 1.101a.95.95 0 0 0-.235.787c.079.747.826 1.494 1.73 1.573 2.517.236 4.562-.63 5.978-2.753zm-4.68-5.152c1.376 1.18 3.067 1.455 4.837 1.377.157 0 .315 0 .354-.118.04-.197-.157-.197-.275-.236-.826-.354-1.691-.63-2.438-1.14S6.848 8.25 6.534 7.266c-.236-.747.078-1.415.825-1.651.669-.236 1.337-.236 1.967 0 .393.157.55.078.629-.354.118-.747.354-1.455.826-2.085.55-.786.55-.865-.354-1.376-.04 0-.04-.04-.079-.04-.865-.471-1.534-.196-1.848.709-.472 1.376-1.377 1.887-2.832 1.612-.196-.04-.393-.079-.472-.079-.747.118-1.18.55-1.297 1.14-.158 1.81.786 3.107 2.084 4.17zm-2.32 3.658c-.079-.944-1.023-1.652-2.045-1.534-.905.079-1.691 1.022-1.613 1.966.08.983 1.023 1.77 1.967 1.652 1.14-.079 1.73-1.18 1.69-2.084zm15.18-8.298c.943-.079 1.73-.983 1.651-1.927-.078-.983-1.022-1.77-2.005-1.691-1.023.079-1.73.983-1.652 1.966s.983 1.73 2.006 1.652zm-12.27-.826c1.062-.157 1.77-1.023 1.652-2.045C8.107.897 7.163.149 6.18.267c-1.062.118-1.691.944-1.573 2.085.118.865 1.061 1.612 1.966 1.494z"/></svg>',
  arch: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#1793D1" d="M11.39.605C10.376 3.092 9.764 4.72 8.635 7.132c.693.734 1.543 1.589 2.923 2.554-1.484-.61-2.496-1.224-3.252-1.86C6.86 10.842 4.596 15.138 0 23.395c3.612-2.085 6.412-3.37 9.021-3.862a6.61 6.61 0 01-.171-1.547l.003-.115c.058-2.315 1.261-4.095 2.687-3.973 1.426.12 2.534 2.096 2.478 4.409a6.52 6.52 0 01-.146 1.243c2.58.505 5.352 1.787 8.914 3.844-.702-1.293-1.33-2.459-1.929-3.57-.943-.73-1.926-1.682-3.933-2.713 1.38.359 2.367.772 3.137 1.234-6.09-11.334-6.582-12.84-8.67-17.74zM22.898 21.36v-.623h-.234v-.084h.562v.084h-.234v.623h.331v-.707h.142l.167.5.034.107a2.26 2.26 0 01.038-.114l.17-.493H24v.707h-.091v-.593l-.206.593h-.084l-.205-.602v.602h-.091"/></svg>',
  alpine: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#0D597F" d="M5.998 1.607L0 12l5.998 10.393h12.004L24 12 18.002 1.607H5.998zM9.965 7.12L12.66 9.9l1.598 1.595.002-.002 2.41 2.363c-.2.14-.386.252-.563.344a3.756 3.756 0 01-.496.217 2.702 2.702 0 01-.425.111c-.131.023-.25.034-.358.034-.13 0-.242-.014-.338-.034a1.317 1.317 0 01-.24-.072.95.95 0 01-.2-.113l-1.062-1.092-3.039-3.041-1.1 1.053-3.07 3.072a.974.974 0 01-.2.111 1.274 1.274 0 01-.237.073c-.096.02-.209.033-.338.033-.108 0-.227-.009-.358-.031a2.7 2.7 0 01-.425-.114 3.748 3.748 0 01-.496-.217 5.228 5.228 0 01-.563-.343l6.803-6.727zm4.72.785l4.579 4.598 1.382 1.353a5.24 5.24 0 01-.564.344 3.73 3.73 0 01-.494.217 2.697 2.697 0 01-.426.111c-.13.023-.251.034-.36.034-.129 0-.241-.014-.337-.034a1.285 1.285 0 01-.385-.146c-.033-.02-.05-.036-.053-.04l-1.232-1.218-2.111-2.111-.334.334L12.79 9.8l1.896-1.897zm-5.966 4.12v2.529a2.128 2.128 0 01-.356-.035 2.765 2.765 0 01-.422-.116 3.708 3.708 0 01-.488-.214 5.217 5.217 0 01-.555-.34l1.82-1.825Z"/></svg>',
  proxmox: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#E57000" d="M4.928 1.825c-1.09.553-1.09.64-.07 1.78 5.655 6.295 7.004 7.782 7.107 7.782.139.017 7.971-8.542 8.058-8.801.034-.07-.208-.312-.519-.536-.415-.312-.864-.433-1.712-.467-1.59-.104-2.144.242-4.115 2.455-.899 1.003-1.66 1.833-1.66 1.833-.017 0-.76-.813-1.642-1.798S8.473 2.1 8.127 1.91c-.796-.45-2.421-.484-3.2-.086zM1.297 4.367C.45 4.695 0 5.007 0 5.248c0 .121 1.331 1.678 2.94 3.459 1.625 1.78 2.939 3.268 2.939 3.302 0 .035-1.331 1.522-2.94 3.303C1.314 17.11.017 18.683.035 18.822c.086.467 1.504 1.055 2.541 1.055 1.678-.018 2.058-.312 5.603-4.202 1.78-1.954 3.233-3.614 3.233-3.666 0-.069-1.435-1.694-3.199-3.63-2.3-2.508-3.423-3.632-3.96-3.874-.812-.398-2.126-.467-2.956-.138zm18.467.12c-.502.26-1.764 1.505-3.943 3.891-1.763 1.937-3.199 3.562-3.199 3.631 0 .07 1.453 1.712 3.234 3.666 3.544 3.89 3.925 4.184 5.602 4.202 1.038 0 2.455-.588 2.542-1.055.017-.156-1.28-1.712-2.905-3.493-1.608-1.78-2.94-3.285-2.94-3.32 0-.034 1.332-1.539 2.94-3.32C22.72 6.91 24.017 5.352 24 5.214c-.087-.45-1.366-.968-2.473-1.038-.795-.034-1.21.035-1.763.312zM7.954 16.973c-2.144 2.369-3.908 4.374-3.943 4.46-.034.07.208.312.52.537.414.311.864.432 1.711.467 1.574.103 2.161-.26 4.15-2.508.864-.968 1.608-1.78 1.625-1.78s.761.812 1.643 1.798c2.023 2.248 2.559 2.576 4.132 2.49.848-.035 1.297-.156 1.712-.467.311-.225.553-.467.519-.536-.087-.26-7.92-8.819-8.058-8.801-.069 0-1.867 1.954-4.011 4.34z"/></svg>',
  kali: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#557C94" d="M12.778 5.943s-1.97-.13-5.327.92c-3.42 1.07-5.36 2.587-5.36 2.587s5.098-2.847 10.852-3.008zm7.351 3.095l.257-.017s-1.468-1.78-4.278-2.648c1.58.642 2.954 1.493 4.021 2.665zm.42.74c.039-.068.166.217.263.337.004.024.01.039-.045.027-.005-.025-.013-.032-.013-.032s-.135-.08-.177-.137c-.041-.057-.049-.157-.028-.195zm3.448 8.479s.312-3.578-5.31-4.403a18.277 18.277 0 0 0-2.524-.187c-4.506.06-4.67-5.197-1.275-5.462 1.407-.116 3.087.643 4.73 1.408-.007.204.002.385.136.552.134.168.648.35.813.445.164.094.691.43 1.014.85.07-.131.654-.512.654-.512s-.14.003-.465-.119c-.326-.122-.713-.49-.722-.511-.01-.022-.015-.055.06-.07.059-.049-.072-.207-.13-.265-.058-.058-.445-.716-.454-.73-.009-.016-.012-.031-.04-.05-.085-.027-.46.04-.46.04s-.575-.283-.774-.893c.003.107-.099.224 0 .469-.3-.127-.558-.344-.762-.88-.12.305 0 .499 0 .499s-.707-.198-.82-.85c-.124.293 0 .469 0 .469s-1.153-.602-3.069-.61c-1.283-.118-1.55-2.374-1.43-2.754 0 0-1.85-.975-5.493-1.406-3.642-.43-6.628-.065-6.628-.065s6.45-.31 11.617 1.783c.176.785.704 2.094.989 2.723-.815.563-1.733 1.092-1.876 2.97-.143 1.878 1.472 3.53 3.474 3.58 1.9.102 3.214.116 4.806.942 1.52.84 2.766 3.4 2.89 5.703.132-1.709-.509-5.383-3.5-6.498 4.181.732 4.549 3.832 4.549 3.832zM12.68 5.663l-.15-.485s-2.484-.441-5.822-.204C3.37 5.211 0 6.38 0 6.38s6.896-1.735 12.68-.717Z"/></svg>',
  mint: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#86BE43" d="M5.438 5.906v8.438c0 2.06 1.69 3.75 3.75 3.75h5.625c2.06 0 3.75-1.69 3.75-3.75V9.656a2.827 2.827 0 0 0-2.813-2.812 2.8 2.8 0 0 0-1.875.737A2.8 2.8 0 0 0 12 6.844a2.827 2.827 0 0 0-2.812 2.812v4.688h1.875V9.656c0-.529.408-.937.937-.937s.938.408.938.937v4.688h1.875V9.656c0-.529.408-.937.937-.937s.938.408.938.937v4.688a1.86 1.86 0 0 1-1.875 1.875H9.188a1.86 1.86 0 0 1-1.875-1.875V5.906ZM12 0C5.384 0 0 5.384 0 12s5.384 12 12 12 12-5.384 12-12S18.616 0 12 0m0 1.875A10.11 10.11 0 0 1 22.125 12 10.11 10.11 0 0 1 12 22.125 10.11 10.11 0 0 1 1.875 12 10.11 10.11 0 0 1 12 1.875"/></svg>',
  opensuse: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#73BA25" d="M10.724 0a12 12 0 0 0-9.448 4.623c1.464.391 2.5.727 2.81.832.005-.19.037-1.893.037-1.893s.004-.04.025-.06c.026-.026.065-.018.065-.018.385.056 8.602 1.274 12.066 3.292.427.25.638.517.902.786.958.99 2.223 5.108 2.359 5.957.005.033-.036.07-.054.083a5.177 5.177 0 0 1-.313.228c-.82.55-2.708 1.872-5.13 1.656-2.176-.193-5.018-1.44-8.445-3.699.336.79.668 1.58 1 2.371.497.258 5.287 2.7 7.651 2.651 1.904-.04 3.941-.968 4.756-1.458 0 0 .179-.108.257-.048.085.066.061.167.041.27-.05.234-.164.66-.242.863l-.065.165c-.093.25-.183.482-.356.625-.48.436-1.246.784-2.446 1.305-1.855.812-4.865 1.328-7.66 1.31-1.001-.022-1.968-.133-2.817-.232-1.743-.197-3.161-.357-4.026.269A12 12 0 0 0 10.724 24a12 12 0 0 0 12-12 12 12 0 0 0-12-12zM13.4 6.963a3.503 3.503 0 0 0-2.521.942 3.498 3.498 0 0 0-1.114 2.449 3.528 3.528 0 0 0 3.39 3.64 3.48 3.48 0 0 0 2.524-.946 3.504 3.504 0 0 0 1.114-2.446 3.527 3.527 0 0 0-3.393-3.64zm-.03 1.035a2.458 2.458 0 0 1 2.368 2.539 2.43 2.43 0 0 1-.774 1.706 2.456 2.456 0 0 1-1.762.659 2.461 2.461 0 0 1-2.364-2.542c.02-.655.3-1.26.777-1.707a2.419 2.419 0 0 1 1.756-.655zm.402 1.23c-.602 0-1.087.325-1.087.727 0 .4.485.725 1.087.725.6 0 1.088-.326 1.088-.725 0-.402-.487-.726-1.088-.726Z"/></svg>',
  suse: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M22.6691 10.2274a.392.392 0 0 1-.4295 0c-.2108-.14-.2311-.4327-.061-.602a.3828.3828 0 0 1 .5515-.0002c.1698.1695.1492.4622-.061.6022m-1.12.8819c-.5308-.1245-.952-.5457-1.0768-1.0762-.2444-1.0419.6924-1.9787 1.7346-1.7346.5305.1241.952.545 1.0768 1.0759.2451 1.0425-.692 1.98-1.7346 1.7349zm-5.0114 4.374c.0394.1174.0898.2723.2057.3346.0064.0035.012.0066.019.0085.2128.0775.7598.0645.7598.0645h1.006c.086.0013.8419-.001.8228-.0854-.091-.4041-.5584-.4765-.9142-.688-.328-.1955-.6391-.417-.78-.7984-.0737-.1968-.0302-.6508.0965-.8162.0923-.1196.2285-.199.3749-.231.1622-.0347.3305-.0048.4927.0117.2.0203.3974.0565.5968.0813a7.4343 7.4343 0 0 0 1.1613.0596c.6403-.0177 1.2822-.1197 1.8892-.3266.4238-.1423.8413-.3346 1.2016-.6023.4095-.3044.3019-.2758-.1134-.2333-.4971.0508-.9987.0584-1.4974.0289-.4654-.027-.9245-.082-1.3454-.2981-.3314-.1711-.6162-.3425-.879-.6076-.0394-.04-.0639-.1568.0082-.2314.0698-.0724.2178-.0305.2632.0082.4584.3832 1.1422.6987 1.8501.733.3829.019.7553.026 1.1384.0095.1915-.0088.4804-.0076.6724-.0095.099-.0012.3692.0273.4197-.0778.0152-.0304.014-.0657.0127-.1-.0562-1.532-.1695-3.26-1.7727-3.9923-1.1962-.547-2.9895-1.3943-3.747-1.7458-.1755-.0834-.381.0486-.381.2442 0 .5117.026 1.247.0264 1.9162-.3629-.3696-.974-.6029-1.4397-.8169-.5289-.2425-1.0749-.4482-1.6305-.6212-1.1184-.3464-2.2758-.5597-3.44-.6753-1.3203-.1317-2.6628-.0685-3.9628.2-2.141.4438-4.2454 1.4734-5.8429 2.979-.9806.924-1.7501 2.2373-1.8021 3.5703-.0743 1.8867.4543 2.8997 1.4257 3.9439 1.5492 1.664 4.8835 1.8971 6.234-.0762.6076-.8883.7394-2.093.2984-3.075-.441-.9812-1.4546-1.6904-2.5292-1.7266-.834-.0276-1.7225.3965-2.0422 1.1676-.2438.5889-.1051 1.3165.339 1.7736.173.1785.4073.3245.6632.2673.1508-.0336.2768-.147.2997-.3.0336-.2257-.1638-.372-.2854-.5453-.2194-.3127-.175-.7823.0997-1.048.2317-.2244.5749-.2908.8974-.2898.3003.0006.6073.0543.8664.2057.3641.2143.606.6067.6898 1.0213.2499 1.239-.7574 2.2457-2.1232 2.3247-.6987.0413-1.4098-.1422-1.9552-.5813-1.3813-1.111-1.7197-3.3822-.141-4.5946 1.4988-1.1508 3.3908-.8542 4.5064-.2561.8927.4784 1.558 1.2612 2.0622 2.1266.253.4353.4686.8902.6686 1.352.1924.4442.3724.8918.7575 1.2172.2549.2159.5695.2083.9034.2083h1.9064c.259 0 .1959-.1727.0841-.287-.2527-.2584-.6158-.3168-.952-.4092-.7686-.2114-.6902-1.2289-.4775-1.2289.687 0 .7086.0206 1.3105.013.8685-.012 1.1314-.0625 1.8108.1886.3631.1346.712.4895.9397.814.119.171.218.3365.2736.5019Z"/></svg>',
  gentoo: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#54487A" d="M9.94 0a7.31 7.31 0 00-1.26.116c-4.344.795-7.4 4.555-7.661 7.031-.126 1.215.53 2.125.89 2.526.977 1.085 2.924 1.914 4.175 2.601-1.81 1.543-2.64 2.296-3.457 3.154C1.403 16.712.543 18.125.54 19.138c0 .325-.053 1.365.371 2.187.16.309.613 1.338 1.98 2.109.874.494 2.119.675 3.337.501 3.772-.538 8.823-3.737 12.427-6.716 2.297-1.9 3.977-3.739 4.462-4.644.39-.731.434-2.043.207-2.866-.645-2.337-5.887-7.125-10.172-9.051A7.824 7.824 0 009.94 0zm-.008.068a7.4 7.4 0 013.344.755c3.46 1.7 9.308 6.482 9.739 8.886.534 2.972-9.931 11.017-16.297 12.272-2.47.485-4.576.618-5.537-1.99-.832-2.262.783-3.916 3.16-6.09a92.546 92.546 0 012.96-2.576c.065-.069-5.706-2.059-5.89-4.343C1.221 4.634 4.938.3 9.697.076c.08-.004.157-.007.235-.008zm-.112.52a5.647 5.647 0 00-.506.032c-2.337.245-2.785.547-4.903 2.149-.71.537-2.016 1.844-2.35 3.393-.128.59.024 1.1.448 1.458 1.36 1.144 3.639 2.072 5.509 2.97.547.263.185.74-.698 1.505-2.227 1.928-5.24 4.276-5.45 6.066-.099.842.19 1.988 1.213 2.574 1.195.685 3.676.238 5.333-.379 2.422-.902 5.602-2.892 8.127-4.848 2.625-2.034 5.067-4.617 5.188-5.038.148-.517.133-.996-.154-1.546-.448-.862-1.049-1.503-1.694-2.22-1.732-1.825-3.563-3.43-5.754-4.658C12.694 1.242 11.417.564 9.82.588zm1.075 3.623c.546 0 1.176.173 1.853.5 1.688.817 3.422 2.961-.015 4.195-.935.336-3.9-.824-3.81-2.407.09-1.57.854-2.289 1.972-2.288zm.285 1.367c-.317-.002-.575.079-.694.263-.557.861-.303 1.472.212 1.862.192-.457 2.156.043 2.148.472a.32.32 0 00.055-.032c1.704-1.282-.472-2.557-1.72-2.565z"/></svg>',
  nixos: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#5277C3" d="M7.352 1.592l-1.364.002L5.32 2.75l1.557 2.713-3.137-.008-1.32 2.34H14.11l-1.353-2.332-3.192-.006-2.214-3.865zm6.175 0l-2.687.025 5.846 10.127 1.341-2.34-1.59-2.765 2.24-3.85-.683-1.182h-1.336l-1.57 2.705-1.56-2.72zm6.887 4.195l-5.846 10.125 2.696-.008 1.601-2.76 4.453.016.682-1.183-.666-1.157-3.13-.008L21.778 8.1l-1.365-2.313zM9.432 8.086l-2.696.008-1.601 2.76-4.453-.016L0 12.02l.666 1.157 3.13.008-1.575 2.71 1.365 2.315L9.432 8.086zM7.33 12.25l-.006.01-.002-.004-1.342 2.34 1.59 2.765-2.24 3.85.684 1.182H7.35l.004-.006h.001l1.567-2.698 1.558 2.72 2.688-.026-.004-.006h.01L7.33 12.25zm2.55 3.93l1.354 2.332 3.192.006 2.215 3.865 1.363-.002.668-1.156-1.557-2.713 3.137.008 1.32-2.34H9.881Z"/></svg>',
  manjaro: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#35BFA4" d="M2.182 0A2.177 2.177 0 0 0 0 2.182v19.636C0 23.027.973 24 2.182 24h4.363V6.545h8.728V0Zm15.273 0v24h4.363A2.177 2.177 0 0 0 24 21.818V2.182A2.177 2.177 0 0 0 21.818 0ZM8.727 8.727V24h6.546V8.727Z"/></svg>',
  popos: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#48B9C7" d="M12 0C5.372 0 0 5.373 0 12c0 6.628 5.372 12 12 12 6.627 0 12-5.372 12-12 0-6.627-5.373-12-12-12ZM9.64 2.918c1.091-.026 1.548.229 2.182.635a4.459 4.459 0 0 1 1.902 2.764c.254 1.141.178 2.029-.127 2.664v.05c-.609 1.294-1.622 2.335-3.043 2.842l1.217 3.172c.228.583.432 1.192.254 1.75-.177.558-.989.736-1.572.127-1.116-1.192-4.871-8.702-5.15-9.26-.279-.558-.584-1.016-.584-1.574.026-.837 1.318-1.7 1.953-2.131.634-.431 1.877-1.014 2.968-1.039Zm-.996 2.311c-.789.022-.358 1.669-.197 2.129.178.507.661 1.572 1.193 2.105.127.127.254.229.407.254.152.027.457-.127.584-.33a.932.932 0 0 0 .15-.559 3.232 3.232 0 0 0-.049-1.216c-.228-.787-.711-1.548-1.346-2.055-.127-.102-.279-.229-.457-.279a.901.901 0 0 0-.285-.049Zm8.414 2.027a2.283 2.283 0 0 1 1.588.636c.305.279.33.582.229.963-.102.38-.457 1.194-.736 1.777l-.709 1.344c-1.37 2.435-1.649 2.689-2.03 2.537-.456-.178-.304-2.614.127-5.582.127-.812.329-1.217.557-1.42.171-.152.6-.248.975-.254l-.001-.001Zm-1.859 8.332c.554.011.789.7.656 1.232a.861.861 0 0 1-.379.559c-.203.127-.685.127-.965-.102-.278-.228-.33-.609-.254-.914.076-.304.331-.635.686-.736a.757.757 0 0 1 .256-.039Zm-8.604 2.805h10.809c.52 0 .938.419.938.939v.074c0 .52-.418.94-.938.94H6.595a.936.936 0 0 1-.937-.94v-.074c0-.52.417-.939.937-.939Z"/></svg>',
  elementary: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#64BAFF" d="M12 0a12 12 0 1 0 0 24 12 12 0 0 0 0-24zm0 1a11 11 0 0 1 10.59 8.01 19.09 19.09 0 0 1-4.66 6.08c-.94.81-1.96 1.53-3.08 2.04-1.13.5-2.37.8-3.6.72a6.23 6.23 0 0 1-2.66-.76 20.02 20.02 0 0 0 5.68-4.58 9.97 9.97 0 0 0 2.31-4.17c.18-.79.2-1.6.04-2.4a4.42 4.42 0 0 0-1.08-2.11 4.33 4.33 0 0 0-2-1.19 5.25 5.25 0 0 0-2.33-.08A7.8 7.8 0 0 0 7.2 4.85a9.77 9.77 0 0 0-2.94 7.49 7.88 7.88 0 0 0 1.95 4.59 18 18 0 0 1-3.56.85A11 11 0 0 1 12 1zm.07 2.22c.77 0 1.55.24 2.17.7.55.42.97 1.02 1.2 1.68.23.65.3 1.37.21 2.06a7.85 7.85 0 0 1-1.7 3.76 16.22 16.22 0 0 1-6.37 4.96c-.48-.42-.9-.92-1.2-1.48a6.61 6.61 0 0 1-.75-3.87c.12-1.32.58-2.6 1.2-3.79a7.92 7.92 0 0 1 3.02-3.42c.68-.37 1.45-.6 2.22-.6zm10.83 7.3A11 11 0 0 1 3.52 19a19.8 19.8 0 0 0 3.63-1.2c.51.4 1.08.71 1.67.94a8 8 0 0 0 5.44-.04 13.3 13.3 0 0 0 4.64-2.95 20 20 0 0 0 4-5.22z"/></svg>',
  zorin: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#15A6F0" d="M4 18.944L5.995 22.4h12.01L20 18.944H4zM24 12l-2.013 3.488H9.216l12.771-6.976L24 12zM0 12l2.013-3.488h12.771L2.013 15.488 0 12zm4-6.944L5.995 1.6h12.01L20 5.056H4z"/></svg>',
  truenas: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#0095D5" d="M24 10.049v5.114l-10.949 6.324v-5.114L24 10.049zm-24 0v5.114l10.956 6.324v-5.114L0 10.049zm12.004-.605l-4.433 2.559 4.433 2.559 4.429-2.559-4.429-2.559zm10.952-1.207l-9.905-5.723v5.118l5.473 3.164 4.432-2.559zm-12-.605V2.513L1.044 8.236l4.432 2.555 5.48-3.159z"/></svg>',
  homeassistant: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#18BCF2" d="M22.939 10.627 13.061.749a1.505 1.505 0 0 0-2.121 0l-9.879 9.878C.478 11.21 0 12.363 0 13.187v9c0 .826.675 1.5 1.5 1.5h9.227l-4.063-4.062a2.034 2.034 0 0 1-.664.113c-1.13 0-2.05-.92-2.05-2.05s.92-2.05 2.05-2.05 2.05.92 2.05 2.05c0 .233-.041.456-.113.665l3.163 3.163V9.928a2.05 2.05 0 0 1-1.15-1.84c0-1.13.92-2.05 2.05-2.05s2.05.92 2.05 2.05a2.05 2.05 0 0 1-1.15 1.84v8.127l3.146-3.146A2.051 2.051 0 0 1 18 12.239c1.13 0 2.05.92 2.05 2.05s-.92 2.05-2.05 2.05c-.25 0-.488-.047-.709-.13L12.9 20.602v3.088h9.6c.825 0 1.5-.675 1.5-1.5v-9c0-.825-.477-1.977-1.061-2.561z"/></svg>',
  linux: '<svg viewBox="2.5 4 19 19" aria-hidden="true"><ellipse cx="12" cy="13.2" rx="6" ry="8.2" fill="#232323" stroke="#8b8b8b" stroke-width=".5"/><ellipse cx="12" cy="15.4" rx="3.9" ry="5.4" fill="#f4f4f4"/><circle cx="10.3" cy="8" r="1.35" fill="#fff"/><circle cx="13.7" cy="8" r="1.35" fill="#fff"/><circle cx="10.5" cy="8.3" r=".6" fill="#111"/><circle cx="13.5" cy="8.3" r=".6" fill="#111"/><path d="M10.3 10.1c1-.6 2.4-.6 3.4 0-.5 1-1.2 1.5-1.7 1.5s-1.2-.5-1.7-1.5z" fill="#f6b40e"/><ellipse cx="8.5" cy="21.3" rx="2.7" ry="1.25" fill="#f6b40e"/><ellipse cx="15.5" cy="21.3" rx="2.7" ry="1.25" fill="#f6b40e"/></svg>',
};
const OS_PATTERNS = [
  [/^(macos|mac os|os x|darwin|ios|ipados|apple)\b/i, "apple"],
  [/^(raspbian|raspberry pi os|raspberry pi|raspios)\b/i, "raspberrypi"],
  [/^(microsoft )?windows\b/i, "windows"],
  [/^debian\b/i, "debian"],
  [/^(k|x|l)?ubuntu\b/i, "ubuntu"],
  [/^(red hat|rhel)\b/i, "redhat"],
  [/^fedora\b/i, "fedora"],
  [/^centos\b/i, "centos"],
  [/^rocky\b/i, "rocky"],
  [/^alma ?linux\b/i, "alma"],
  [/^arch( linux)?\b/i, "arch"],
  [/^alpine\b/i, "alpine"],
  [/^proxmox\b/i, "proxmox"],
  [/^kali\b/i, "kali"],
  [/^(linux mint|mint)\b/i, "mint"],
  [/^opensuse\b/i, "opensuse"],
  [/^(suse|sles)\b/i, "suse"],
  [/^gentoo\b/i, "gentoo"],
  [/^nixos\b/i, "nixos"],
  [/^manjaro\b/i, "manjaro"],
  [/^pop!?_?os\b/i, "popos"],
  [/^elementary\b/i, "elementary"],
  [/^zorin\b/i, "zorin"],
  [/^truenas\b/i, "truenas"],
  [/^(home assistant|haos)\b/i, "homeassistant"],
  [/^(linux|ubuntu|debian|fedora|centos|red hat|rhel|rocky|alma|arch|manjaro|opensuse|suse|sles|alpine|amazon linux|kali|linux mint|mint|pop!?_os|proxmox|oracle linux|gentoo|nixos|elementary|zorin|truenas|home assistant)\b/i, "linux"],
];
// The name has to end there or be followed by a space, digit or bracket:
// "Debian 13.7" and "Linux" are systems, but "linux-base-rpi-2712" is a
// package that merely starts with an OS's name.
function osLogoKind(text) {
  for (const [re, kind] of OS_PATTERNS) {
    const m = re.exec(text);
    if (m && (m[0].length === text.length || /[\s\d(]/.test(text[m[0].length]))) return kind;
  }
  return "";
}
function osLogo(osOrText) {
  const kind = OS_LOGOS[osOrText] ? osOrText : osLogoKind(String(osOrText || ""));
  return kind ? `<span class="os-logo os-${/* safe-html: a key of OS_LOGOS */ kind}">${/* safe-html: fixed SVG from OS_LOGOS */ OS_LOGOS[kind]}</span>` : "";
}

// decorateIcons adds the icons to whatever the page has drawn: headings,
// tiles and OS names. Pages build most of their content after load, so a
// mutation observer runs it again (at most once a frame); everything it
// touches is marked and never decorated twice.
function isOsColumn(cell) {
  let head = "";
  if (cell.tagName === "DD") {
    const dt = cell.previousElementSibling; head = dt && dt.tagName === "DT" ? dt.textContent : "";
    if (!head && cell.parentElement) { const lbl = cell.parentElement.querySelector("dt, .k, label"); head = lbl ? lbl.textContent : ""; }
  } else {
    const table = cell.closest("table"), row = table && table.tHead && table.tHead.rows[0];
    head = (row && row.cells[cell.cellIndex] && row.cells[cell.cellIndex].textContent) || cell.dataset.label || "";
  }
  return /^\s*(os\b|platform|operating system|system\b)/i.test(head);
}

// --- short IDs -----------------------------------------------------------
//
// Endpoints, deployments and packages carry a short number (Tanium-style)
// beside their text ID. Wherever a text ID would be read on screen it is
// shown as its number, with the full ID kept as the tooltip. Links keep the
// text ID; the server takes either.
let idNums = null;
const ID_KINDS = { agt: "Endpoint", run: "Deployment", sw: "Package", rvl: "Rule" };
const LONG_ID = /^(agt|run|sw|rvl)-[0-9a-f]{12,}$/;
function loadIdNums() {
  try {
    const c = JSON.parse(sessionStorage.getItem("mustra-idnums") || "null");
    if (c && Date.now() - c.at < 30000) { idNums = c.ids; return; }
  } catch (e) {}
  fetch("/api/idnums").then(r => r.ok ? r.json() : null).then(d => {
    if (!d) return;
    idNums = d.ids || {};
    try { sessionStorage.setItem("mustra-idnums", JSON.stringify({ at: Date.now(), ids: idNums })); } catch (e) {}
    if (document.body) decorateIcons(document);
  }).catch(() => {});
}
// shortId is how a text ID reads: "Endpoint 17", or bare "17" where the
// column or label already says it is an ID.
function shortId(id, bare) {
  const n = idNums && idNums[id];
  if (!n) return "";
  return bare ? String(n) : `${ID_KINDS[id.split("-")[0]] || "#"} ${n}`;
}
function swapLongIds(root) {
  if (!idNums) return;
  const walker = document.createTreeWalker(root === document ? document.body : root, NodeFilter.SHOW_TEXT);
  const hits = [];
  let node;
  while ((node = walker.nextNode())) {
    const t = node.textContent.trim();
    if (t.length > 11 && LONG_ID.test(t) && idNums[t]) hits.push([node, t]);
  }
  for (const [n, id] of hits) {
    const el = n.parentElement;
    if (!el || el.closest("input, textarea, script, style, code.keep-id")) continue;
    let label = "";
    const cell = el.closest("td, dd");
    if (cell && cell.tagName === "TD") {
      const table = cell.closest("table"), row = table && table.tHead && table.tHead.rows[0];
      label = (row && row.cells[cell.cellIndex] && row.cells[cell.cellIndex].textContent) || "";
    } else if (cell) {
      const dt = cell.previousElementSibling; label = dt ? dt.textContent : "";
    } else {
      const prev = el.previousElementSibling; label = prev ? prev.textContent : "";
    }
    n.textContent = n.textContent.replace(id, shortId(id, el.classList.contains("id-bare") || /\bid\b/i.test(label)));
    if (!el.title) el.title = id;
  }
}

function decorateIcons(root) {
  root = root || document;
  swapLongIds(root);
  root.querySelectorAll(".panel-header > h2:not([data-deco]), .chart-title:not([data-deco]), .dash-group-header > h2:not([data-deco]), .mini-chart-title:not([data-deco]), .pnl-title:not([data-deco])").forEach(h => {
    h.dataset.deco = "1";
    addSectionHelp(h);
    const name = topicIcon(h.textContent);
    if (!name || h.querySelector(".ic")) return;
    h.insertAdjacentHTML("afterbegin", `<span class="hd-ic"${sx(`--hue:${iconHue(name)}`)}>${icon(name)}</span>`);
  });
  root.querySelectorAll(".stat-tile:not([data-deco]), .env-card:not([data-deco])").forEach(t => {
    t.dataset.deco = "1";
    const label = (t.querySelector(".stat-tile-label, .k") || {}).textContent || "";
    const name = topicIcon(label);
    if (!name || t.classList.contains("wide")) return;
    t.classList.add("has-tile-ic");
    t.insertAdjacentHTML("beforeend", `<span class="tile-ic ic-${escapeHtml(name)}"${sx(`--hue:${iconHue(name)}`)}>${icon(name)}</span>`);
  });
  // Dashboard number panels have room to spare: a big icon beside the number.
  root.querySelectorAll(".pnl:not(.compact) .pnl-body > .hero:not([data-deco])").forEach(h => {
    h.dataset.deco = "1";
    const title = (h.closest(".pnl").querySelector(".pnl-title") || {}).textContent || "";
    const name = topicIcon(title);
    if (!name) return;
    h.parentElement.classList.add("has-hero-ic");
    // One icon per panel: the big one replaces the title's.
    const small = h.closest(".pnl").querySelector(".pnl-title .hd-ic");
    if (small) small.remove();
    h.insertAdjacentHTML("afterend", `<span class="hero-ic ic-${escapeHtml(name)}"${sx(`--hue:${iconHue(name)}`)}>${icon(name)}</span>`);
  });
  // Chart legends: the label follows the colour swatch.
  root.querySelectorAll(".legend-item:not([data-os])").forEach(el => {
    el.dataset.os = "1";
    const swatch = el.querySelector("i");
    const text = swatch && swatch.nextSibling;
    if (!text || text.nodeType !== Node.TEXT_NODE) return;
    const logo = osLogo(text.textContent.trim());
    if (logo) swatch.insertAdjacentHTML("afterend", logo);
  });
  root.querySelectorAll("td:not([data-os]), .hbar-label:not([data-os]), .mini-bar-label:not([data-os]), .env-legend-item .lbl:not([data-os]), dd:not([data-os]), .os-pill:not([data-os]), td > span:only-child:not([data-os])").forEach(el => {
    el.dataset.os = "1";
    const first = el.firstChild;
    if (!first || first.nodeType !== Node.TEXT_NODE) return;
    const text = first.textContent.trim();
    if (!text || text.length > 80) return;
    const logo = osLogo(text);
    if (!logo) return;
    // In tables and detail lists only a column (or term) that is about the
    // system gets one: "macOS Tahoe 26.7.1" under Patch is an update, not
    // an operating system.
    if ((el.tagName === "TD" || el.tagName === "DD") && !isOsColumn(el)) return;
    // An OS alone in a table cell becomes the OS pill, the same one the
    // Patches tables draw, so every list shows systems alike.
    if (el.tagName === "TD" || el.tagName === "DD") {
      const pill = document.createElement("span");
      pill.className = "os-pill";
      pill.dataset.os = "1";
      pill.title = text;
      pill.insertAdjacentHTML("afterbegin", logo);
      // Raw values ("darwin", "haos") read as their names, like the pills
      // pages draw themselves; the raw value stays in the title for rules.
      const key = text.toLowerCase();
      pill.append(document.createTextNode(PLATFORM_LABELS[key] || (key === "linux" ? "Linux" : text)));
      first.replaceWith(pill);
      if (pill.nextSibling) pill.after(document.createTextNode(" "));
      return;
    }
    el.insertAdjacentHTML("afterbegin", logo);
  });
}
(function watchForIcons() {
  let queued = false;
  const run = () => { queued = false; decorateIcons(document); };
  const queue = () => { if (!queued) { queued = true; requestAnimationFrame(run); } };
  const start = () => { run(); new MutationObserver(queue).observe(document.body, { childList: true, subtree: true }); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();

// --- section help ------------------------------------------------------
//
// A "?" beside every heading: hover (or tap) for what the area is for.
// The text is, in order: a description written for that heading
// (SECTION_HELP), the first sentence of the explanation the panel already
// carries, or the description of the module section it sits in. A
// heading with none of those gets no "?" rather than an empty one.

function sectionHelpText(h) {
  const title = h.textContent.replace(/\s+/g, " ").trim();
  if (SECTION_HELP[title]) { h.dataset.helpSrc = "written"; return SECTION_HELP[title]; }
  const box = h.closest(".panel, .chart-card, .mini-chart-card, .pnl, .dash-group");
  if (box) {
    const hint = box.querySelector(":scope > p.hint, :scope > p, :scope > .panel-header + p, :scope > .chart-sub, :scope > details.hint");
    const text = hint && hint.textContent.replace(/\s+/g, " ").replace(/^How [a-z ]+ work\s*/i, "").trim();
    if (text && text.length > 12) {
      h.dataset.helpSrc = "hint";
      const first = text.match(/^.{20,260}?[.!?](\s|$)/);
      return first ? first[0].trim() : (text.length > 260 ? text.slice(0, 257) + "…" : text);
    }
  }
  const section = h.closest(".module-section");
  if (section) {
    const hash = section.id.replace(/^section-/, "");
    for (const c of NAV_TREE) for (const sub of (c.sub || [])) {
      if (sub.hash === hash && (!sub.href || sub.href === location.pathname) && sub.desc) { h.dataset.helpSrc = "section"; return sub.desc; }
    }
  }
  return "";
}

function addSectionHelp(h) {
  if (h.querySelector(".help-q")) return;
  const text = sectionHelpText(h);
  if (!text) return;
  const b = document.createElement("button");
  b.type = "button";
  b.className = "help-q";
  b.textContent = "?";
  b.dataset.help = text;
  b.setAttribute("aria-label", "About " + h.textContent.trim() + ": " + text);
  h.append(b);
}

// One floating bubble, shared: shown on hover or focus, toggled by a tap.
(function wireHelpBubbles() {
  // shownAt: a tap fires mouseover (which shows) and then click (which
  // toggles); a click right after showing must not hide it again.
  let bubble = null, owner = null, shownAt = 0;
  const hide = () => { if (bubble) bubble.hidden = true; owner = null; };
  const show = (btn) => {
    if (!bubble) {
      bubble = document.createElement("div");
      bubble.className = "help-bubble";
      bubble.setAttribute("role", "tooltip");
      document.body.append(bubble);
    }
    if (owner !== btn || bubble.hidden) shownAt = Date.now();
    owner = btn;
    bubble.textContent = btn.dataset.help;
    bubble.hidden = false;
    const r = btn.getBoundingClientRect(), bw = Math.min(320, window.innerWidth - 16);
    bubble.style.maxWidth = bw + "px";
    const left = Math.max(8, Math.min(r.left + r.width / 2 - bw / 2, window.innerWidth - bw - 8));
    bubble.style.left = left + "px";
    const below = r.bottom + 8;
    bubble.style.top = below + "px";
    const bh = bubble.offsetHeight;
    if (below + bh > window.innerHeight - 8) bubble.style.top = Math.max(8, r.top - bh - 8) + "px";
  };
  document.addEventListener("mouseover", e => { const b = e.target.closest && e.target.closest(".help-q"); if (b) show(b); });
  document.addEventListener("mouseout", e => { const b = e.target.closest && e.target.closest(".help-q"); if (b && !b.contains(e.relatedTarget)) hide(); });
  document.addEventListener("focusin", e => { if (e.target.classList && e.target.classList.contains("help-q")) show(e.target); });
  document.addEventListener("focusout", e => { if (e.target.classList && e.target.classList.contains("help-q")) hide(); });
  document.addEventListener("click", e => {
    const b = e.target.closest && e.target.closest(".help-q");
    if (b) { e.preventDefault(); e.stopPropagation(); owner === b && bubble && !bubble.hidden && Date.now() - shownAt > 500 ? hide() : show(b); return; }
    hide();
  }, true);
  window.addEventListener("scroll", hide, true);
  document.addEventListener("keydown", e => { if (e.key === "Escape") hide(); });
})();

// Descriptions written for headings whose panels say nothing about
// themselves. Keyed by the heading's text exactly as shown.
const SECTION_HELP = {
  "Installing": "Each step of issuing and installing the certificate as the server works through it. If a step fails, nothing on the endpoint is changed.",
  "Environment Status": "The fleet right now: endpoints online, the total, what they run, what's offline and how many sites. Click a number to list the endpoints behind it.",
  "Query": "Ask the fleet a question in plain terms (\"get os from all machines\") or search for endpoints. Answers come from the inventory mustra already holds, so offline endpoints are included.",
  "Modules": "Every area of mustra. Choose which ones show here with the Choose button.",
  "Fleet overview": "Dashboard panels about the whole fleet, filtered by computer group and timeframe. Click a chart to drill into the endpoints behind it.",
  "Managed endpoints": "How many endpoints have an agent reporting to this console, online or not.",
  "Online now": "Endpoints whose agent has checked in recently enough to count as connected.",
  "Endpoints over time": "How the number of reporting endpoints has changed over the chosen timeframe.",
  "By operating system": "The fleet split by operating system. Click a slice to list those endpoints.",
  "By agent version": "Which agent versions the fleet is running. More than one bar usually means an update is still rolling out.",
  "Platform by site": "How many endpoints are at each site, by platform.",
  "Patch Status": "Missing operating system updates across the fleet, from each endpoint's latest patch scan.",
  "Missing Patches by OS": "How many updates are pending, grouped by operating system.",
  "Endpoint Patch Compliance": "Endpoints with nothing pending against those that still need patching.",
  "Top Missing Patches": "The updates missing from the most endpoints: the ones worth deploying first.",
  "Risk & Compliance": "Known vulnerabilities (CVEs) matched against installed packages, so you can see what is exposed and where.",
  "Vulnerabilities by Severity": "Matched vulnerabilities counted by severity, critical first.",
  "Most Vulnerable Packages": "Installed packages carrying the most known vulnerabilities across the fleet. Updating these removes the most risk.",
  "Devices by Vulnerability Count": "The endpoints with the most matched vulnerabilities.",
  "Endpoints": "Every endpoint reporting to this console. Filter or sort any column, and click a hostname to open its page.",
  "Action groups": "Upper limits on which endpoints a module may act on, whoever is asking. A module outside its action group cannot touch an endpoint.",
  "New dashboard": "Start a dashboard: name it, then add panels from saved queries or module data.",
  "Agent version rollout": "How much of the fleet is on the version this server hands out, and how much is still behind.",
  "Credential vault": "Saved SSH passwords and keys, encrypted, used to push the agent onto machines found by a network scan.",
  "Failures by endpoint": "Which endpoints fail the most benchmark checks, worst first.",
  "Policies": "The rules endpoints must keep. Each is checked on a timer and put back when it drifts.",
  "Standing, per endpoint": "How each endpoint stands against its policies: compliant, drifted, or unknown where a check can't run.",
  "Existing policies": "Policies already defined: what each enforces, where, and whether it only reports or also fixes.",
  "Reports": "Scheduled summaries sent to people who don't use the console: what each contains, who gets it and when.",
  "Findings": "Matches against indicators of compromise, newest first.",
  "Signal findings": "Hits from signals: behavioural rules run on every process, file, registry, network, DNS and logon event as it arrives. One row per signal per endpoint, with a count.",
  "Live activity": "Every process start as it happens. Identical runs within five seconds collapse into one row with a count.",
  "Signals": "The behavioural rules evaluated live against every event. Each one can raise a finding.",
  "Users with the most reach": "Accounts that can reach the most endpoints through their memberships, where a compromise would spread furthest.",
  "Groups that grant the most": "Groups whose membership gives access to the most endpoints.",
  "Endpoints that reach the most": "Endpoints ranked by how many other endpoints can be reached from them, and from how many they can be reached.",
  "What to fix first": "The changes that remove the most reach for the least effort.",
  "Confirmed findings by pattern": "Sensitive data found on endpoints, by kind (card numbers, SSNs, secrets), counting only validated matches.",
  "Endpoints with the most confirmed files": "Where sensitive data is concentrated, by number of files with confirmed matches.",
  "Rules": "What Reveal looks for: patterns, where to search, and how matches are confirmed.",
  "Results": "The files where a rule matched, with masked samples of what was found.",
  "Unexpected change by endpoint, last 7 days": "Endpoints with the most changes to watched files and settings this week that weren't from a known change.",
  "Saved queries": "Questions saved for reuse, in dashboards or by anyone with access.",
  "Playbooks": "Multi-step runbooks done in order per endpoint: patch, wait for the reboot, verify, tell the user.",
  "Runs": "Each time a playbook ran: on which endpoints, and how far each got.",
  "New trigger": "Start a playbook automatically from an event or a schedule, rather than by hand.",
  "Endpoint patch readiness": "How ready the fleet is to patch: endpoints up to date, needing updates, or not able to scan.",
  "Devices": "Each endpoint's pending updates. Tick endpoints to patch them together, or use Apply patches on one.",
  "Schedules": "Recurring patch deployments: which endpoints, when, and whether they wait for a maintenance window.",
  "Preview": "The endpoints this group's rules match right now, before you save it.",
};

// --- Feel: in-place button states, undo, live numbers, skeletons ---------

// withButtonState runs a save behind a button and shows its outcome where
// the click was: a spinner while it runs, then a drawn check and doneLabel
// for a moment. The button keeps its width throughout, so nothing beside it
// moves. A failure puts the button back and rethrows for the caller's
// message.
async function withButtonState(btn, run, doneLabel) {
  if (!btn || btn.dataset.state === "busy") return;
  const original = btn.innerHTML;
  btn.dataset.state = "busy";
  btn.style.minWidth = btn.getBoundingClientRect().width + "px";
  btn.setAttribute("aria-busy", "true");
  btn.innerHTML = '<span class="btn-state"><i class="btn-spin" aria-hidden="true"></i></span>';
  try {
    const out = await run();
    btn.removeAttribute("aria-busy");
    btn.innerHTML = /* safe-html: the button's own markup from before */ original;
    delete btn.dataset.state;
    if (btn.isConnected) flashDone(btn, doneLabel);
    return out;
  } catch (e) {
    btn.innerHTML = /* safe-html: the button's own markup from before */ original;
    btn.style.minWidth = "";
    delete btn.dataset.state;
    btn.removeAttribute("aria-busy");
    throw e;
  }
}

// flashDone shows a drawn check and label in a button for a moment, then
// puts its own content back: the outcome of a save, where the click was.
function flashDone(btn, doneLabel) {
  if (!btn || btn.classList.contains("is-done")) return;
  const original = btn.innerHTML;
  btn.style.minWidth = btn.getBoundingClientRect().width + "px";
  btn.classList.add("is-done");
  btn.innerHTML = `<span class="btn-state"><svg class="btn-check" width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 8.5l3.2 3L13 4.8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>${escapeHtml(doneLabel || "Saved")}</span>`;
  setTimeout(() => {
    btn.classList.remove("is-done");
    btn.innerHTML = /* safe-html: the button's own markup from before */ original;
    btn.style.minWidth = "";
  }, 1400);
}

// undoable is a delete that can be taken back: hide() takes it off the
// screen now, commit() does it for real once the bar runs out (8 seconds),
// and Undo, or Ctrl/Cmd+Z, calls restore() instead. A second undoable
// commits the first. Leaving the page commits whatever is pending, so
// commit should use fetch(..., { keepalive: true }).
//
// For deletes that are reversible in the sense that matters: the person
// sees what happened and has a moment to change their mind. Deletes that
// take collected data or access with them still ask first.
const pendingUndo = { finish: null };
function undoable({ text, hide, restore, commit, seconds = 8 }) {
  if (pendingUndo.finish) pendingUndo.finish();
  hide();
  let settled = false, timer = 0;
  let toast = document.getElementById("undo-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "undo-toast";
    toast.className = "undo-toast";
    toast.setAttribute("role", "status");
    document.body.appendChild(toast);
  }
  const mac = /Mac|iPhone|iPad/.test(navigator.platform);
  toast.innerHTML = `<span class="undo-toast-text"></span><button type="button" aria-keyshortcuts="${mac ? "Meta+Z" : "Control+Z"}">Undo <kbd aria-hidden="true">${mac ? "⌘Z" : "Ctrl+Z"}</kbd></button><i class="undo-toast-bar" aria-hidden="true"></i>`;
  toast.querySelector(".undo-toast-text").textContent = text;
  const close = () => { toast.classList.remove("on"); document.removeEventListener("keydown", onKey); pendingUndo.finish = null; };
  const finish = () => {
    if (settled) return; settled = true; clearTimeout(timer); close();
    Promise.resolve().then(commit).catch(e => console.error("undoable commit failed", e));
  };
  const undo = () => { if (settled) return; settled = true; clearTimeout(timer); close(); restore(); };
  const onKey = e => {
    // Ctrl/Cmd+Z in a text field is that field's own undo.
    const inField = e.target instanceof Element && e.target.closest("input, textarea, [contenteditable], .cm-editor");
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && e.key.toLowerCase() === "z" && !inField) {
      e.preventDefault(); undo();
    }
  };
  document.addEventListener("keydown", onKey);
  toast.querySelector("button").addEventListener("click", undo);
  pendingUndo.finish = finish;
  requestAnimationFrame(() => toast.classList.add("on"));
  toast.querySelector(".undo-toast-bar").animate([{ transform: "scaleX(1)" }, { transform: "scaleX(0)" }], { duration: seconds * 1000, fill: "forwards" });
  timer = setTimeout(finish, seconds * 1000);
}
window.addEventListener("pagehide", () => { if (pendingUndo.finish) pendingUndo.finish(); });

// rollTiles: when a stat tile's number changes while the page is open, its
// digits roll to the new value and the figure is marked once. Tiles are
// re-rendered wholesale, so the last value is remembered by the tile's
// label on this page. Only whole numbers roll; "41%" or "2 of 5" just
// change.
const tileValues = new Map();
// Stat tiles on module pages, and the Home page's environment cards.
const ROLL_SEL = ".stat-tile-value, .env-card > .v";
function rollTile(el) {
  if (el.dataset.rolling) return;
  const label = el.closest(".stat-tile, .env-card")?.querySelector(".stat-tile-label, .k")?.textContent || "";
  const key = location.pathname + location.hash + "|" + label;
  const text = el.textContent.trim();
  const prev = tileValues.get(key);
  tileValues.set(key, text);
  if (prev === undefined || prev === text || !/^\d{1,9}$/.test(text) || !/^\d{1,9}$/.test(prev)) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) { el.classList.add("is-changed"); return; }
  const to = text, from = prev.padStart(to.length, "0").slice(-to.length);
  el.dataset.rolling = "1";
  const roll = document.createElement("span");
  roll.className = "roll";
  roll.setAttribute("aria-hidden", "true");
  const inners = [];
  for (let i = 0; i < to.length; i++) {
    const d = document.createElement("span"); d.className = "roll-digit";
    const inner = document.createElement("span");
    for (let n = 0; n <= 9; n++) { const x = document.createElement("span"); x.textContent = String(n); inner.appendChild(x); }
    inner.style.transform = `translateY(calc(${-Number(from[i])} * 1lh))`;
    d.appendChild(inner); roll.appendChild(d); inners.push([inner, Number(to[i])]);
  }
  el.setAttribute("aria-label", text);
  el.textContent = "";
  el.appendChild(roll);
  requestAnimationFrame(() => requestAnimationFrame(() => inners.forEach(([inner, n]) => { inner.style.transform = `translateY(calc(${-n} * 1lh))`; })));
  el.classList.remove("is-changed"); void el.offsetWidth; el.classList.add("is-changed");
  setTimeout(() => { el.textContent = text; el.removeAttribute("aria-label"); delete el.dataset.rolling; }, 480);
}

// skeletonize turns a "loading…" placeholder into rows shaped like what is
// coming, so the table does not jump when the data lands.
function skeletonize(el) {
  if (el.dataset.skel || el.textContent.trim() !== "loading…") return;
  el.dataset.skel = "1";
  el.setAttribute("aria-busy", "true");
  el.innerHTML = '<span class="sr-only">Loading</span><span class="skel" aria-hidden="true"><i></i><i></i><i></i></span>';
}

function feelScan(root) {
  if (!(root instanceof Element)) return;
  if (root.matches(ROLL_SEL)) rollTile(root);
  root.querySelectorAll(ROLL_SEL).forEach(rollTile);
  if (root.matches(".empty")) skeletonize(root);
  root.querySelectorAll(".empty").forEach(skeletonize);
}
new MutationObserver(list => {
  for (const m of list) {
    m.addedNodes.forEach(feelScan);
    if (m.type === "characterData" || (m.type === "childList" && m.target instanceof Element && m.target.matches(ROLL_SEL))) {
      const t = m.target instanceof Element ? m.target : m.target.parentElement;
      if (t && t.matches(ROLL_SEL)) rollTile(t);
    }
  }
}).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => feelScan(document.body));
else feelScan(document.body);

