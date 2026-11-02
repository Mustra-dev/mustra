// charts.js — the dashboard panel renderer, shared by Home and Dashboards.
//
// Inline SVG, no library. One categorical palette in a fixed order (the
// eight slots below validate for colour-vision deficiency in both themes;
// a ninth slice is folded into "Other" server-side, never given a new
// hue). Text always wears text tokens; a colour swatch beside it carries
// identity. Every chart with two or more series has a legend and direct
// labels on the largest slices; every mark has a hover title; a table view
// of any chart is one click away (the "rows" toggle).

const CHART_PALETTE = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"];
const CHART_PALETTE_DARK = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];

// chartRole keeps a chart's accessible role honest: a chart with drill-down
// links inside is a group of links, not an image -- role="img" would hide
// those links from assistive technology while they stay in the tab order.
function chartRole(inner) {
  return String(inner).includes("<a ") ? "group" : "img";
}

function chartIsDark() {
  const t = document.documentElement.getAttribute("data-theme");
  if (t === "dark") return true;
  if (t === "light") return false;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
}
// A palette may bring its own validated order (theme.js sets --viz-cat-N);
// otherwise the slots above.
function chartColor(i) {
  const own = getComputedStyle(document.documentElement).getPropertyValue(`--viz-cat-${(i % 8) + 1}`).trim();
  return own || (chartIsDark() ? CHART_PALETTE_DARK : CHART_PALETTE)[i % 8];
}
function chartEsc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function chartNum(n) { return Number(n || 0).toLocaleString(); }

// renderPanel returns the HTML for one evaluated panel. compact is the
// micro-chart form used by Home's Dashboard List.
function renderPanel(p, compact) {
  compactMode = !!compact;
  const hl = p.highlight ? " panel-hl" : "";
  const head = compact ? "" : `<div class="pnl-head"><span class="pnl-title">${chartEsc(p.title)}</span>
    ${p.chart !== "text" ? `<span class="pnl-meta">${p.error ? "" : chartNum(p.count) + " row" + (p.count === 1 ? "" : "s")}</span>
    <button class="pnl-rows" data-rows-toggle title="Show as rows">rows</button>` : ""}</div>`;
  let body;
  if (p.error) body = `<div class="pnl-err">${chartEsc(p.error)}</div>`;
  else switch (p.chart) {
    case "number": body = renderNumber(p, compact); break;
    case "donut": body = renderDonut(p, compact); break;
    case "bar": body = renderBars(p, compact); break;
    case "stacked": body = renderStacked(p, compact); break;
    case "area": body = renderArea(p, compact); break;
    case "table": body = renderTable(p, compact); break;
    case "text": body = renderText(p); break;
    default: body = `<div class="pnl-err">unknown chart</div>`;
  }
  const rows = p.chart === "text" || p.error ? "" : `<div class="pnl-rowsview" hidden>${renderRowsView(p)}</div>`;
  return `<div class="pnl w${chartEsc(p.width || 1)}${hl}${compact ? " compact" : ""}" data-panel="${chartEsc(p.id)}">${head}<div class="pnl-body">${body}</div>${rows}</div>`;
}

// --- drill-down -------------------------------------------------------
//
// A panel says forty endpoints run Debian; the next question is always
// which forty. Interact already answers that and can act on the answer, so
// a mark links to the query it stands for rather than this growing a second
// filtered table of its own.
//
// Only the endpoints source maps onto the query grammar. Panels over the
// other sources are left inert rather than given a link that lands on a
// parse error -- a mark that looks clickable and is not is worse than one
// that never offered.
function drillable(p) {
  return !compactMode && p && p.source === "endpoints" && !!p.group_by;
}

// compactMode is set for the duration of a compact render: Home's micro
// charts are already a link to the dashboard they came from, and a second
// target inside the first is a coin toss about where a click goes.
let compactMode = false;

function quoteValue(v) {
  const text = String(v == null ? "" : v);
  return /\s/.test(text) ? '"' + text.replace(/"/g, "") + '"' : text;
}

// drillHref builds "get <field> from all machines with <field> equals <v>",
// plus the second condition when a stacked panel knows both dimensions.
function drillHref(p, groupValue, seriesValue) {
  const conds = [`${p.group_by} equals ${quoteValue(groupValue)}`];
  const get = ["hostname", p.group_by];
  if (p.series_by && seriesValue != null) {
    conds.push(`${p.series_by} equals ${quoteValue(seriesValue)}`);
    get.push(p.series_by);
  }
  const q = `get ${get.join(" and ")} from all machines with ${conds.join(" and ")}`;
  return "/interact#ask?q=" + encodeURIComponent(q);
}

// drillWrap makes one mark a link when the panel supports it. SVG's own <a>
// is used rather than a click handler so the browser's own affordances --
// middle-click, open in a new tab, the status bar -- keep working.
function drillWrap(p, /* html-param: callers pass the chart mark they built */ markup, groupValue, seriesValue) {
  if (!drillable(p)) return markup;
  return `<a class="drill" href="${chartEsc(safeUrl(drillHref(p, groupValue, seriesValue)))}">${markup}</a>`;
}

// htmlMark is one HTML chart mark: a link to the endpoints behind it when
// the panel drills, otherwise a plain span. The charts below draw in HTML
// rather than a stretched SVG, whose text was squeezed to a sliver on a
// phone and smeared across a wide panel.
function htmlMark(p, cls, style, tip, groupValue, seriesValue) {
  return drillable(p)
    ? `<a class="drill ${chartEsc(cls)}"${sx(style)} title="${chartEsc(tip)}" href="${chartEsc(safeUrl(drillHref(p, groupValue, seriesValue)))}"></a>`
    : `<span class="${chartEsc(cls)}"${sx(style)} title="${chartEsc(tip)}"></span>`;
}

// keyOf is the value a mark was built from. The server tidies labels for
// reading -- "microsoft windows 11 pro" becomes "Windows 11 Pro" -- and
// sends the original alongside, because a query for the tidied one matches
// nothing.
function keyOf(point) { return (point && point.key) || (point && point.label) || ""; }

// A panel with no grouping is still worth a click: its number stands for a
// set of endpoints, and "which forty" is the same question there. The query
// is the panel's own filter, or every endpoint when it has none.
function drillableWhole(p) {
  return !compactMode && p && p.source === "endpoints";
}

function wholeHref(p) {
  const conds = [];
  const get = ["hostname", "os"];
  if (p.filter_column && p.filter_value) {
    conds.push(`${p.filter_column} equals ${quoteValue(p.filter_value)}`);
    if (!get.includes(p.filter_column)) get.push(p.filter_column);
  }
  const q = `get ${get.join(" and ")} from all machines` +
    (conds.length ? ` with ${conds.join(" and ")}` : "");
  return "/interact#ask?q=" + encodeURIComponent(q);
}

// drillNote is appended to a mark's hover title, so the link is discoverable
// without a legend entry explaining that charts are clickable.
function drillNote(p) {
  return drillable(p) ? " — click to list them" : "";
}

function renderNumber(p, compact) {
  const body = `<span class="hero-value">${chartNum(p.count)}</span>${compact ? `<span class="hero-label">${chartEsc(p.title)}</span>` : ""}`;
  if (!drillableWhole(p)) return `<div class="hero ${compact ? "small" : ""}">${body}</div>`;
  return `<a class="hero drill-hero ${compact ? "small" : ""}" href="${chartEsc(safeUrl(wholeHref(p)))}"
    title="List the endpoints behind this">${body}</a>`;
}

function legend(series) {
  if (!series || series.length < 2) return "";
  return `<div class="legend">${series.map((s, i) => `<span class="legend-item"><i${sx(`background:${chartColor(i)}`)}></i>${chartEsc(s.label)} <b>${chartNum(s.value)}</b></span>`).join("")}</div>`;
}

function renderDonut(p, compact) {
  const series = p.series || [];
  const total = series.reduce((a, s) => a + s.value, 0);
  if (!total) return `<div class="pnl-empty">no rows</div>`;
  // The radius has to leave room for half the stroke, which sits outside
  // it. r = size/2 - 6 against a 20px stroke put the ring's outer edge 4px
  // beyond the viewBox on every side, so the circle was drawn flattened on
  // all four -- visible as a donut with its top and sides shaved off.
  const size = compact ? 88 : 150, cx = size / 2, cy = size / 2;
  const stroke = compact ? 12 : 20;
  const r = size / 2 - stroke / 2 - 1;
  const circ = 2 * Math.PI * r;
  let offset = 0;
  const arcs = series.map((s, i) => {
    const len = s.value / total * circ;
    // A 2px surface gap between segments (the spacer) and a hover title.
    const gap = series.length > 1 ? Math.min(2.5, len / 2) : 0;
    const el = drillWrap(p, `<circle r="${r}" cx="${cx}" cy="${cy}" fill="none" stroke="${chartEsc(chartColor(i))}" stroke-width="${stroke}"
      stroke-dasharray="${Math.max(0, len - gap)} ${circ - Math.max(0, len - gap)}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cy})">
      <title>${chartEsc(s.label)}: ${chartNum(s.value)} (${s.share.toFixed(1)}%)${drillNote(p)}</title></circle>`, keyOf(s));
    offset += len;
    return el;
  }).join("");
  const top = series[0];
  const center = compact
    ? `<text x="${cx}" y="${cy + 4}" text-anchor="middle" class="hero-svg small">${chartNum(total)}</text>`
    : `<text x="${cx}" y="${cy - 2}" text-anchor="middle" class="hero-svg">${chartNum(total)}</text>
       <text x="${cx}" y="${cy + 14}" text-anchor="middle" class="hero-svg-sub">${chartEsc(top.label.length > 14 ? top.label.slice(0, 13) + "…" : top.label)} ${top.share.toFixed(0)}%</text>`;
  const svg = `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="${chartEsc(chartRole(arcs))}" aria-label="${chartEsc(p.title)}">${arcs}${center}</svg>`;
  return `<div class="donut-wrap">${svg}${compact ? `<div class="hero-label">${chartEsc(p.title)}</div>` : legend(series)}</div>`;
}

function renderBars(p, compact) {
  const series = p.series || [];
  if (!series.length) return `<div class="pnl-empty">no rows</div>`;
  const max = Math.max(1, ...series.map(s => s.value));
  if (!compact) {
    const cols = series.map(s => {
      const pct = Math.max(1.5, (s.value / max) * 100);
      const tip = `${s.label}: ${chartNum(s.value)} (${s.share.toFixed(1)}%)${drillNote(p)}`;
      return `<div class="vb-col"><div class="vb-area"><span class="vb-val">${chartNum(s.value)}</span>` +
        htmlMark(p, "vb-bar", `height:${pct.toFixed(2)}%;background:${chartColor(0)}`, tip, keyOf(s)) +
        `</div><span class="vb-lbl" title="${chartEsc(s.label)}">${chartEsc(s.label)}</span></div>`;
    }).join("");
    return `<div class="vbars" role="${chartEsc(chartRole(cols))}" aria-label="${chartEsc(p.title)}">${cols}</div>`;
  }
  // The viewBox is stretched to the panel's width, so its width has to
  // track the panel's column span or the <text> inside is stretched with
  // it — two and three-wide panels were drawing their labels at double and
  // triple width. topPad is headroom for the value label above the tallest
  // bar, which used to be clipped by the top of the viewBox.
  const n = series.length, w = compact ? 160 : 420 * (p.width || 1);
  const h = compact ? 70 : 150, pad = 4, labelH = compact ? 0 : 30, topPad = compact ? 2 : 14;
  // Bars used to be capped at 36px and spread across the whole panel, so a
  // two-series chart in a double-width panel drew two slivers a third of a
  // screen apart. Give each one a slot, cap the slot rather than the bar,
  // and centre the group: few categories cluster in the middle at a
  // readable width, many still use the full width.
  const slot = Math.min((w - pad * 2) / n, compact ? 40 : 132);
  const step = slot;
  const bw = Math.max(6, Math.min(slot - (compact ? 4 : 18), compact ? 28 : 86));
  const originX = pad + ((w - pad * 2) - slot * n) / 2;
  const bars = series.map((s, i) => {
    const bh = Math.max(2, (s.value / max) * (h - topPad));
    const x = originX + i * step + (step - bw) / 2, y = h - bh;
    // One hue for one series: bars are magnitude, not identity. The single
    // categorical slot is series-1; the label is the identity.
    const lbl = compact ? "" : `<text x="${x + bw / 2}" y="${h + 14}" text-anchor="middle" class="axis-label">${chartEsc(s.label.length > 10 ? s.label.slice(0, 9) + "…" : s.label)}</text>`;
    const val = compact || s.value / max < 0.12 ? "" : `<text x="${x + bw / 2}" y="${y - 3}" text-anchor="middle" class="value-label">${chartNum(s.value)}</text>`;
    const bar = drillWrap(p, `<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="3" fill="${chartEsc(chartColor(0))}"><title>${chartEsc(s.label)}: ${chartNum(s.value)} (${s.share.toFixed(1)}%)${drillNote(p)}</title></rect>`, keyOf(s));
    return `<g>${bar}${val}${lbl}</g>`;
  }).join("");
  const svg = `<svg viewBox="0 0 ${w} ${h + labelH}" width="100%" height="${h + labelH}" preserveAspectRatio="none" role="${chartEsc(chartRole(bars))}" aria-label="${chartEsc(p.title)}">
    <line x1="0" y1="${h}" x2="${w}" y2="${h}" class="axis-line"/>${bars}</svg>`;
  return `<div class="bars-wrap">${svg}${compact ? `<div class="hero-label">${chartEsc(p.title)}</div>` : ""}</div>`;
}

function renderStacked(p, compact) {
  const bars = p.stacked || [];
  if (!bars.length) return `<div class="pnl-empty">no rows</div>`;
  // Series order is fixed by the server across every bar.
  const seriesNames = [];
  bars.forEach(b => b.parts.forEach(pt => { if (!seriesNames.includes(pt.label)) seriesNames.push(pt.label); }));
  const max = Math.max(1, ...bars.map(b => b.total));
  if (!compact) {
    const rows = bars.map(b => {
      const segs = b.parts.map(pt => {
        const ci = seriesNames.indexOf(pt.label);
        const pct = b.total ? (pt.value / b.total) * 100 : 0;
        const tip = `${b.label} · ${pt.label}: ${chartNum(pt.value)} (${pt.share.toFixed(0)}%)${drillNote(p)}`;
        return htmlMark(p, "hs-seg", `width:${pct.toFixed(2)}%;background:${chartColor(ci)}`, tip, keyOf(b), keyOf(pt));
      }).join("");
      const fill = Math.max(1, (b.total / max) * 100);
      return `<div class="hs-row"><span class="hs-label" title="${chartEsc(b.label)}">${chartEsc(b.label)}</span>` +
        `<span class="hs-track"><span class="hs-fill"${sx(`width:${fill.toFixed(2)}%`)}>${segs}</span>` +
        `<span class="hs-total">${chartNum(b.total)}</span></span></div>`;
    }).join("");
    const lg0 = legend(seriesNames.map((n, i) => ({ label: n, value: bars.reduce((a, b) => a + (b.parts.find(x => x.label === n) || { value: 0 }).value, 0) })));
    return `<div class="stack-wrap"><div class="hstack" role="${chartEsc(chartRole(rows))}" aria-label="${chartEsc(p.title)}">${rows}</div>${lg0}</div>`;
  }
  const rowH = compact ? 10 : 22, gap = compact ? 4 : 10, labelW = compact ? 0 : 110;
  // As in renderBars: widen with the panel so the labels are not stretched.
  const w = compact ? 160 : 460 * (p.width || 1);
  // Room for the total printed after the longest bar. A fixed 40px fitted
  // "812" and ran a seven-figure fleet count off the right edge.
  const totW = compact ? 0 : 12 + String(chartNum(max)).length * 6;
  const h = bars.length * (rowH + gap);
  const rows = bars.map((b, bi) => {
    let x = labelW;
    const y = bi * (rowH + gap);
    const segs = b.parts.map(pt => {
      const sw = Math.max(0, (pt.value / max) * (w - labelW - totW) - 2);
      const ci = seriesNames.indexOf(pt.label);
      const el = drillWrap(p, `<rect x="${x}" y="${y}" width="${sw}" height="${rowH}" rx="2" fill="${chartEsc(chartColor(ci))}"><title>${chartEsc(b.label)} · ${chartEsc(pt.label)}: ${chartNum(pt.value)} (${pt.share.toFixed(0)}%)${drillNote(p)}</title></rect>`, keyOf(b), keyOf(pt));
      x += sw + 2;
      return el;
    }).join("");
    const lbl = compact ? "" : `<text x="${labelW - 8}" y="${y + rowH - 6}" text-anchor="end" class="axis-label">${chartEsc(b.label.length > 16 ? b.label.slice(0, 15) + "…" : b.label)}</text>`;
    const tot = compact ? "" : `<text x="${x + 4}" y="${y + rowH - 6}" class="value-label">${chartNum(b.total)}</text>`;
    return `<g>${lbl}${segs}${tot}</g>`;
  }).join("");
  const svg = `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" preserveAspectRatio="none" role="${chartEsc(chartRole(rows))}" aria-label="${chartEsc(p.title)}">${rows}</svg>`;
  const lg = compact ? `<div class="hero-label">${chartEsc(p.title)}</div>` : legend(seriesNames.map((n, i) => ({ label: n, value: bars.reduce((a, b) => a + (b.parts.find(x => x.label === n) || { value: 0 }).value, 0) })));
  return `<div class="stack-wrap">${svg}${lg}</div>`;
}

function renderArea(p, compact) {
  const pts = p.history || [];
  if (pts.length < 1) return `<div class="pnl-empty">no history yet — the first sample lands within 15 minutes</div>`;
  const w = compact ? 160 : 460, h = compact ? 60 : 130, padX = 4, padY = 6;
  const t0 = new Date(pts[0].at).getTime(), t1 = Math.max(t0 + 1, new Date(pts[pts.length - 1].at).getTime());
  const max = Math.max(1, ...pts.map(x => x.value));
  const xy = pts.map(x => [padX + (new Date(x.at).getTime() - t0) / (t1 - t0) * (w - padX * 2), h - padY - (x.value / max) * (h - padY * 2)]);
  const line = xy.map((c, i) => (i ? "L" : "M") + c[0].toFixed(1) + " " + c[1].toFixed(1)).join(" ");
  const area = line + ` L${xy[xy.length - 1][0].toFixed(1)} ${h - padY} L${xy[0][0].toFixed(1)} ${h - padY} Z`;
  const last = pts[pts.length - 1], first = pts[0];
  // Hover targets: one invisible column per point carrying the tooltip.
  const hover = xy.map((c, i) => `<rect x="${(c[0] - (w / Math.max(1, xy.length)) / 2).toFixed(1)}" y="0" width="${(w / Math.max(1, xy.length)).toFixed(1)}" height="${h}" fill="transparent"><title>${chartEsc(fmtTime(pts[i].at))}: ${chartNum(pts[i].value)}</title></rect>`).join("");
  const marker = `<circle cx="${xy[xy.length - 1][0].toFixed(1)}" cy="${xy[xy.length - 1][1].toFixed(1)}" r="4" fill="${chartEsc(chartColor(0))}" class="pt-ring"/>`;
  const plot = `<path d="${area}" fill="${chartEsc(chartColor(0))}" opacity="0.18"/><path d="${line}" fill="none" stroke="${chartEsc(chartColor(0))}" stroke-width="2" stroke-linejoin="round"/>${marker}${hover}`;
  const svg = `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" preserveAspectRatio="none" role="${chartEsc(drillableWhole(p) ? "group" : "img")}" aria-label="${chartEsc(p.title)}">
    ${drillableWhole(p) ? `<a class="drill" href="${chartEsc(safeUrl(wholeHref(p)))}">${plot}</a>` : plot}</svg>`;
  const axis = compact ? `<div class="hero-label">${chartEsc(p.title)} · ${chartNum(last.value)}</div>`
    : `<div class="spark-axis"><span>${chartEsc(fmtDate(first.at))}</span><span>now <b>${chartNum(last.value)}</b>${chartEsc(pts.length > 1 ? ` · ${pts.length} samples, peak ${chartNum(max)}` : "")}</span></div>`;
  return `<div class="area-wrap">${svg}${axis}</div>`;
}

function renderTable(p, compact) {
  const cols = p.columns || [], rows = p.rows || [];
  if (!rows.length) return `<div class="pnl-empty">no rows</div>`;
  if (compact) return `<div class="hero small"><span class="hero-value">${chartNum(p.count)}</span><span class="hero-label">${chartEsc(p.title)}</span></div>`;
  return `<div class="table-scroll u-maxh-320"><table><thead><tr>${cols.map(c => `<th>${chartEsc(c)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map(r => `<tr>${r.map(v => `<td>${chartEsc(v)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
    ${p.count > rows.length ? `<div class="pnl-more">${chartNum(rows.length)} of ${chartNum(p.count)} rows</div>` : ""}`;
}

function renderText(p) {
  // Plain text with paragraphs; a line that is a console path becomes a link.
  const lines = String(p.text || "").split("\n");
  return `<div class="pnl-text">${lines.map(l => {
    const t = l.trim();
    if (!t) return "";
    if (/^\/[a-z][a-z0-9\-\/]*(#[^\s]*)?(\s.*)?$/i.test(t)) {
      const [href, ...rest] = t.split(/\s+/);
      return `<p><a href="${chartEsc(safeUrl(href))}">${chartEsc(rest.join(" ") || href)}</a></p>`;
    }
    return `<p>${chartEsc(t)}</p>`;
  }).join("")}</div>`;
}

function renderRowsView(p) {
  if (p.series && p.series.length) return `<table><thead><tr><th>Label</th><th>Count</th><th>Share</th></tr></thead><tbody>${p.series.map(s => `<tr><td>${chartEsc(s.label)}</td><td>${chartNum(s.value)}</td><td>${s.share.toFixed(1)}%</td></tr>`).join("")}</tbody></table>`;
  if (p.stacked && p.stacked.length) return `<table><thead><tr><th>Bar</th><th>Series</th><th>Count</th></tr></thead><tbody>${p.stacked.flatMap(b => b.parts.map(pt => `<tr><td>${chartEsc(b.label)}</td><td>${chartEsc(pt.label)}</td><td>${chartNum(pt.value)}</td></tr>`)).join("")}</tbody></table>`;
  if (p.history && p.history.length) return `<table><thead><tr><th>When</th><th>Value</th></tr></thead><tbody>${p.history.slice(-40).map(h => `<tr><td>${chartEsc(fmtTime(h.at))}</td><td>${chartNum(h.value)}</td></tr>`).join("")}</tbody></table>`;
  return `<table><tbody><tr><td>${chartNum(p.count)} row(s)</td></tr></tbody></table>`;
}

// wirePanels attaches the rows toggle inside a container.
function wirePanels(container) {
  container.querySelectorAll("[data-rows-toggle]").forEach(b => b.addEventListener("click", () => {
    const pnl = b.closest(".pnl"), body = pnl.querySelector(".pnl-body"), rows = pnl.querySelector(".pnl-rowsview");
    const showRows = rows.hidden;
    rows.hidden = !showRows; body.hidden = showRows;
    b.textContent = showRows ? "chart" : "rows";
  }));
}

const CHART_CSS = `
  .pnl-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
  .pnl.w2 { grid-column: span 2; } .pnl.w3 { grid-column: span 3; }
  @media (max-width: 900px) { .pnl-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .pnl.w3 { grid-column: span 2; } }
  @media (max-width: 600px) { .pnl-grid { grid-template-columns: 1fr; } .pnl.w2, .pnl.w3 { grid-column: span 1; } }
  .pnl { border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); padding: 12px 14px; min-width: 0; }
  .pnl.panel-hl { border-color: var(--viz-critical); box-shadow: inset 3px 0 0 var(--viz-critical); }
  .pnl.compact { padding: 8px 10px; border: 0; background: transparent; }
  .pnl-head { display: flex; align-items: baseline; gap: 8px; margin-bottom: 8px; }
  .pnl-title { font-weight: 600; font-size: 13px; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .pnl-meta { font-size: var(--fs-meta); color: var(--text-muted); }
  .pnl-rows { font-size: var(--fs-meta); padding: 1px 7px; border-radius: 999px; border: 1px solid var(--border); background: var(--surface-2); color: var(--text-muted); cursor: pointer; }
  .pnl-rows:hover { color: var(--text); border-color: var(--accent); }
  .pnl-err { color: var(--off); font-size: 12px; } .pnl-empty { color: var(--text-muted); font-size: 12px; padding: 12px 0; }
  .pnl-more { font-size: var(--fs-meta); color: var(--text-muted); margin-top: 4px; }
  .pnl-rowsview { overflow-x: auto; }
  .pnl-rowsview table { width: 100%; font-size: 12px; } .pnl-rowsview td, .pnl-rowsview th { padding: 3px 6px; text-align: left; border-bottom: 1px solid var(--border); }
  .hero { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; padding: 8px 0; }
  .hero-value { font-size: 34px; font-weight: 700; line-height: 1; color: var(--text); font-variant-numeric: tabular-nums; }
  .hero.small .hero-value { font-size: 24px; }
  .hero-label { font-size: var(--fs-meta); color: var(--text-muted); }
  .hero-svg { font-size: 22px; font-weight: 700; fill: var(--text); } .hero-svg.small { font-size: 14px; } .hero-svg-sub { font-size: 9.5px; fill: var(--text-muted); }
  .donut-wrap { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
  .donut-wrap > svg { flex: 0 0 auto; }
  /* The legend shares the donut's row rather than wrapping beneath it. A
     150px donut plus a legend at its natural width overflowed a single-width
     panel, so the legend wrapped and left the donut alone in the left third
     of a card with nothing in the rest of it. */
  .legend { display: flex; flex-wrap: wrap; gap: 4px 12px; font-size: var(--fs-meta); color: var(--text-muted);
    flex: 1 1 150px; min-width: 0; }
  .stack-wrap .legend, .pnl-body > .legend { flex: 1 1 100%; }
  /* A linked mark says so on hover, and keeps the pointer it would have had
     as a link rather than the text caret SVG gives it by default. */
  a.drill { cursor: pointer; }
  a.drill:hover rect, a.drill:hover circle { filter: brightness(1.15); }
  a.drill:focus-visible rect, a.drill:focus-visible circle { outline: 2px solid var(--accent); outline-offset: 2px; }
  .legend-item { display: inline-flex; align-items: center; gap: 5px; } .legend-item i { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
  .legend-item b { color: var(--text); font-weight: 600; }
  .axis-label { font-size: 10px; fill: var(--text-muted); } .value-label { font-size: 10px; fill: var(--text); font-weight: 600; }
  .axis-line { stroke: var(--border); stroke-width: 1; }
  .pt-ring { stroke: var(--surface); stroke-width: 2; }
  .spark-axis { display: flex; justify-content: space-between; font-size: var(--fs-meta); color: var(--text-muted); margin-top: 4px; }
  .spark-axis b { color: var(--text); }
  .stack-wrap svg { display: block; margin-bottom: 8px; }
  /* HTML charts (renderStacked, renderBars): text at its real size at any
     panel width. */
  .hstack { display: flex; flex-direction: column; gap: 10px; margin-bottom: 12px; }
  .hs-row { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .hs-label { flex: 0 0 clamp(64px, 22%, 140px); font-size: var(--fs-meta); color: var(--text-muted); text-align: right;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hs-track { flex: 1 1 auto; min-width: 0; display: flex; align-items: center; gap: 6px; }
  .hs-fill { display: flex; gap: 2px; height: 22px; max-width: calc(100% - 3.5em); min-width: 3px; }
  .hs-seg { display: block; height: 100%; min-width: 3px; border-radius: 2px; }
  .hs-total { font-size: var(--fs-meta); font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums; }
  .vbars { display: flex; align-items: stretch; justify-content: center; gap: 14px; padding-top: 4px; }
  .vb-col { display: flex; flex-direction: column; align-items: center; flex: 1 1 0; min-width: 0; max-width: 132px; }
  .vb-area { height: 150px; width: 100%; display: flex; flex-direction: column; justify-content: flex-end; align-items: center;
    border-bottom: 1px solid var(--border); }
  .vb-val { font-size: var(--fs-meta); font-weight: 600; color: var(--text); margin-bottom: 3px; font-variant-numeric: tabular-nums; }
  .vb-bar { display: block; width: min(86px, 80%); border-radius: 3px 3px 0 0; }
  .vb-lbl { font-size: var(--fs-meta); color: var(--text-muted); margin-top: 5px; max-width: 100%;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  a.drill.hs-seg:hover, a.drill.vb-bar:hover { filter: brightness(1.15); }
  a.drill.hs-seg:focus-visible, a.drill.vb-bar:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .legend-item { max-width: 100%; }
  .pnl-text p { margin: 0 0 8px; font-size: 13px; line-height: 1.5; } .pnl-text a { color: var(--accent); }
  /* A number that stands for a set of endpoints is a link to them, and
     looks like the number it replaced until you point at it. */
  a.hero.drill-hero { text-decoration: none; color: inherit; }
  a.hero.drill-hero:hover .hero-value { color: var(--accent); }
  a.hero.drill-hero:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; border-radius: var(--radius-sm); }
`;
// The console's CSP lets a <style> element apply only with the page's
// nonce, which this script's own tag carries.
(function () {
  const st = document.createElement("style");
  const nonce = document.currentScript && document.currentScript.nonce;
  if (nonce) st.nonce = nonce;
  st.textContent = CHART_CSS; document.head.appendChild(st);
})();
