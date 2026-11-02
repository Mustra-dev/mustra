// Deployment dashboard, shared by Patches, Software and Deploy Agents.
//
// One component rather than three copies, so the pages read the same and
// stay that way: a filterable list (Active / Inactive tabs, live segmented
// progress) and a full page per deployment that reads it as a count you
// drill into -- a stage bar, errors collapsed by message, the details, and
// endpoints grouped by status.
//
// Each page supplies only where its data comes from. load() returns
// deployments in the shape below and loadDetail(id) one deployment with the
// endpoints behind it; everything drawn from there on is the same code.
//
//   deployment: { id, title, target, kind, started_at, by, total, reported,
//                 status, failing, facts?: [[label, value], ...] }
//   device:     { id, name, status, detail, finished_at }
//
// opts.extraTiles() adds header buttons, each { label, value, title?,
// onClick } -- a button always opens something. opts.create, when given,
// is { label, href } for the page's primary "deploy something" action.
//
// opts.deviceLink(device, deployment), when a page has more to show about
// one endpoint's run, returns { href, label } for a link beside it.
//
// opts.deviceActions(device, deployment) returns buttons for an endpoint's
// row, each { label, danger?, onClick(device, deployment, slot) }. slot is a
// region under the deployment's page that live refreshes leave alone, for
// things like a console viewer. A device's warning (e.g. "endpoint silent
// for 12m") shows under its name, and any warning is summarised on top.
//
// Needs app.js (escapeHtml, fmtAgo, fmtTime, icon, csvRow, safeUrl)
// loaded first.

// Every per-endpoint action status rolls up into one of these groups, and a
// group expands to the machines behind it.
const DEPLOYMENT_STATUS_GROUPS = [
  { key: "waiting", label: "Waiting", tone: "warn",
    hint: "Held until the endpoint's maintenance window opens",
    has: s => s === "waiting" },
  { key: "downloading", label: "Downloading", tone: "warn",
    hint: "Downloading the update or package",
    has: s => s === "downloading" },
  { key: "installing", label: "Installing", tone: "warn",
    hint: "Installing; a macOS update through the MDM stays here until the Mac reports the new version",
    has: s => s === "installing" },
  { key: "in_progress", label: "In Progress", tone: "warn",
    hint: "The agent accepted the job and has not yet said what stage it is at",
    has: s => ["started", "pending", "running"].includes(s) },
  { key: "pending_restart", label: "Pending Restart", tone: "warn",
    hint: "Installed; not in effect until the endpoint restarts",
    has: s => s === "pending_restart" },
  { key: "complete", label: "Complete", tone: "ok",
    hint: "Finished and reported success, or nothing was permitted to run",
    has: s => ["succeeded", "skipped"].includes(s) },
  { key: "error", label: "Error", tone: "bad",
    hint: "Reported a failure, timed out, never reached a connected agent, or the window never opened",
    has: s => ["failed", "timed_out", "no_response", "expired"].includes(s) },
];

const DEPLOYMENT_GROUP_COLORS = {
  waiting: "var(--viz-warning)", in_progress: "var(--viz-progress)",
  downloading: "color-mix(in srgb, var(--viz-progress) 55%, transparent)", installing: "var(--viz-progress)",
  pending_restart: "var(--viz-warning)", complete: "var(--viz-good)", error: "var(--viz-critical)",
};

// A run still working, whichever stage it reports (see deploymentStatus).
const deploymentActive = s => s === "running" || s === "downloading" || s === "installing";

function deploymentGroupFor(status) {
  return DEPLOYMENT_STATUS_GROUPS.find(g => g.has(status)) || null;
}

// deploymentStatusPill accepts both a deployment's status ("running",
// "partial", ...) and a raw per-endpoint status ("started", "timed_out"), so
// the list and the drawer's endpoint rows read the same. A "Retry N." detail
// adds a "– retry N" suffix.
function deploymentStatusPill(status, detail) {
  if (status === "timed_out") status = "timed out";
  if (status === "no_response") status = "no response";
  if (status === "started" || status === "pending") status = "running";
  if (status === "pending_restart") status = "pending restart";
  const retry = /^Retry (\d+)\./.exec(detail || "");
  const suffix = retry ? ` – retry ${retry[1]}` : "";
  const pill = (cls, text, title) =>
    `<span class="dd-pill ${escapeHtml(cls)}"${title ? ` title="${escapeHtml(title)}"` : ""}>${escapeHtml(text)}</span>`;
  switch (status) {
    case "succeeded": return pill("ok", "succeeded" + suffix);
    case "skipped": return pill("none", "skipped", "Nothing was permitted to run");
    case "pending restart": return pill("warn", "pending restart");
    case "waiting": return pill("none", "waiting for window", detail || "");
    case "downloading": case "installing": return pill("live", status + suffix);
    case "running": return pill("live", "running");
    case "expired": case "failed": case "stalled": return pill("bad", status);
    case "partial": case "timed out": return pill("warn", status);
    case "no response": return pill("none", status, "The agent was not connected, so nothing ran");
    default: return pill("none", status || "unknown");
  }
}

// deploymentBreakdown buckets a deployment's endpoints into the status
// groups. Run-based deployments carry per-status outcome counts; an agent
// push is one endpoint, so its own status is the whole story. Endpoints
// targeted but not yet reported are counted, so the parts add up to total.
function deploymentBreakdown(d) {
  const by = Object.fromEntries(DEPLOYMENT_STATUS_GROUPS.map(g => [g.key, 0]));
  by.other = 0;
  const total = d.total || 0;
  let reported = 0;
  if (d.outcomes) {
    for (const [status, n] of Object.entries(d.outcomes)) {
      const g = deploymentGroupFor(status);
      by[g ? g.key : "other"] += n;
      reported += n;
    }
  } else if (d.reported) {
    const g = deploymentGroupFor(d.status);
    by[g ? g.key : (d.status === "running" ? "in_progress" : "other")] += d.reported;
    reported = d.reported;
  }
  return { by, reported, notYet: Math.max(0, total - reported), total };
}

// A segmented bar: complete, in progress, waiting, failed and not yet
// reported, each its own colour, so a list row says more than "how much".
function deploymentBarHtml(d) {
  const b = deploymentBreakdown(d);
  const denom = Math.max(b.total, b.reported, 1);
  const segs = [
    ...DEPLOYMENT_STATUS_GROUPS.map(g => [g.key, b.by[g.key], DEPLOYMENT_GROUP_COLORS[g.key], g.label]),
    ["other", b.by.other, "var(--viz-none)", "Other"],
  ].filter(s => s[1] > 0);
  const label = segs.map(s => `${s[3]} ${s[1]}`).join(", ") + (b.notYet ? `, not reported ${b.notYet}` : "");
  return `<div class="dl-bar" role="img" aria-label="${escapeHtml(label || "nothing reported")}" title="${escapeHtml(label || "nothing reported")}">${
    segs.map(s => `<span${sx(`width:${(s[1] * 100 / denom).toFixed(2)}%;background:${s[2]}`)}></span>`).join("")}</div>`;
}

function mountDeploymentDashboard(root, opts) {
  const P = opts.id; // prefixes DOM ids and saved state
  const LIVE_POLL_MS = 5000;
  const LIST_POLL_MS = 10000;
  const IDLE_POLL_MS = 30000;
  let list = [];
  let tab = "active";
  let liveTimer = null, listTimer = null;
  let liveID = null, groupPick = "", liveSince = null;
  const view = { q: "", filters: {}, filtersOpen: false, sort: { key: "started", dir: -1 } };
  try { Object.assign(view, JSON.parse(sessionStorage.getItem("mustra-dl-" + P) || "{}"), { q: "" }); } catch (e) {}
  const saveView = () => { try { sessionStorage.setItem("mustra-dl-" + P, JSON.stringify({ filters: view.filters, filtersOpen: view.filtersOpen, sort: view.sort })); } catch (e) {} };

  // Two views in one container: the list, and one deployment's page. The
  // page used to be a side drawer; a deployment has enough to say (status,
  // errors, targets, every endpoint) to deserve the full width.
  root.innerHTML = `
    <div class="dl" data-dl-list>
      <div class="dl-head">
        <h1>Deployments</h1>
        <div class="dl-head-actions" data-dl-actions></div>
      </div>
      <nav class="dl-tabs" role="tablist" aria-label="Deployment lists" data-dl-tabs></nav>
      <section class="dl-panel">
        <div class="dl-bar-row">
          <div class="dl-count" aria-live="polite" data-dl-count></div>
          <div class="dl-tools">
            <span class="dl-updated" aria-live="off" data-dl-updated></span>
            <button type="button" class="dl-btn dl-icon-btn" data-dl-refresh title="Refresh now" aria-label="Refresh deployments">${icon("sync")}</button>
            <button type="button" class="dl-btn" data-dl-export>Export CSV</button>
            <label class="dl-search">${icon("search")}<input type="search" placeholder="Filter items" aria-label="Filter deployments" data-dl-q></label>
          </div>
        </div>
        <div class="dl-filters">
          <button type="button" class="dl-filter-toggle" aria-expanded="false" data-dl-ftoggle></button>
          <div class="dl-filter-grid" data-dl-fgrid hidden></div>
        </div>
        <div class="dl-table-wrap"><table class="dl-table">
          <thead><tr data-dl-thead></tr></thead>
          <tbody data-dl-body><tr><td class="dl-empty" colspan="9">loading…</td></tr></tbody>
        </table></div>
      </section>
    </div>
    <div class="dv" data-dl-detail hidden></div>`;
  const $ = sel => root.querySelector(sel);
  const listEl = $("[data-dl-list]");
  const detailEl = $("[data-dl-detail]");

  const COLUMNS = [
    { key: "id", label: "ID", value: d => d.id },
    { key: "name", label: "Name", value: d => d.title || opts.title },
    { key: "kind", label: "Type", value: d => d.kind || "" },
    { key: "by", label: "Created By", value: d => d.by || "" },
    { key: "complete", label: "Complete", value: d => deploymentBreakdown(d).by.complete },
    { key: "endpoints", label: "Endpoints", value: d => d.total || 0 },
    { key: "started", label: "Start Time", value: d => d.started_at || "" },
    { key: "status", label: "Status", value: d => d.status || "" },
  ];
  const FILTERS = [
    { key: "name", label: "Name", of: d => d.title || opts.title },
    { key: "kind", label: "Type", of: d => d.kind || "", label2: kindLabel },
    { key: "status", label: "Status", of: d => d.status || "" },
    { key: "by", label: "Issued By", of: d => d.by || "" },
    { key: "category", label: "Content", of: d => d.category || "", label2: c => ({ patch: "Patches", software: "Software", playbook: "Playbooks", other: "Other" }[c] || c) },
    { key: "target", label: "Targeted", of: d => d.target || "" },
  ];

  // --- the list ---------------------------------------------------------------
  const tabsOf = () => {
    const t = [
      { key: "active", label: "Active", has: d => deploymentActive(d.status) },
      { key: "inactive", label: "Inactive", has: d => !deploymentActive(d.status) },
    ];
    // Self Service gets its own tab once anything was requested that way,
    // as on the console it is modelled on; it is a view, not a third state.
    if (list.some(d => d.kind === "self service")) t.push({ key: "selfservice", label: "Self Service", has: d => d.kind === "self service" });
    return t;
  };

  function shownRows() {
    const t = tabsOf().find(x => x.key === tab) || tabsOf()[0];
    const inTab = list.filter(t.has);
    const shown = inTab.filter(d => {
      if (view.q) {
        const hay = [d.id, d.title, d.target, d.kind, d.by, d.status, d.category].join(" ").toLowerCase();
        if (!hay.includes(view.q)) return false;
      }
      return FILTERS.every(f => !view.filters[f.key] || f.of(d) === view.filters[f.key]);
    });
    const col = COLUMNS.find(c => c.key === view.sort.key) || COLUMNS[6];
    shown.sort((a, b) => {
      const x = col.value(a), y = col.value(b);
      const r = typeof x === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
      return r * view.sort.dir;
    });
    return { inTab, shown };
  }

  function renderHead() {
    const actions = $("[data-dl-actions]");
    const extra = opts.extraTiles ? opts.extraTiles() : [];
    actions.innerHTML = extra.map((t, i) =>
      `<button type="button" class="dl-btn" data-dl-extra="${i}" title="${escapeHtml(t.title || "")}">${escapeHtml(t.label)} <span class="dl-badge">${escapeHtml(String(t.value))}</span></button>`).join("") +
      (opts.create ? `<a class="dl-primary" href="${escapeHtml(safeUrl(opts.create.href))}">${escapeHtml(opts.create.label)}</a>` : "");
    actions.querySelectorAll("[data-dl-extra]").forEach(b => b.addEventListener("click", () => extra[Number(b.dataset.dlExtra)].onClick()));

    const tabs = tabsOf();
    if (!tabs.some(t => t.key === tab)) tab = "active";
    $("[data-dl-tabs]").innerHTML = tabs.map(t => {
      const n = list.filter(t.has).length;
      return `<button type="button" role="tab" class="dl-tab" aria-selected="${t.key === tab}" data-dl-tab="${escapeHtml(t.key)}">${escapeHtml(t.label)} <span class="dl-tab-n">${escapeHtml(String(n))}</span></button>`;
    }).join("");
    $("[data-dl-tabs]").querySelectorAll("[data-dl-tab]").forEach(b => b.addEventListener("click", () => { tab = b.dataset.dlTab; render(); }));
  }

  function renderFilters() {
    const active = FILTERS.filter(f => view.filters[f.key]).length;
    const toggle = $("[data-dl-ftoggle]");
    toggle.setAttribute("aria-expanded", String(view.filtersOpen));
    toggle.innerHTML = `<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M3 2l4 3-4 3z" fill="currentColor"/></svg> Filters${active ? ` <span class="dl-badge dl-badge-accent">${escapeHtml(String(active))}</span>` : ""}`;
    const grid = $("[data-dl-fgrid]");
    grid.hidden = !view.filtersOpen;
    if (!view.filtersOpen) return;
    // Each select offers only values present in the list, so no choice
    // returns nothing.
    grid.innerHTML = FILTERS.map(f => {
      const values = [...new Set(list.map(f.of).filter(Boolean))].sort((a, b) => a.localeCompare(b));
      if (values.length < 2 && !view.filters[f.key]) return "";
      return `<label class="dl-filter"><span>${escapeHtml(f.label)}</span>
        <select data-dl-filter="${escapeHtml(f.key)}"><option value="">Select…</option>${values.map(v =>
          `<option value="${escapeHtml(v)}"${view.filters[f.key] === v ? " selected" : ""}>${escapeHtml(f.label2 ? f.label2(v) : v)}</option>`).join("")}</select></label>`;
    }).join("") + (active ? `<button type="button" class="dl-link" data-dl-fclear>Clear filters</button>` : "");
    grid.querySelectorAll("[data-dl-filter]").forEach(s => s.addEventListener("change", () => {
      view.filters[s.dataset.dlFilter] = s.value; saveView(); render();
    }));
    grid.querySelector("[data-dl-fclear]")?.addEventListener("click", () => { view.filters = {}; saveView(); render(); });
  }

  function renderTable() {
    const { inTab, shown } = shownRows();
    $("[data-dl-count]").innerHTML = `<strong>${escapeHtml(shown.length.toLocaleString())}</strong> of <strong>${escapeHtml(inTab.length.toLocaleString())}</strong> Items`;
    $("[data-dl-thead]").innerHTML = COLUMNS.map(c => {
      const on = view.sort.key === c.key;
      return `<th${on ? ` aria-sort="${view.sort.dir > 0 ? "ascending" : "descending"}"` : ""}><button type="button" class="dl-sort" data-dl-sort="${escapeHtml(c.key)}"${on ? ` data-dir="${view.sort.dir > 0 ? "asc" : "desc"}"` : ""}>${escapeHtml(c.label)}</button></th>`;
    }).join("");
    $("[data-dl-thead]").querySelectorAll("[data-dl-sort]").forEach(b => b.addEventListener("click", () => {
      const k = b.dataset.dlSort;
      view.sort = view.sort.key === k ? { key: k, dir: -view.sort.dir } : { key: k, dir: k === "started" || k === "complete" || k === "endpoints" ? -1 : 1 };
      saveView(); renderTable();
    }));
    const body = $("[data-dl-body]");
    if (!shown.length) {
      const msg = inTab.length ? "No deployments match these filters."
        : tab === "active" ? "Nothing is running right now." : (opts.emptyText || "No deployments yet.");
      body.innerHTML = `<tr><td class="dl-empty" colspan="${COLUMNS.length}">${escapeHtml(msg)}</td></tr>`;
      return;
    }
    body.innerHTML = shown.map(d => {
      const b = deploymentBreakdown(d);
      const pct = b.total ? Math.round(b.by.complete * 100 / b.total) : 0;
      return `
      <tr data-dl-open="${escapeHtml(d.id)}">
        <td class="dl-id" title="${escapeHtml(d.id)}">${escapeHtml(shortRunID(d.id))}</td>
        <td class="dl-name-cell">
          <a class="dl-name" href="?run=${encodeURIComponent(d.id)}${escapeHtml(location.hash)}" data-dl-link="${escapeHtml(d.id)}">${escapeHtml(d.title || opts.title)}</a>
          ${d.target && d.target !== d.title ? `<div class="dl-sub">${escapeHtml(d.target)}</div>` : ""}
          ${deploymentBarHtml(d)}
        </td>
        <td class="dl-nowrap">${escapeHtml(kindLabel(d.kind))}</td>
        <td class="dl-by">${escapeHtml(d.by || "—")}</td>
        <td class="dl-num" data-sort="${escapeHtml(String(b.by.complete))}">${escapeHtml(String(b.by.complete))} <span class="dl-muted">(${escapeHtml(String(pct))}%)</span></td>
        <td class="dl-num">${escapeHtml(String(b.total || "—"))}</td>
        <td class="dl-nowrap" title="${escapeHtml(d.started_at ? fmtAgo(d.started_at) : "")}">${d.started_at ? escapeHtml(fmtTime(d.started_at)) : "—"}</td>
        <td>${deploymentStatusPill(d.status)}</td>
      </tr>`;
    }).join("");
    body.querySelectorAll("[data-dl-link]").forEach(a => a.addEventListener("click", e => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button) return;
      e.preventDefault(); open(a.dataset.dlLink);
    }));
  }

  function render() {
    renderHead();
    renderFilters();
    renderTable();
    // The list keeps itself current: every LIST_POLL_MS while anything is
    // running, every IDLE_POLL_MS otherwise, so a deployment started
    // elsewhere appears without a reload. Only while it is on screen.
    if (!listTimer) listTimer = setInterval(() => {
      if (document.hidden || listEl.hidden || root.offsetParent === null) return;
      const age = Date.now() - lastLoaded;
      const running = list.some(d => deploymentActive(d.status));
      if (age >= (running ? LIST_POLL_MS : IDLE_POLL_MS)) reload();
      else paintUpdated();
    }, 5000);
  }

  function paintUpdated() {
    const el = $("[data-dl-updated]");
    if (!el || !lastLoaded) return;
    const secs = Math.round((Date.now() - lastLoaded) / 1000);
    el.textContent = secs < 5 ? "Updated just now" : `Updated ${secs < 60 ? secs + "s" : Math.round(secs / 60) + "m"} ago`;
  }

  $("[data-dl-ftoggle]").addEventListener("click", () => { view.filtersOpen = !view.filtersOpen; saveView(); renderFilters(); });
  $("[data-dl-refresh]").addEventListener("click", () => reload());
  $("[data-dl-q]").addEventListener("input", e => { view.q = e.target.value.trim().toLowerCase(); renderTable(); });
  $("[data-dl-export]").addEventListener("click", () => {
    const { shown } = shownRows();
    const lines = [csvRow(["ID", "Name", "Targeted", "Type", "Category", "Created By", "Complete", "Failed", "Endpoints", "Start Time", "Status"])];
    for (const d of shown) {
      const b = deploymentBreakdown(d);
      lines.push(csvRow([d.id, d.title || opts.title, d.target || "", d.kind || "", d.category || "", d.by || "", b.by.complete, b.by.error, d.total || 0, d.started_at || "", d.status || ""]));
    }
    downloadText(`${P}-deployments.csv`, lines.join("\n"), "text/csv");
  });

  let lastLoaded = 0;
  async function reload() {
    const btn = $("[data-dl-refresh]");
    btn?.classList.add("spinning");
    try {
      list = await opts.load();
    } catch (e) {
      return; // keep what is on screen; the next poll or visit tries again
    } finally {
      btn?.classList.remove("spinning");
    }
    lastLoaded = Date.now();
    render();
    paintUpdated();
  }

  // --- one deployment ---------------------------------------------------------
  function stopLive() {
    if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
    liveID = null;
  }

  function setRunParam(id) {
    const u = new URL(location.href);
    if (id) u.searchParams.set("run", id); else u.searchParams.delete("run");
    history.replaceState(null, "", u);
  }

  async function open(id) {
    stopLive();
    liveID = id;
    groupPick = "";
    setRunParam(id);
    listEl.hidden = true;
    detailEl.hidden = false;
    detailEl.innerHTML = `<div data-dv-body>${crumbHtml(id)}<p class="dl-empty">loading…</p></div><div data-dv-extra></div>`;
    wireCrumb();
    root.scrollIntoView({ block: "start" });
    await refresh(id);
  }

  // The page re-renders [data-dv-body] while live; [data-dv-extra] belongs
  // to the hosting page (a console viewer) and survives those refreshes.
  const bodyEl = () => detailEl.querySelector("[data-dv-body]") || detailEl;
  const extraEl = () => detailEl.querySelector("[data-dv-extra]");

  function crumbHtml(title) {
    return `<nav class="dv-crumb" aria-label="Breadcrumb"><a href="#" data-dv-back>Deployments</a><span aria-hidden="true">›</span><span class="dv-crumb-here">${escapeHtml(title)}</span></nav>`;
  }
  function wireCrumb() {
    detailEl.querySelector("[data-dv-back]")?.addEventListener("click", e => { e.preventDefault(); close(); });
  }

  async function refresh(id) {
    let data;
    try {
      data = await opts.loadDetail(id);
    } catch (e) {
      // A blip while polling should not wipe the page out from under
      // someone reading it.
      if (!liveTimer) { bodyEl().innerHTML = `${crumbHtml(id)}<p class="dl-empty">${escapeHtml(e.message)}</p>`; wireCrumb(); }
      return;
    }
    if (liveID !== id) return; // moved on while this was in flight
    liveSince = new Date();
    renderDetail(data.deployment, data.devices || []);

    const running = deploymentActive(data.deployment.status);
    if (running && !liveTimer) {
      liveTimer = setInterval(() => refresh(id), LIVE_POLL_MS);
    } else if (!running && liveTimer) {
      clearInterval(liveTimer);
      liveTimer = null;
      reload(); // the list's status is now stale
    }
  }

  function renderDetail(d, devices) {
    const running = deploymentActive(d.status);
    const total = d.total || 0;

    // Bucket the endpoints, keeping an unknown status visible rather than
    // silently dropping a machine off the page.
    const buckets = new Map(DEPLOYMENT_STATUS_GROUPS.map(g => [g.key, []]));
    const other = [];
    devices.forEach(a => {
      const g = deploymentGroupFor(a.status);
      if (g) buckets.get(g.key).push(a); else other.push(a);
    });
    const notYet = Math.max(0, total - devices.length);
    const stages = [
      ...DEPLOYMENT_STATUS_GROUPS.map(g => ({ key: g.key, label: g.label, hint: g.hint, n: buckets.get(g.key).length, color: DEPLOYMENT_GROUP_COLORS[g.key] })),
      ...(other.length ? [{ key: "other", label: "Other", hint: "A status this console does not group", n: other.length, color: "var(--viz-none)" }] : []),
      { key: "", label: "Not Reported", hint: "Targeted; nothing reported yet", n: notYet, color: "var(--surface-3)" },
    ];
    const denom = Math.max(total, devices.length, 1);
    const pctOfTotal = n => `${Math.round(n * 100 / denom)}%`;

    const deviceLinkHtml = a => {
      const link = opts.deviceLink && opts.deviceLink(a, d);
      return link ? `<a class="dd-device-link" href="${escapeHtml(safeUrl(link.href))}">${escapeHtml(link.label)}</a>` : "";
    };
    const hasActions = typeof opts.deviceActions === "function";
    const deviceTable = rows => `
      <div class="dv-scroll"><table class="dv-table">
        <thead><tr><th>Endpoint</th><th>Status</th><th>Detail</th><th>Finished</th>${hasActions ? "<th></th>" : ""}</tr></thead>
        <tbody>${rows.map(a => `
          <tr>
            <td class="dv-strong">${escapeHtml(a.name || "—")} ${deviceLinkHtml(a)}${a.warning ? `<div class="dv-dev-warn">${escapeHtml(a.warning)}</div>` : ""}</td>
            <td>${deploymentStatusPill(a.status, a.detail)}</td>
            <td>${a.detail ? `<details class="dd-output"><summary>${escapeHtml(a.detail.split("\n")[0].slice(0, 90))}</summary><div class="dd-output-text">${escapeHtml(a.detail)}</div></details>` : '<span class="dl-muted">—</span>'}</td>
            <td class="dl-nowrap">${a.finished_at ? escapeHtml(fmtTime(a.finished_at)) : "—"}</td>
            ${hasActions ? `<td class="dv-actions">${(opts.deviceActions(a, d) || []).map((b, i) =>
              `<button type="button" class="dl-btn${b.danger ? " dv-danger" : ""}" data-dv-act="${escapeHtml(a.id || "")}" data-dv-act-i="${i}">${escapeHtml(b.label)}</button>`).join("")}</td>` : ""}
          </tr>`).join("")}</tbody>
      </table></div>`;

    // Re-rendered every few seconds while live: a section someone opened or
    // closed stays that way.
    const wasOpen = new Map([...detailEl.querySelectorAll("details[data-dv-sec]")].map(el => [el.dataset.dvSec, el.open]));
    const wasGroup = new Set([...detailEl.querySelectorAll("details.dd-group[open]")].map(el => el.dataset.group));
    const firstRender = !detailEl.querySelector("details[data-dv-sec]");
    const secOpen = (key, dflt) => wasOpen.has(key) ? wasOpen.get(key) : dflt;
    const groupOpen = key => key === groupPick || wasGroup.has(key) || (firstRender && (key === "error" || devices.length <= 1));

    const tone = t => t === "ok" ? "var(--ok)" : t === "bad" ? "var(--off)" : "var(--accent)";
    const groupsHtml = DEPLOYMENT_STATUS_GROUPS.map(g => {
      const rows = buckets.get(g.key);
      if (!rows.length) return "";
      return `
        <details class="dd-group" data-group="${escapeHtml(g.key)}" ${groupOpen(g.key) ? "open" : ""}>
          <summary><span${sx(`color:${tone(g.tone)}`)}>${escapeHtml(g.label)}</span>
            <span class="dd-group-hint">${escapeHtml(g.hint)}</span><span class="dd-group-count">${escapeHtml(rows.length)}</span></summary>
          <div>${deviceTable(rows)}</div>
        </details>`;
    }).join("") + (other.length ? `
        <details class="dd-group" data-group="other" ${groupOpen("other") ? "open" : ""}>
          <summary><span>Other</span><span class="dd-group-count">${escapeHtml(other.length)}</span></summary>
          <div>${deviceTable(other)}</div>
        </details>` : "");

    // Failures collapsed by message: twenty machines failing the same way
    // is one problem to fix, not twenty.
    const errs = new Map();
    devices.filter(a => ["failed", "timed_out", "no_response", "expired"].includes(a.status)).forEach(a => {
      const key = (a.detail || "(no detail reported)").split("\n")[0].slice(0, 160);
      if (!errs.has(key)) errs.set(key, []);
      errs.get(key).push(a.name || "—");
    });
    const errEndpoints = [...errs.values()].reduce((n, h) => n + h.length, 0);
    const complete = buckets.get("complete").length;
    const warned = devices.filter(a => a.warning);
    const lastFinished = devices.map(a => a.finished_at).filter(Boolean).sort().pop();

    const field = (label, value, cls) => `<div class="dv-field"><div class="dv-label">${escapeHtml(label)}</div><div class="dv-value ${escapeHtml(cls || "")}">${/* safe-html: every caller passes escapeHtml()ed text or pill markup */ value}</div></div>`;
    const sec = (key, title, body, dflt = true) => `
      <details class="dv-card" data-dv-sec="${escapeHtml(key)}" ${secOpen(key, dflt) ? "open" : ""}>
        <summary><span>${escapeHtml(title)}</span><svg class="dv-chev" viewBox="0 0 10 10" aria-hidden="true"><path d="M3 2l4 3-4 3z" fill="currentColor"/></svg></summary>
        <div class="dv-card-body">${/* safe-html: section bodies are built from escaped fields above */ body}</div>
      </details>`;

    const body = bodyEl();
    body.innerHTML = `
      ${crumbHtml(d.title || opts.title)}
      ${warned.length ? `<div class="dv-warn" role="status">${escapeHtml(warned.length === 1
        ? `${warned[0].name || "One endpoint"} has stopped checking in while its job is still open. If this was an agent update, the update may have taken the agent with it.`
        : `${warned.length} endpoints have stopped checking in while their jobs are still open. If these were agent updates, the updates may have taken those agents with them.`)}</div>` : ""}
      <div class="dv-head">
        <div>
          <h1>${escapeHtml(d.title || opts.title)}</h1>
          <div class="dv-id">ID <span class="id-bare">${escapeHtml(d.id)}</span></div>
        </div>
        <div class="dv-head-actions">
          <button type="button" class="dl-btn dl-icon-btn" data-dv-refresh title="Refresh now" aria-label="Refresh this deployment">${icon("sync")}</button>
          <button type="button" class="dl-btn" data-dv-export>Export results</button>
          <button type="button" class="dl-btn" data-dv-back2>Back to list</button>
        </div>
      </div>

      <div class="dv-scope">
        <div class="dv-scope-ic">${icon("deploy") || icon("rocket")}</div>
        <div class="dv-scope-main">
          <div class="dv-label">Deployment Scope</div>
          <div class="dv-scope-text">${escapeHtml(d.title || opts.title)}${d.target && d.target !== d.title ? ` <span class="dl-muted">on</span> ${escapeHtml(d.target)}` : ""} <span class="dl-muted">· ${escapeHtml(String(total))} endpoint${total === 1 ? "" : "s"}</span></div>
        </div>
        <div class="dv-scope-side">
          ${field("Type", escapeHtml(kindLabel(d.kind)))}
          ${field("Status", deploymentStatusPill(d.status) + (running ? ` <span class="dd-live"><span class="dd-live-dot"></span>live</span>` : ""))}
        </div>
      </div>

      <h2 class="dv-h2">${icon("chart")} Status</h2>
      <section class="dv-panel">
        <div class="dv-panel-title">Deployment Progress on Endpoints
          <span class="dl-muted">${escapeHtml(String(complete))} of ${escapeHtml(String(total || "?"))} complete${running ? ` · refreshing every ${LIVE_POLL_MS / 1000}s` : ""}</span></div>
        <div class="dv-progress">${stages.filter(s => s.n > 0).map(s =>
          `<button type="button" class="dv-seg"${sx(`flex:${String(s.n)};background:${s.color}`)} title="${escapeHtml(`${s.label}: ${s.n} (${pctOfTotal(s.n)})`)}" aria-label="${escapeHtml(`${s.label}: ${s.n}`)}"${s.key ? ` data-dv-pick="${escapeHtml(s.key)}"` : " disabled"}></button>`).join("") || '<div class="dv-seg u-flex-1 u-bg-surface-3"></div>'}</div>
        <div class="dv-stages">${stages.map(s => `
          <button type="button" class="dv-stage"${sx(`--stage:${s.color}`)} title="${escapeHtml(s.hint)}"${s.key && s.n ? ` data-dv-pick="${escapeHtml(s.key)}"` : " disabled"}>
            <span class="dv-stage-n">${escapeHtml(String(s.n))} <span class="dl-muted">(${escapeHtml(pctOfTotal(s.n))})</span></span>
            <span class="dv-stage-label">${escapeHtml(s.label)}</span>
          </button>`).join("")}</div>
        <div class="dv-reporting"><span class="dv-label">Reporting</span>
          <button type="button" class="dv-chip" data-dv-jump="results">Results by Endpoint</button>
          <button type="button" class="dv-chip" data-dv-jump="errors"${errs.size ? "" : " disabled"}>Error Summary</button>
          <button type="button" class="dv-chip" data-dv-jump="details">Deployment Details</button>
        </div>
      </section>

      <div class="dv-meta">
        ${field("Status Updated", escapeHtml(liveSince ? fmtTime(liveSince.toISOString()) : "—"))}
        ${field("Issued By", escapeHtml(d.by || "unknown"))}
        ${field("Issued On", escapeHtml(d.started_at ? fmtTime(d.started_at) : "—"))}
        ${field("Last Result", escapeHtml(lastFinished ? fmtTime(lastFinished) : "—"))}
        ${field("Endpoints Reported", escapeHtml(`${devices.length} of ${total || "?"}`))}
      </div>

      <section class="dv-panel" data-dv-anchor="errors">
        <div class="dv-panel-title">Deployment Errors</div>
        <div class="dv-meta dv-meta-tight">
          ${field("Errors", escapeHtml(String(errs.size)), errs.size ? "dv-bad" : "")}
          ${field("Total Endpoints with Errors", escapeHtml(String(errEndpoints)), errEndpoints ? "dv-bad" : "")}
        </div>
        ${errs.size ? `<div class="dv-scroll"><table class="dv-table">
          <thead><tr><th>Message</th><th>Endpoints</th></tr></thead>
          <tbody>${[...errs.entries()].map(([msg, hosts]) => `
            <tr><td><code class="dv-code">${escapeHtml(msg)}</code></td>
                <td class="dl-nowrap">${escapeHtml(hosts.length)} <details class="dd-output"><summary>which</summary><div>${hosts.map(escapeHtml).join(", ")}</div></details></td></tr>`).join("")}</tbody>
        </table></div>` : ""}
      </section>

      <div class="dv-section-head" data-dv-anchor="details"><h2 class="dv-h2">Deployment Details</h2><button type="button" class="dl-link" data-dv-expand>Expand all</button></div>
      ${sec("content", "Content to Deploy", `<div class="dv-meta dv-meta-tight">
          ${field("Name", escapeHtml(d.title || opts.title))}
          ${field("Content", escapeHtml(({ patch: "Patches", software: "Software", playbook: "Playbook", other: "Other" })[d.category] || d.category || opts.title))}
          ${field("Type", escapeHtml(kindLabel(d.kind)))}
          ${field("Run ID", `<code class="dv-code">${escapeHtml(d.id)}</code>`)}
        </div>`)}
      ${sec("targets", "Endpoints to Target", `
        <div class="dv-sub">Target Summary</div>
        <div class="dv-meta dv-meta-tight">
          ${field("Endpoints Targeted", escapeHtml(String(total)))}
          ${field("Reported", escapeHtml(String(devices.length)))}
          ${field("Complete", escapeHtml(`${pctOfTotal(complete)} complete`))}
        </div>
        <div class="dv-sub">Targets</div>
        <div class="dv-targets"><span class="dv-chip dv-chip-static">${escapeHtml(d.target || "—")}</span></div>`)}
      ${(d.facts && d.facts.length) ? sec("more", "Deployment Settings", `<div class="dv-meta dv-meta-tight">${d.facts.map(([k, v]) => field(k, escapeHtml(String(v)))).join("")}</div>`) : ""}
      <div data-dv-anchor="results">${sec("results", `Results by Endpoint (${devices.length})`,
        devices.length === 0
          ? `<p class="dl-muted">No endpoint has reported back yet. ${d.status === "no response"
              ? "The targeted agents were most likely offline when this went out."
              : "Results appear here as each one finishes."}</p>`
          : groupsHtml)}</div>`;

    wireCrumb();
    body.querySelectorAll("[data-dv-act]").forEach(btn => btn.addEventListener("click", () => {
      const dev = devices.find(a => (a.id || "") === btn.dataset.dvAct);
      const action = dev && (opts.deviceActions(dev, d) || [])[Number(btn.dataset.dvActI)];
      if (action) action.onClick(dev, d, extraEl());
    }));
    detailEl.querySelector("[data-dv-back2]").addEventListener("click", close);
    detailEl.querySelector("[data-dv-refresh]").addEventListener("click", () => refresh(d.id));
    detailEl.querySelectorAll("[data-dv-pick]").forEach(b => b.addEventListener("click", () => {
      groupPick = b.dataset.dvPick;
      const results = detailEl.querySelector('details[data-dv-sec="results"]');
      if (results) results.open = true;
      renderDetail(d, devices);
      const el = detailEl.querySelector(`details.dd-group[data-group="${groupPick}"]`);
      if (el) { el.open = true; el.scrollIntoView({ behavior: "smooth", block: "start" }); }
    }));
    detailEl.querySelectorAll("[data-dv-jump]").forEach(b => b.addEventListener("click", () => {
      const target = detailEl.querySelector(`[data-dv-anchor="${b.dataset.dvJump}"]`);
      const inner = target && target.querySelector("details[data-dv-sec]");
      if (inner) inner.open = true;
      if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
    }));
    // The button names what it will do next, from the sections' real state.
    const expandBtn = detailEl.querySelector("[data-dv-expand]");
    const cards = [...detailEl.querySelectorAll("details[data-dv-sec]")];
    const syncExpand = () => { expandBtn.textContent = cards.some(c => !c.open) ? "Expand all" : "Collapse all"; };
    cards.forEach(c => c.addEventListener("toggle", syncExpand));
    syncExpand();
    expandBtn.addEventListener("click", () => {
      const openAll = cards.some(c => !c.open);
      cards.forEach(c => { c.open = openAll; });
      syncExpand();
    });
    detailEl.querySelector("[data-dv-export]").addEventListener("click", () => {
      const lines = [csvRow(["Endpoint", "Status", "Detail", "Finished"])];
      for (const a of devices) lines.push(csvRow([a.name || "", a.status || "", a.detail || "", a.finished_at || ""]));
      downloadText(`deployment-${d.id}.csv`, lines.join("\n"), "text/csv");
    });
  }

  function close() {
    stopLive();
    setRunParam("");
    detailEl.hidden = true;
    detailEl.innerHTML = "";
    listEl.hidden = false;
  }
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && !detailEl.hidden && !e.target.closest?.("input,textarea,select")) close();
  });

  // ?run=<id> opens that deployment, so one can be linked to rather than
  // found by scrolling.
  function openLinked() {
    const id = new URLSearchParams(window.location.search).get("run");
    if (id) open(id);
  }

  return { reload, open, openLinked, render, refreshOpen: () => liveID && refresh(liveID), slot: extraEl };
}

// Run IDs are long and random; the list shows enough to tell them apart,
// with the whole ID in the cell's tooltip and on the deployment's page.
function shortRunID(id) {
  const s = String(id || "");
  const m = /^([a-z]+)-([0-9a-f]{6})[0-9a-f]+$/.exec(s);
  return m ? `${m[1]}-${m[2]}` : s;
}

// kindLabel: "single device" reads as a sentence fragment in a column;
// capitalise it, and say "—" rather than leave the cell empty.
function kindLabel(k) {
  const s = String(k || "").trim();
  return s ? s[0].toUpperCase() + s.slice(1) : "—";
}

function downloadText(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: type || "text/plain" }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// The patch and software deployments API, shaped for the dashboard. Both
// pages read /api/patches/deployments: a software install is a deployment
// like any other, and only the list differs.
function runDeploymentFromAPI(d, fallbackTitle) {
  const outcomes = d.outcomes || {};
  return {
    id: d.id,
    title: d.schedule_name || fallbackTitle,
    target: d.target_desc,
    kind: d.kind,
    started_at: d.started_at,
    by: d.triggered_by,
    total: d.agent_count || 0,
    reported: Object.values(outcomes).reduce((a, b) => a + b, 0),
    status: d.status,
    failing: (outcomes.failed || 0) > 0 || (outcomes.timed_out || 0) > 0 || (outcomes.no_response || 0) > 0,
    category: d.category,
    outcomes: d.outcomes || {},
    consoleOutput: !!d.console_output,
  };
}

async function loadRunDeployments(filter, fallbackTitle) {
  const resp = await fetch("/api/patches/deployments");
  if (!resp.ok) throw new Error(await resp.text());
  const all = (await resp.json()).deployments || [];
  return all.filter(filter || (() => true)).map(d => runDeploymentFromAPI(d, fallbackTitle));
}

async function loadRunDeploymentDetail(id, fallbackTitle) {
  const resp = await fetch(`/api/patches/deployments/${encodeURIComponent(id)}`);
  if (!resp.ok) throw new Error(await resp.text() || "could not load this deployment");
  const data = await resp.json();
  return {
    deployment: runDeploymentFromAPI(data.deployment, fallbackTitle),
    devices: (data.devices || []).map(a => ({
      id: a.id, name: a.hostname || a.agent_id, status: a.status, detail: a.detail, finished_at: a.finished_at,
    })),
  };
}
