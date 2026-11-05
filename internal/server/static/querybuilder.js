// Query Builder: Interact's query, assembled from pickers instead of typed.
//
// It writes the same "get … from all machines with …" text the query box
// takes, and running it hands that text to the query box, so there is one
// parser and one results grid. What it adds is the vocabulary: every
// sensor and its fields, searchable by name, the operators each field
// supports, and groups for "(A or B) and C" without remembering brackets.
//
// mountQueryBuilder(root, { fields, recordSelect, onRun }) draws it into
// root. fields is the catalog from /api/interact/saved; recordSelect the
// query box's Result view select, whose options it copies; onRun(text,
// { record, sameRow }) runs the query and onSave(text, extra) saves it. The returned
// object's load(get, rules, all) fills it from a parsed query.

(function () {
  "use strict";

  // Catalog operator → how it reads. The text uses the catalog's own names
  // (gt, regex), which the query box accepts as typed.
  const OP_LABELS = {
    equals: "equals", not_equals: "does not equal", contains: "contains", not_contains: "does not contain",
    starts_with: "starts with", ends_with: "ends with", regex: "matches regex",
    in: "is one of (a,b,c)", not_in: "is none of (a,b,c)",
    gt: "greater than", gte: "at least", lt: "less than", lte: "at most",
    exists: "has a value", not_exists: "has no value",
  };
  const NO_VALUE = new Set(["exists", "not_exists"]);
  const MAX_DEPTH = 3;
  const HIDE_KEY = "mustra-qb-hide-text";

  // The sensor a field belongs to, and what to call it. Inventory fields
  // (hostname, os, …) have no sensor; custom sensors carry their name in
  // the label ("Pending reboot · value").
  function sensorOf(f) {
    const i = f.field.indexOf(".");
    if (i < 0) return { key: "", name: "Endpoint" };
    const key = f.field.slice(0, i);
    if (key.startsWith("custom_")) return { key, name: (f.label.split(" · ")[0] || key) + " (custom)" };
    const name = key.replace(/_/g, " ");
    return { key, name: name.charAt(0).toUpperCase() + name.slice(1) };
  }

  function quoteValue(op, v) {
    v = String(v || "").trim();
    if (op === "in" || op === "not_in") return v.split(",").map(s => s.trim()).filter(Boolean).join(",");
    return /[\s()]/.test(v) || /^(and|or)$/i.test(v) ? `"${v.replace(/"/g, "")}"` : v;
  }

  // splitGetEntry reads "field[op value][op value]" back into a row.
  function splitGetEntry(entry) {
    const i = entry.indexOf("[");
    const field = (i < 0 ? entry : entry.slice(0, i)).trim();
    const filters = [];
    // Scanned by hand: a regular expression that lets a quote be either the start
    // of a string or an ordinary character backtracks exponentially on "[!""""…".
    let pos = i;
    while (pos >= 0 && pos < entry.length) {
      const open = entry.indexOf("[", pos);
      if (open < 0) break;
      const filter = readFilter(entry, open + 1);
      if (!filter) { pos = open + 1; continue; }
      const op = OP_ALIAS[filter.op] || filter.op;
      filters.push({ field, op, value: filter.value.trim().replace(/^"(.*)"$/, "$1") });
      pos = filter.end;
    }
    return { field, filters };
  }
  // readFilter reads "op value]" from position p. A "]" inside quotes is part of
  // the value, and a quote with no partner is an ordinary character.
  function readFilter(s, p) {
    while (p < s.length && /\s/.test(s[p])) p++;
    const opStart = p;
    while (p < s.length && !/\s/.test(s[p]) && s[p] !== "]") p++;
    const op = s.slice(opStart, p);
    if (!op) return null;
    while (p < s.length && /\s/.test(s[p])) p++;
    let value = "";
    while (p < s.length) {
      if (s[p] === "]") return { op, value, end: p + 1 };
      const close = s[p] === '"' ? s.indexOf('"', p + 1) : -1;
      const next = close > 0 ? close + 1 : p + 1;
      value += s.slice(p, next);
      p = next;
    }
    return null;
  }
  const OP_ALIAS = { greater_than: "gt", less_than: "lt", matches_regex: "regex" };

  function mountQueryBuilder(root, opts) {
    const fields = opts.fields || [];
    const byField = new Map(fields.map(f => [f.field, f]));
    const sensors = [];
    for (const f of fields) {
      const s = sensorOf(f);
      let entry = sensors.find(x => x.key === s.key);
      if (!entry) { entry = { key: s.key, name: s.name, fields: [] }; sensors.push(entry); }
      entry.fields.push(f);
    }

    const newRow = () => ({ type: "row", field: "", op: "equals", value: "" });
    let state;
    const reset = () => {
      state = { get: [{ field: "", filters: [] }], where: { type: "group", all: true, items: [] } };
    };
    reset();

    root.innerHTML = `
      <div class="qbp">
        <div class="qbp-main">
          <div class="qbp-h"><span>Get the following data</span></div>
          <div class="qbp-get" data-get></div>
          <button class="tiny" type="button" data-add-get>+ Add row</button>
          <div class="qbp-h"><span>from all machines with</span></div>
          <div class="qbp-where" data-where></div>
          <details class="qbp-adv">
            <summary>Advanced query options</summary>
            <div class="qbp-adv-body">
              <label>Result view <select class="select" data-record></select></label>
              <label class="qbp-check"><input type="checkbox" data-same-row> Conditions on one sensor must match the same record
                (for example the same installed app's name <i>and</i> version)</label>
              <label class="qbp-check"><input type="checkbox" data-live> Ask live: get processes, services, installed apps and patches from the online endpoints now (up to 20 seconds) instead of the cache</label>
            </div>
          </details>
        </div>
        <button class="qbp-toggle" type="button" data-toggle aria-expanded="true"><span>Hide query text</span></button>
        <div class="qbp-side" data-side><pre class="qbp-text" data-text></pre><p class="qbp-problem" data-problem></p></div>
      </div>
      <div class="qbp-actions">
        <button class="primary" type="button" data-run>Run query</button>
        <button class="secondary" type="button" data-save>Save query</button>
        <button class="secondary" type="button" data-reset>Reset</button>
        <a href="#" class="qbp-copy" data-copy>Copy query to clipboard</a>
      </div>`;
    const $ = sel => root.querySelector(sel);
    // The Result view choices are the query box's own, copied as nodes.
    const copyRecords = from => {
      const sel = $("[data-record]"), prev = sel.value;
      sel.replaceChildren(...[...from.options].map(o => o.cloneNode(true)));
      sel.value = prev;
    };
    if (opts.recordSelect) copyRecords(opts.recordSelect);

    // --- the field picker: type to filter, grouped by sensor -----------
    function fieldPicker(value, onPick, placeholder) {
      const box = document.createElement("div");
      box.className = "qbp-pick";
      const input = document.createElement("input");
      input.className = "search-input";
      input.placeholder = placeholder || "Filter by name…";
      input.autocomplete = "off";
      input.spellcheck = false;
      input.setAttribute("aria-label", placeholder || "Field");
      const spec = byField.get(value);
      input.value = spec ? spec.label : value;
      if (spec) input.title = spec.field;
      const list = document.createElement("div");
      list.className = "qbp-pick-list";
      list.setAttribute("role", "listbox");
      box.append(input, list);
      let active = -1, shown = [];
      const draw = () => {
        const q = input.value.trim().toLowerCase();
        const exact = byField.get(value);
        const all = !q || (exact && input.value === exact.label);
        const html = [];
        shown = [];
        for (const s of sensors) {
          const hits = s.fields.filter(f => all || f.label.toLowerCase().includes(q) || f.field.toLowerCase().includes(q) || s.name.toLowerCase().includes(q));
          if (!hits.length) continue;
          html.push(`<div class="qbp-pick-group">${escapeHtml(s.name)}</div>`);
          for (const f of hits) {
            html.push(`<div class="qbp-pick-item${f.field === value ? " sel" : ""}" role="option" data-i="${escapeHtml(String(shown.length))}"><span>${escapeHtml(f.label)}</span><code>${escapeHtml(f.field)}</code></div>`);
            shown.push(f);
          }
        }
        list.innerHTML = html.join("") || '<div class="qbp-pick-none">No field matches — try Browse all sensors.</div>';
        active = -1;
      };
      let picked = false;
      const open = () => { draw(); box.classList.add("open"); };
      const close = () => { box.classList.remove("open"); };
      const pick = f => { picked = true; close(); onPick(f.field); };
      input.addEventListener("focus", () => { input.select(); open(); });
      input.addEventListener("input", open);
      input.addEventListener("keydown", e => {
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          if (!box.classList.contains("open")) open();
          active = Math.max(0, Math.min(shown.length - 1, active + (e.key === "ArrowDown" ? 1 : -1)));
          list.querySelectorAll(".qbp-pick-item").forEach((el, i) => el.classList.toggle("active", i === active));
          list.querySelector(".qbp-pick-item.active")?.scrollIntoView({ block: "nearest" });
        } else if (e.key === "Enter") {
          e.preventDefault();
          const f = shown[active >= 0 ? active : 0];
          if (f) pick(f);
        } else if (e.key === "Escape") { close(); input.blur(); }
      });
      // mousedown, not click: the input's blur would close the list first.
      list.addEventListener("mousedown", e => {
        const item = e.target.closest(".qbp-pick-item");
        if (!item) return;
        e.preventDefault();
        pick(shown[+item.dataset.i]);
      });
      input.addEventListener("blur", () => setTimeout(() => {
        close();
        if (picked) return;
        // Typing a field's name exactly picks it; anything else snaps back.
        const typed = input.value.trim().toLowerCase();
        const f = fields.find(x => x.label.toLowerCase() === typed || x.field.toLowerCase() === typed);
        if (f && f.field !== value) onPick(f.field);
        else { const cur = byField.get(value); input.value = cur ? cur.label : ""; }
      }, 120));
      return box;
    }

    // Browse all sensors: every sensor and its fields, with what each one
    // holds, for when the name to search for is not obvious.
    function browse(onPick) {
      openModal("Browse all sensors", `
        <input class="search-input qbp-browse-filter" placeholder="Filter sensors and fields…" aria-label="Filter sensors and fields">
        <div class="qbp-browse" data-list></div>`, wrap => {
        wrap.querySelector(".modal").classList.add("qbp-browse-modal");
        const filter = wrap.querySelector(".qbp-browse-filter"), list = wrap.querySelector("[data-list]");
        const draw = () => {
          const q = filter.value.trim().toLowerCase();
          list.innerHTML = sensors.map(s => {
            const hits = s.fields.filter(f => !q || s.name.toLowerCase().includes(q) || f.label.toLowerCase().includes(q) || f.field.toLowerCase().includes(q) || (f.hint || "").toLowerCase().includes(q));
            if (!hits.length) return "";
            return `<details class="qbp-browse-sensor"${q ? " open" : ""}><summary>${escapeHtml(s.name)} <span class="hint">${escapeHtml(String(hits.length))} field${hits.length === 1 ? "" : "s"}</span></summary>
              ${hits.map(f => `<button type="button" class="qbp-browse-field" data-field="${escapeHtml(f.field)}">
                <span class="l">${escapeHtml(f.label)}</span><code>${escapeHtml(f.field)}</code>
                <span class="k">${escapeHtml(f.kind)}</span>${f.hint ? `<span class="h">${escapeHtml(f.hint)}</span>` : ""}</button>`).join("")}
            </details>`;
          }).join("") || '<p class="hint">Nothing matches.</p>';
        };
        filter.addEventListener("input", draw);
        list.addEventListener("click", e => {
          const b = e.target.closest(".qbp-browse-field");
          if (!b) return;
          wrap.remove();
          onPick(b.dataset.field);
        });
        draw();
        filter.focus();
      });
    }

    function opsFor(field) {
      const spec = byField.get(field);
      const ops = (spec && spec.ops ? spec.ops : ["equals", "not_equals", "contains", "not_contains"]).filter(o => OP_LABELS[o]);
      return ops.concat(["exists", "not_exists"]).filter((o, i, a) => a.indexOf(o) === i);
    }

    // One condition's operator and value controls, shared by row filters
    // and the where clause.
    function condControls(c) {
      const frag = document.createDocumentFragment();
      const sel = document.createElement("select");
      sel.className = "select qbp-op";
      sel.setAttribute("aria-label", "Operator");
      const ops = opsFor(c.field);
      if (!ops.includes(c.op)) c.op = ops[0];
      sel.innerHTML = ops.map(o => `<option value="${escapeHtml(o)}"${o === c.op ? " selected" : ""}>${escapeHtml(OP_LABELS[o])}</option>`).join("");
      const spec = byField.get(c.field);
      let val;
      if (spec && spec.kind === "bool") {
        val = document.createElement("select");
        val.className = "select qbp-value";
        if (!/^(true|false)$/.test(c.value)) c.value = "true";
        val.innerHTML = ["true", "false"].map(v => `<option${v === c.value ? " selected" : ""}>${escapeHtml(v)}</option>`).join("");
        val.addEventListener("change", () => { c.value = val.value; update(); });
      } else {
        val = document.createElement("input");
        val.className = "search-input qbp-value";
        val.value = c.value;
        val.placeholder = spec && spec.hint ? spec.hint : spec && spec.kind === "number" ? "a number" : "value";
        if (spec && spec.kind === "number") val.inputMode = "decimal";
        val.addEventListener("input", () => { c.value = val.value; update(); });
      }
      val.setAttribute("aria-label", "Value");
      val.hidden = NO_VALUE.has(c.op);
      sel.addEventListener("change", () => { c.op = sel.value; val.hidden = NO_VALUE.has(c.op); update(); });
      frag.append(sel, val);
      return frag;
    }

    function removeButton(label, onClick) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "qbp-x";
      b.textContent = "✕";
      b.title = label;
      b.setAttribute("aria-label", label);
      b.addEventListener("click", onClick);
      return b;
    }

    // A drag handle that reorders arr: rows of Get, or the conditions and
    // groups inside one group. Pointer events rather than HTML5 drag, which
    // Firefox will not start from inside a form and phones do not do.
    function dragHandle(arr, i, redraw) {
      const h = document.createElement("span");
      h.className = "qbp-handle";
      h.textContent = "⠿";
      h.title = "Drag to reorder";
      h.setAttribute("aria-hidden", "true");
      h.addEventListener("pointerdown", e => {
        if (arr.length < 2) return;
        e.preventDefault();
        const item = h.closest("[data-qb-item]");
        const others = [...item.parentElement.children].filter(el => el.hasAttribute("data-qb-item") && el !== item);
        item.classList.add("qbp-dragging");
        h.setPointerCapture(e.pointerId);
        let pos = i;
        const clear = () => others.forEach(el => el.classList.remove("qbp-drop-before", "qbp-drop-after"));
        const move = ev => {
          pos = others.filter(el => { const r = el.getBoundingClientRect(); return r.top + r.height / 2 < ev.clientY; }).length;
          clear();
          if (pos < others.length) others[pos].classList.add("qbp-drop-before");
          else if (others.length) others[others.length - 1].classList.add("qbp-drop-after");
        };
        const end = () => {
          h.removeEventListener("pointermove", move);
          clear();
          item.classList.remove("qbp-dragging");
          if (pos !== i) { const [x] = arr.splice(i, 1); arr.splice(pos, 0, x); }
          redraw();
        };
        h.addEventListener("pointermove", move);
        h.addEventListener("pointerup", end, { once: true });
        h.addEventListener("pointercancel", end, { once: true });
      });
      if (arr.length < 2) h.classList.add("qbp-handle-off");
      return h;
    }

    function link(text, onClick) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "qbp-link";
      b.textContent = text;
      b.addEventListener("click", onClick);
      return b;
    }

    // --- Get rows ------------------------------------------------------
    function drawGet() {
      const box = $("[data-get]");
      box.textContent = "";
      state.get.forEach((row, i) => {
        const card = document.createElement("div");
        card.className = "qbp-card";
        card.dataset.qbItem = "";
        const head = document.createElement("div");
        head.className = "qbp-card-head";
        head.append(dragHandle(state.get, i, drawGet));
        const setField = f => { row.field = f; row.filters.forEach(c => { if (!opsFor(f).includes(c.op)) c.op = opsFor(f)[0]; }); drawGet(); };
        head.append(fieldPicker(row.field, setField, "Filter by name…"),
          link("Browse all sensors", () => browse(setField)),
          removeButton("Remove this row", () => {
            state.get.splice(i, 1);
            if (!state.get.length) state.get.push({ field: "", filters: [] });
            drawGet();
          }));
        card.append(head);
        const spec = byField.get(row.field);
        if (spec && spec.hint) {
          const h = document.createElement("div");
          h.className = "qbp-card-hint";
          h.textContent = spec.hint;
          card.append(h);
        }
        row.filters.forEach((c, j) => {
          const line = document.createElement("div");
          line.className = "qbp-cond qbp-filter";
          const lbl = document.createElement("span");
          lbl.className = "qbp-filter-lbl";
          lbl.textContent = "only values that";
          c.field = row.field;
          line.append(lbl, condControls(c), removeButton("Remove this filter", () => { row.filters.splice(j, 1); drawGet(); }));
          card.append(line);
        });
        if (row.field) card.append(link("+ Add filter", () => { row.filters.push({ field: row.field, op: opsFor(row.field)[0], value: "" }); drawGet(); }));
        box.append(card);
      });
      update();
    }

    // --- the where clause: rows and groups, nested ---------------------
    function drawGroup(g, depth, onRemove) {
      const el = document.createElement("div");
      el.className = depth ? "qbp-group" : "qbp-root";
      if (g.items.length > 1 || depth) {
        const bar = document.createElement("div");
        bar.className = "qbp-join";
        const sel = document.createElement("select");
        sel.className = "select";
        sel.setAttribute("aria-label", "How these conditions combine");
        sel.innerHTML = `<option value="all"${g.all ? " selected" : ""}>Match all of these</option><option value="any"${g.all ? "" : " selected"}>Match any of these</option>`;
        sel.addEventListener("change", () => { g.all = sel.value === "all"; drawWhere(); });
        bar.append(sel);
        if (onRemove) bar.append(removeButton("Remove this group", onRemove));
        el.append(bar);
      }
      if (!g.items.length) {
        const empty = document.createElement("div");
        empty.className = "qbp-empty";
        empty.textContent = depth ? "An empty group matches nothing: add a row." : "Every machine. Add a row or a group to narrow it down.";
        el.append(empty);
      }
      g.items.forEach((item, i) => {
        if (i > 0) {
          const j = document.createElement("div");
          j.className = "qbp-joiner";
          j.textContent = g.all ? "and" : "or";
          el.append(j);
        }
        const remove = () => { g.items.splice(i, 1); drawWhere(); };
        if (item.type === "group") {
          const ge = drawGroup(item, depth + 1, remove);
          ge.dataset.qbItem = "";
          ge.querySelector(".qbp-join").prepend(dragHandle(g.items, i, drawWhere));
          el.append(ge);
          return;
        }
        const line = document.createElement("div");
        line.className = "qbp-cond";
        line.dataset.qbItem = "";
        line.append(dragHandle(g.items, i, drawWhere), fieldPicker(item.field, f => { item.field = f; drawWhere(); }, "Field…"),
          condControls(item), removeButton("Remove this row", remove));
        el.append(line);
      });
      const adds = document.createElement("div");
      adds.className = "qbp-adds";
      const addRow = document.createElement("button");
      addRow.type = "button"; addRow.className = "tiny"; addRow.textContent = "+ Add row";
      addRow.addEventListener("click", () => { g.items.push(newRow()); drawWhere(); });
      adds.append(addRow);
      if (depth < MAX_DEPTH) {
        const addGroup = document.createElement("button");
        addGroup.type = "button"; addGroup.className = "tiny"; addGroup.textContent = "+ Add group";
        addGroup.addEventListener("click", () => { g.items.push({ type: "group", all: !g.all, items: [newRow(), newRow()] }); drawWhere(); });
        adds.append(addGroup);
      }
      el.append(adds);
      return el;
    }
    function drawWhere() {
      const box = $("[data-where]");
      box.textContent = "";
      box.append(drawGroup(state.where, 0, null));
      update();
    }

    // --- the text --------------------------------------------------------
    function condText(c) {
      return NO_VALUE.has(c.op) ? `${c.field} ${c.op}` : `${c.field} ${c.op} ${quoteValue(c.op, c.value)}`;
    }
    function groupText(g, top) {
      const parts = g.items.map(it => it.type === "group" ? (it.items.length ? `(${groupText(it, false)})` : "") : condText(it)).filter(Boolean);
      return parts.join(g.all ? " and " : " or ");
    }
    function problems() {
      const out = [];
      if (!state.get.some(r => r.field)) out.push("Pick at least one field to get.");
      if (state.get.some(r => r.filters.some(c => !NO_VALUE.has(c.op) && !String(c.value).trim()))) out.push("A row filter needs a value.");
      const walk = g => {
        if (!g.items.length && g !== state.where) out.push("A group is empty.");
        for (const it of g.items) {
          if (it.type === "group") walk(it);
          else if (!byField.has(it.field)) out.push("A condition needs a field.");
          else if (!NO_VALUE.has(it.op) && !String(it.value).trim()) out.push(`${byField.get(it.field).label} needs a value.`);
        }
      };
      walk(state.where);
      return [...new Set(out)];
    }
    // A row's filters ride on its field in brackets — "installed_apps.name
    // [contains chrome]" — which trims that sensor's answer to the rows
    // that match, rather than only narrowing the machines.
    function filterText(c) {
      return NO_VALUE.has(c.op) ? `[${c.op}]` : `[${c.op} ${quoteValue(c.op, c.value)}]`;
    }
    function text() {
      const get = [...new Set(state.get.filter(r => r.field).map(r => r.field + r.filters.map(filterText).join("")))];
      let q = `get ${get.join(" and ") || "…"} from all machines`;
      const where = groupText(state.where, true);
      if (where) q += ` with ${where}`;
      return q;
    }
    function update() {
      const t = text();
      const issues = problems();
      // The keywords stand out, as in the query box's examples.
      $("[data-text]").innerHTML = /* safe-html: escaped first; the replacements only add fixed <b> tags */ escapeHtml(t)
        .replace(/^get /, '<b>get</b>\n  ')
        .replace(/ from all machines/, '\n<b>from all machines</b>')
        .replace(/ with /, '\n<b>with</b>\n  ');
      $("[data-problem]").textContent = issues.join(" ");
      $("[data-run]").disabled = issues.length > 0;
    }

    // --- actions -------------------------------------------------------
    $("[data-add-get]").addEventListener("click", () => { state.get.push({ field: "", filters: [] }); drawGet(); });
    $("[data-reset]").addEventListener("click", () => {
      reset();
      $("[data-record]").value = "";
      $("[data-same-row]").checked = false;
      $("[data-live]").checked = false;
      drawGet(); drawWhere();
    });
    $("[data-run]").addEventListener("click", () => {
      if (problems().length) return;
      opts.onRun(text(), { record: $("[data-record]").value, sameRow: $("[data-same-row]").checked, live: $("[data-live]").checked });
    });
    $("[data-save]").addEventListener("click", () => {
      if (problems().length) { showToast(problems()[0], "error"); return; }
      opts.onSave(text(), { record: $("[data-record]").value, sameRow: $("[data-same-row]").checked });
    });
    $("[data-copy]").addEventListener("click", async e => {
      e.preventDefault();
      try { await navigator.clipboard.writeText(text()); showToast("Query copied to the clipboard", "ok"); }
      catch (err) { showToast("Could not copy: " + err.message, "error"); }
    });
    const qbp = $(".qbp");
    const setHidden = hidden => {
      qbp.classList.toggle("text-hidden", hidden);
      $("[data-toggle]").setAttribute("aria-expanded", String(!hidden));
      $("[data-toggle] span").textContent = hidden ? "Show query text" : "Hide query text";
      try { localStorage.setItem(HIDE_KEY, hidden ? "1" : ""); } catch (e) {}
    };
    let hiddenPref = false;
    try { hiddenPref = localStorage.getItem(HIDE_KEY) === "1"; } catch (e) {}
    setHidden(hiddenPref);
    $("[data-toggle]").addEventListener("click", () => setHidden(!qbp.classList.contains("text-hidden")));

    drawGet();
    drawWhere();

    return {
      // load fills the builder from a parsed query: the fields to get and
      // the where clause (rules as the rule engine has them, groups nested).
      load(get, rules, all, extra) {
        reset();
        const rows = (get || []).map(splitGetEntry).filter(r => byField.has(r.field));
        state.get = rows.length ? rows : [{ field: "", filters: [] }];
        const toItems = rs => rs.flatMap(r => {
          if (r.op === "group") {
            const g = JSON.parse(r.value);
            return [{ type: "group", all: !!g.all, items: toItems(g.rules || []) }];
          }
          if (r.op === "same_row") return toItems(JSON.parse(r.value));
          return [{ type: "row", field: r.field, op: r.op, value: r.value || "" }];
        });
        state.where = { type: "group", all: all !== false, items: toItems(rules || []) };
        if (extra) {
          $("[data-record]").value = extra.record || "";
          $("[data-same-row]").checked = !!extra.sameRow;
        }
        drawGet();
        drawWhere();
      },
      setRecords: copyRecords,
    };
  }

  window.mountQueryBuilder = mountQueryBuilder;
})();
