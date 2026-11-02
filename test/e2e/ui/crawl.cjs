// Browser crawl of the console for the e2e harness (TestE2E/ui-crawl).
//
// Loads every page the navigation links to, plus one endpoint page, in the
// dark and light themes at a desktop and a phone width, and records what a
// person would notice before anything else: a JavaScript error, a request
// the Content-Security-Policy blocked, a page wider than the screen. The
// Go test reads the JSON report this writes and fails on any issue.
//
// Input (environment): MUSTRA_E2E_CONSOLE_URL, MUSTRA_E2E_COOKIE
// (name=value of a signed-in session), MUSTRA_E2E_ENDPOINT_ID,
// MUSTRA_E2E_REPORT (output path), MUSTRA_E2E_SHOTS (screenshot dir).
'use strict';
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const base = process.env.MUSTRA_E2E_CONSOLE_URL.replace(/\/$/, '');
const [cookieName, ...rest] = process.env.MUSTRA_E2E_COOKIE.split('=');
const cookieValue = rest.join('=');
const endpointID = process.env.MUSTRA_E2E_ENDPOINT_ID || '';
const reportPath = process.env.MUSTRA_E2E_REPORT;
const shots = process.env.MUSTRA_E2E_SHOTS;
fs.mkdirSync(shots, { recursive: true });

const themes = ['dark', 'light'];
const viewports = [
  { tag: 'desktop', width: 1440, height: 900 },
  { tag: 'mobile', width: 390, height: 844 },
];

// Installed before any page script: the theme the inline head script reads
// before first paint, and a record of every CSP violation the page raises.
function initScript(theme) {
  try { localStorage.setItem('mustra-theme', theme); } catch (e) {}
  window.__cspViolations = [];
  document.addEventListener('securitypolicyviolation', e => {
    window.__cspViolations.push(`${e.violatedDirective} blocked ${e.blockedURI || 'inline'} (${e.sourceFile || ''}:${e.lineNumber || 0})`);
  });
}

async function newContext(browser, theme, vp) {
  const ctx = await browser.newContext({
    viewport: { width: vp.width, height: vp.height },
    colorScheme: theme,
  });
  const u = new URL(base);
  await ctx.addCookies([{ name: cookieName, value: cookieValue, domain: u.hostname, path: '/', httpOnly: true, secure: true, sameSite: 'Strict' }]);
  await ctx.addInitScript(initScript, theme);
  return ctx;
}

// The theme is a per-user preference the console applies on every load
// (and "system" defers to the browser), so set it the way the
// Preferences dialog does rather than only in this browser's storage.
async function setTheme(ctx, theme) {
  const got = await ctx.request.get(base + '/api/preferences');
  if (!got.ok()) throw new Error(`GET /api/preferences: ${got.status()}`);
  const prefs = await got.json();
  prefs.theme = theme;
  const put = await ctx.request.put(base + '/api/preferences', { data: prefs });
  if (!put.ok()) throw new Error(`PUT /api/preferences: ${put.status()} ${await put.text()}`);
}

// The pages to visit come from the console's own NAV_TREE, so a page added
// to the navigation is crawled without touching this file.
async function navPages(browser) {
  const ctx = await newContext(browser, 'dark', viewports[0]);
  const page = await ctx.newPage();
  await page.goto(base + '/', { waitUntil: 'load' });
  if (new URL(page.url()).pathname.startsWith('/login')) throw new Error('the session cookie was not accepted');
  const hrefs = await page.evaluate(() => {
    const out = new Set();
    for (const cat of NAV_TREE) {
      if (cat.href) out.add(cat.href);
      for (const s of cat.sub || []) out.add((s.href || cat.href).split('#')[0]);
    }
    return [...out];
  });
  await ctx.close();
  const pages = hrefs.filter(h => h.startsWith('/'));
  if (endpointID) pages.push('/endpoint/' + encodeURIComponent(endpointID));
  return pages;
}

// Pages load concurrently within a theme, at most this many at once. The
// console is plain HTTP/1.1 here, so Chromium opens six connections per
// host, and Home holds one of them for its event stream while every page
// makes several API calls: much past three and requests queue behind each
// other (see #20) until navigations time out. Each page's listeners belong
// to that page alone, so concurrency does not change what is detected.
const concurrency = 3;

// One load of one route, with every check. Returns the issues it found.
async function visit(ctx, theme, vp, route) {
  const page = await ctx.newPage();
  const found = [];
  const add = (kind, detail) => found.push({ page: route, theme, viewport: vp.tag, kind, detail: String(detail).slice(0, 300) });
  page.on('pageerror', err => add('js-error', err.message));
  page.on('console', msg => {
    if (msg.type() === 'error') add('console-error', msg.text());
  });
  page.on('response', resp => {
    if (resp.status() >= 400 && resp.url().startsWith(base)) add('http-' + resp.status(), resp.url().slice(base.length));
  });
  page.on('dialog', d => { add('dialog', d.message()); d.dismiss().catch(() => {}); });
  try {
    // Not networkidle: the dashboard holds a live event stream open.
    const resp = await page.goto(base + route, { waitUntil: 'load', timeout: 30000 });
    if (!resp || resp.status() !== 200) add('status', resp ? resp.status() : 'no response');
    if (new URL(page.url()).pathname.startsWith('/login')) add('redirect', page.url());
    // Late console errors (a failed fetch after first paint) need the time.
    await page.waitForTimeout(1200);
    const state = await page.evaluate(() => ({
      theme: document.documentElement.getAttribute('data-theme'),
      csp: window.__cspViolations || [],
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth: window.innerWidth,
    }));
    if (state.theme !== theme) add('theme', `data-theme is ${state.theme}`);
    for (const v of state.csp) add('csp-violation', v);
    if (state.scrollWidth > state.innerWidth + 1) add('horizontal-overflow', `${state.scrollWidth}px wide in a ${state.innerWidth}px viewport`);
  } catch (e) {
    add('navigation', e.message);
  }
  const name = `${theme}-${vp.tag}-${route.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '') || 'home'}.png`;
  if (found.length > 0 || route === '/') {
    await page.screenshot({ path: path.join(shots, name), fullPage: false }).catch(() => {});
  }
  await page.close();
  return found;
}

// Runs every job through `concurrency` workers and returns the results in
// job order, so the report reads the same however the loads interleave.
async function pool(jobs, run) {
  const results = new Array(jobs.length);
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) {
      const i = next++;
      results[i] = await run(jobs[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, jobs.length) }, worker));
  return results;
}

(async () => {
  const browser = await chromium.launch();
  const issues = [];
  let loads = 0;
  let pages = [];
  try {
    pages = await navPages(browser);
    console.log(`crawling ${pages.length} pages: ${pages.join(' ')}`);
    // Themes one after the other: the theme is a server-side preference of
    // the one crawl user, so two at once would race and report false
    // "theme" issues. Both viewports of a theme share its pool.
    for (const theme of themes) {
      const contexts = [];
      try {
        const jobs = [];
        for (const vp of viewports) {
          const ctx = await newContext(browser, theme, vp);
          contexts.push(ctx);
          for (const route of pages) jobs.push({ ctx, vp, route });
        }
        await setTheme(contexts[0], theme);
        const found = await pool(jobs, async j => {
          const f = await visit(j.ctx, theme, j.vp, j.route);
          loads++;
          return f;
        });
        for (const f of found) issues.push(...f);
      } finally {
        for (const ctx of contexts) await ctx.close();
      }
    }
  } catch (e) {
    issues.push({ page: '-', theme: '-', viewport: '-', kind: 'crawl', detail: e.message });
  } finally {
    await browser.close();
  }
  fs.writeFileSync(reportPath, JSON.stringify({ pages: pages.length, loads, issues }, null, 1));
  console.log(`${loads} loads of ${pages.length} pages, ${issues.length} issues`);
  for (const i of issues) console.log(`  ${i.page} [${i.theme}, ${i.viewport}] ${i.kind}: ${i.detail}`);
  process.exit(issues.length > 0 ? 1 : 0);
})();
