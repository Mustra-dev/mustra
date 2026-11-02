package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

//go:embed static
var staticFS embed.FS

var loginTemplate = template.Must(template.ParseFS(staticFS, "static/login.html"))

var versionedAssets = []string{"static/app.js", "static/app.css", "static/vendor/script-editor.js", "static/deploy.js", "static/deploy.css", "static/charts.js", "static/deployments.js", "static/theme.js", "static/querybuilder.js"}

// assetVersion is a content hash of the versioned static assets, computed
// once at process start. References to these assets in HTML pages
// get "?v=<assetVersion>" appended
// (see versionAssetLinks) so a deploy that changes any of these files is always a
// cache miss at every layer — the browser, and Cloudflare's edge (this
// console sits behind a proxied Cloudflare Tunnel hostname, which caches
// .js/.css by default; a Cache-Control header alone doesn't dislodge an
// object already cached under the old URL, since Cloudflare doesn't
// re-fetch to notice a header changed — but a new URL is unconditionally a
// fresh fetch). This is what lets /static/* also carry a long, aggressive
// Cache-Control instead of the weaker "no-cache" revalidate-every-time
// this file used before assetVersion existed.
var assetVersion = computeAssetVersion()

func computeAssetVersion() string {
	h := sha256.New()
	for _, name := range versionedAssets {
		data, err := staticFS.ReadFile(name)
		if err == nil {
			h.Write(data)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:10]
}

func versionAssetLinks(data []byte) []byte {
	for _, name := range versionedAssets {
		data = bytes.ReplaceAll(data, []byte(`/`+name+`"`), []byte(`/`+name+`?v=`+assetVersion+`"`))
	}
	return data
}

// Every console page is served with a Content-Security-Policy that allows
// only same-origin scripts and the page's own inline <script> blocks, which
// carry a nonce minted for that one response. A markup injection that slips
// past escapeHtml then can't run: inline event handlers, javascript: URLs,
// injected <script> elements and eval are all refused by the browser.
//
// Styles: a <style> element applies only with the response's nonce, like a
// script, so injected markup cannot restyle the page; the pages' own <style>
// blocks are stamped with it, and charts.js and the editor bundle give it to
// the ones they create. style="…" attributes are refused outright (#143):
// pages use the u-* classes in app.css, and a style computed at render time
// goes through sx() in app.js, which applies it through the CSSOM (not
// subject to the policy). style-src repeats the -elem/-attr rules for
// browsers that predate them.
// frame-src allows the Self Service preview, which is same-origin.
const consoleCSPTemplate = "default-src 'self'; " +
	"script-src 'self' 'nonce-%s'; " +
	"style-src 'self' 'nonce-%s'; " +
	"style-src-elem 'self' 'nonce-%s'; " +
	"style-src-attr 'none'; " +
	"img-src 'self' data: blob:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"frame-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

func consoleCSP(nonce string) string {
	return strings.ReplaceAll(consoleCSPTemplate, "%s", nonce)
}

// newCSPNonce returns 128 random bits, base64-encoded as CSP expects.
func newCSPNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand read failed: " + err.Error()) // no safe fallback for a nonce
	}
	return base64.StdEncoding.EncodeToString(b)
}

var (
	scriptOpenTag = regexp.MustCompile(`(?i)<script\b`)
	styleOpenTag  = regexp.MustCompile(`(?i)<style\b`)
)

// addScriptNonce marks every <script> and <style> element in a page with
// the nonce. The pages are first-party files embedded at build time (and
// the login template, rendered by html/template), so every one is ours.
func addScriptNonce(page []byte, nonce string) []byte {
	page = scriptOpenTag.ReplaceAll(page, []byte(`<script nonce="`+nonce+`"`))
	return styleOpenTag.ReplaceAll(page, []byte(`<style nonce="`+nonce+`"`))
}

// setPageSecurityHeaders sets the headers every console HTML response
// carries.
func setPageSecurityHeaders(h http.Header, nonce string) {
	h.Set("Content-Security-Policy", consoleCSP(nonce))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
}

// writeConsolePage serves one embedded console page: asset links
// versioned, scripts nonced, and the security headers set.
func writeConsolePage(w http.ResponseWriter, page []byte) {
	writeConsolePageStatus(w, page, http.StatusOK)
}

// writeConsolePageStatus is writeConsolePage with a status other than 200.
func writeConsolePageStatus(w http.ResponseWriter, page []byte, status int) {
	nonce := newCSPNonce()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	setPageSecurityHeaders(h, nonce)
	w.WriteHeader(status)
	_, _ = w.Write(addScriptNonce(versionAssetLinks(page), nonce))
}

// consoleUIHandler serves the single-page console UI. Deliberately a plain
// server-rendered page with vanilla JS (EventSource + fetch) rather than a
// frontend framework — simple to keep dependency-free and matches the
// project's small-footprint brief.
func consoleUIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeConsolePage(w, data)
	})
}

// agentsPageHandler serves the Agents/Deploy page: manual per-OS install
// instructions plus the network-scan-and-SSH-push flow.
func agentsPageHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile("static/agents.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeConsolePage(w, data)
	})
}

// settingsPageHandler and adminPageHandler both serve the same merged
// "Administration" page (settings.html) — SSO/backdoor/SCIM/agent
// behavior/environment plus users/groups/roles, switched between via its
// own persistent module-subnav rather than being two separate pages.
// They stay two distinct routes/handlers because they're gated behind two
// different permissions (settings.manage vs. users.manage — see
// httpapi.go) — either one reaching this handler is enough, since the
// page itself only shows/loads the sections that permission unlocks.
func settingsPageHandler() http.Handler {
	return staticPageHandler("static/settings.html")
}

func adminPageHandler() http.Handler {
	return staticPageHandler("static/settings.html")
}

// patchesPageHandler serves the Patches tab: fleet-wide missing-patch
// summary and per-agent apply.
func patchesPageHandler() http.Handler {
	return staticPageHandler("static/patches.html")
}

// sensorsPageHandler serves the Sensors tab: what every sensor collects,
// how it collects it per platform, and whether the fleet is actually
// reporting it.
func sensorsPageHandler() http.Handler {
	return staticPageHandler("static/sensors.html")
}

// eunPageHandler serves End-User Notifications: composing what the person
// at the endpoint sees, and sending it.
func eunPageHandler() http.Handler {
	return staticPageHandler("static/eun.html")
}

// engagePageHandler serves Engage: the surveys asked of the people who use
// the fleet, and what they said.
func engagePageHandler() http.Handler {
	return staticPageHandler("static/engage.html")
}

// huntPageHandler serves Threat Response: the indicators mustra looks for,
// and where they have been seen.
func huntPageHandler() http.Handler {
	return staticPageHandler("static/hunt.html")
}

// enforcePageHandler serves Enforce: the settings that must hold, what
// they found, and what mustra did about it.
func enforcePageHandler() http.Handler {
	return staticPageHandler("static/enforce.html")
}

// playbooksPageHandler serves Playbooks: multi-step flows, their schedule,
// and the live per-endpoint view of a run in progress.
func playbooksPageHandler() http.Handler {
	return staticPageHandler("static/playbooks.html")
}

// reportsPageHandler serves Reports: the documents mustra assembles on a
// schedule for people who never open the console.
func reportsPageHandler() http.Handler {
	return staticPageHandler("static/reports.html")
}

// riskPageHandler serves the Risk & Compliance tab: real vulnerability
// data from OSV.dev (see internal/server/osv and vulnscan.go).
func riskPageHandler() http.Handler {
	return staticPageHandler("static/risk.html")
}

// endpointPageHandler serves the per-endpoint detail view — every fact and
// cached sensor mustra holds for one device, tabbed. The agent ID comes
// from the URL path, read client-side.
func endpointPageHandler() http.Handler {
	return staticPageHandler("static/endpoint.html")
}

// interactPageHandler serves Interact: ask a question of the whole fleet
// and act on the answer.
func interactPageHandler() http.Handler {
	return staticPageHandler("static/interact.html")
}

// healthPageHandler serves Performance: endpoint health scores and the
// risk score that weighs them against how much each endpoint matters.
func healthPageHandler() http.Handler {
	return staticPageHandler("static/health.html")
}

// logsPageHandler serves the audit log and its logging controls.
func logsPageHandler() http.Handler {
	return staticPageHandler("static/logs.html")
}

// compliancePageHandler serves Comply: benchmark checks and what fails.
func compliancePageHandler() http.Handler {
	return staticPageHandler("static/compliance.html")
}

// shellPageHandler serves the live shell and its command audit log.
func shellPageHandler() http.Handler {
	return staticPageHandler("static/shell.html")
}

// integrityPageHandler serves File Integrity: what changed in the watched
// set, and which of it mustra itself caused.
func integrityPageHandler() http.Handler {
	return staticPageHandler("static/integrity.html")
}

// certificatesPageHandler serves Certificate Manager: what expires next,
// and where it lives.
func certificatesPageHandler() http.Handler {
	return staticPageHandler("static/certificates.html")
}

// impactPageHandler serves Impact: who can reach what, if an account or an
// endpoint were compromised, from the directory and each endpoint's own
// administrators and sessions.
func impactPageHandler() http.Handler {
	return staticPageHandler("static/impact.html")
}

// guidePageHandler serves Guide: every notification, open and past, in
// one place -- the workspace behind the bell.
func guidePageHandler() http.Handler {
	return staticPageHandler("static/guide.html")
}

// revealPageHandler serves Reveal: where sensitive data sits on endpoints,
// found by patterns that run there and confirmed by validators, with only
// masked evidence coming back.
func revealPageHandler() http.Handler {
	return staticPageHandler("static/reveal.html")
}

// discoverPageHandler serves Discover: what is on the network that mustra
// doesn't manage, assembled from endpoints' own neighbour tables.
func discoverPageHandler() http.Handler {
	return staticPageHandler("static/discover.html")
}

// connectPageHandler serves Connect: standing exports to whatever runs
// alongside mustra.
func connectPageHandler() http.Handler {
	return staticPageHandler("static/connect.html")
}

func backupPageHandler() http.Handler {
	return staticPageHandler("static/backup.html")
}

// softwarePageHandler serves the Deploy module: the software package
// catalog, what the fleet already runs, and per-package deployment.
func softwarePageHandler() http.Handler {
	return staticPageHandler("static/software.html")
}

// catalogPageHandler serves the Software Catalog: the admin half of Self
// Service, where items are published and requests are decided.
func catalogPageHandler() http.Handler {
	return staticPageHandler("static/catalog.html")
}

// groupsPageHandler serves the Computer Groups builder.
func groupsPageHandler() http.Handler {
	return staticPageHandler("static/groups.html")
}

func staticPageHandler(path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeConsolePage(w, data)
	})
}

// staticAssetHandler serves everything under static/ (app.css, app.js, and
// the login page's assets) at /static/*. Every reference to app.js/app.css
// in any page is a "?v=<assetVersion>" URL (see versionAssetLinks), so a
// long, aggressive Cache-Control here is safe — a deploy that changes
// either file produces a brand new URL, which is unconditionally a cache
// miss at every layer (the browser, and Cloudflare's edge: this console
// sits behind a proxied Cloudflare Tunnel hostname, which caches
// .js/.css by default). The unversioned bare filename still resolves too
// (a direct hit, or an old cached HTML page's stale reference) — it just
// isn't cached hard, so it self-heals within a request or two.
func staticAssetHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // embed.FS is compiled in; a missing "static" dir is a build-time bug, not a runtime one
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Assets are fetched by name. http.FileServer would otherwise answer
		// /static/ and every subdirectory with an index of its files.
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("v") == assetVersion {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	}))
}

type loginPageData struct {
	SSOAvailable bool
	Providers    []loginProvider
	LogoURL      string // admin-uploaded console logo, "" for mustra's default mark
	Error        string // empty means no error; html/template auto-escapes this for safe rendering
	Next         string
	// Created is the username the first-run setup just created, to say so
	// and fill it in.
	Created string
	// MFA, when set, replaces the sign-in buttons with the second step.
	MFA *loginMFAView
}

// loginProvider is one branded sign-in button. Only providers that have
// finished discovery are offered — a button that 503s on click would be
// worse than not showing it, and the local account is always there as the
// fallback.
type loginProvider struct {
	ID     string
	Label  string
	Accent string
	SVG    template.HTML
}

// handleLoginPage server-renders the login page so it can decide, at
// request time, whether to show the "Sign in with SSO" button — showing a
// button that 503s because OIDC discovery hasn't completed (or isn't
// configured) would be confusing, and the whole point of the backdoor
// account is a login path that always works regardless of IdP state.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// A deployment nobody has claimed has nothing to sign in to yet, so the
	// login page sends you to the page that creates the account instead of
	// showing a form no credential can satisfy.
	if s.setupPending(r) {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	var providers []loginProvider
	for _, p := range s.auth.Providers() {
		if !p.Ready {
			continue
		}
		b := brandFor(p.Kind)
		providers = append(providers, loginProvider{ID: p.ID, Label: p.Label, Accent: b.Accent, SVG: b.SVG})
	}
	data := loginPageData{
		SSOAvailable: len(providers) > 0,
		Providers:    providers,
		LogoURL:      s.logoURL(),
		Error:        r.URL.Query().Get("error"),
		Next:         r.URL.Query().Get("next"),
		Created:      r.URL.Query().Get("created"),
	}
	if r.URL.Query().Get("step") == "code" {
		mfa, err := s.loginMFAStep(r)
		if err != nil {
			s.logger.Error("render the sign-in code step failed", "error", err)
		}
		if mfa == nil {
			// Expired or never started: back to the password, saying why.
			http.Redirect(w, r, "/login?error="+url.QueryEscape("that sign-in has expired; enter your password again"), http.StatusFound)
			return
		}
		data.MFA = mfa
	}
	s.renderLogin(w, r, data)
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, data loginPageData) {
	var buf bytes.Buffer
	if err := loginTemplate.Execute(&buf, data); err != nil {
		s.logger.Error("render login page failed", "error", err)
		return
	}
	writeConsolePage(w, buf.Bytes())
}
