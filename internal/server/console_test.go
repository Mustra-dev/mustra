package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestSensorEditorAssets(t *testing.T) {
	r := httptest.NewRequest("GET", "/sensors", nil)
	w := httptest.NewRecorder()
	sensorsPageHandler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("sensor page: HTTP %d", w.Code)
	}
	// app.js starts loading the user immediately. A blocking bundle after it
	// could delay the page's listener until mustra:user has already fired.
	editorIndex := bytes.Index(w.Body.Bytes(), []byte(`src="/static/vendor/script-editor.js`))
	appIndex := bytes.Index(w.Body.Bytes(), []byte(`src="/static/app.js`))
	if editorIndex < 0 || appIndex < 0 || editorIndex > appIndex {
		t.Fatal("editor bundle must load before app.js starts the user request")
	}
	hash := sha256.New()
	for _, name := range []string{"static/app.js", "static/app.css", "static/vendor/script-editor.js"} {
		asset, err := staticFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		hash.Write(asset)
		if !bytes.Contains(w.Body.Bytes(), []byte(`/`+name+`?v=`+assetVersion+`"`)) {
			t.Errorf("page does not version %s", name)
		}
	}
	for _, name := range []string{"static/deploy.js", "static/deploy.css", "static/charts.js", "static/deployments.js", "static/theme.js", "static/querybuilder.js"} {
		asset, err := staticFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		hash.Write(asset)
	}
	if want := hex.EncodeToString(hash.Sum(nil))[:10]; assetVersion != want {
		t.Errorf("asset version %q does not cover the editor bundle; want %q", assetVersion, want)
	}
}

func TestDeployAssets(t *testing.T) {
	w := httptest.NewRecorder()
	softwarePageHandler().ServeHTTP(w, httptest.NewRequest("GET", "/software", nil))
	for _, name := range []string{"static/deploy.js", "static/deploy.css"} {
		if !bytes.Contains(w.Body.Bytes(), []byte("/"+name+"?v="+assetVersion)) {
			t.Errorf("Deploy asset is not versioned: %s", name)
		}
	}
	if bytes.Index(w.Body.Bytes(), []byte(`src="/static/deploy.js`)) > bytes.Index(w.Body.Bytes(), []byte(`src="/static/app.js`)) {
		t.Fatal("Deploy listener must load before the user request")
	}
}

// TestDeploymentDashboardPages checks each page that mounts the shared
// deployment dashboard loads deployments.js, versioned, after app.js, whose
// helpers it uses at mount time.
func TestDeploymentDashboardPages(t *testing.T) {
	pages := map[string]http.Handler{
		"/patches": patchesPageHandler(), "/software": softwarePageHandler(), "/agents": agentsPageHandler(),
	}
	for path, h := range pages {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		body := w.Body.Bytes()
		dash := bytes.Index(body, []byte(`src="/static/deployments.js?v=`+assetVersion+`"`))
		app := bytes.Index(body, []byte(`src="/static/app.js`))
		if dash < 0 {
			t.Errorf("%s does not load a versioned deployments.js", path)
			continue
		}
		if app < 0 || app > dash {
			t.Errorf("%s loads deployments.js before app.js", path)
		}
		if !bytes.Contains(body, []byte("mountDeploymentDashboard(")) {
			t.Errorf("%s never mounts the deployment dashboard", path)
		}
	}
}

var nonceAttr = regexp.MustCompile(`<script\b[^>]*\bnonce="([^"]+)"`)

// checkCSPPage asserts one console page response carries the strict policy
// and that every <script> in it has this response's nonce.
func checkCSPPage(t *testing.T, name string, w *httptest.ResponseRecorder) string {
	t.Helper()
	csp := w.Header().Get("Content-Security-Policy")
	m := regexp.MustCompile(`script-src 'self' 'nonce-([A-Za-z0-9+/=]{22,})';`).FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("%s: no nonce script-src in CSP %q", name, csp)
	}
	for _, d := range []string{"object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'", "connect-src 'self'", "default-src 'self'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("%s: CSP lacks %s", name, d)
		}
	}
	if strings.Contains(csp, "unsafe-eval") || strings.Contains(strings.SplitN(strings.SplitN(csp, "script-src", 2)[1], ";", 2)[0], "unsafe-inline") {
		t.Errorf("%s: script-src allows unsafe-inline or unsafe-eval: %q", name, csp)
	}
	// Nothing may run or apply inline without the nonce: no style
	// attributes either (#143).
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "style-src-attr 'none'") || !strings.Contains(csp, "style-src 'self' 'nonce-"+m[1]+"';") {
		t.Errorf("%s: CSP allows inline styles: %q", name, csp)
	}
	for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin"} {
		if got := w.Header().Get(h); got != want {
			t.Errorf("%s: %s = %q, want %q", name, h, got, want)
		}
	}
	body := w.Body.String()
	scripts := regexp.MustCompile(`(?i)<script\b`).FindAllStringIndex(body, -1)
	nonced := nonceAttr.FindAllStringSubmatch(body, -1)
	if len(scripts) == 0 || len(nonced) != len(scripts) {
		t.Errorf("%s: %d <script> tags but %d carry a nonce", name, len(scripts), len(nonced))
	}
	for _, n := range nonced {
		if n[1] != m[1] {
			t.Errorf("%s: script nonce %q is not the response's %q", name, n[1], m[1])
		}
	}
	return m[1]
}

func TestConsolePagesCarryStrictCSP(t *testing.T) {
	entries, err := staticFS.ReadDir("static")
	if err != nil {
		t.Fatal(err)
	}
	pages := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") || e.Name() == "login.html" {
			continue
		}
		h := staticPageHandler("static/" + e.Name())
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
		first := checkCSPPage(t, e.Name(), w)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
		if checkCSPPage(t, e.Name(), w) == first {
			t.Errorf("%s: nonce reused across responses", e.Name())
		}
		pages++
	}
	if pages < 30 {
		t.Errorf("only %d pages checked", pages)
	}
	w := httptest.NewRecorder()
	consoleUIHandler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	checkCSPPage(t, "/", w)

	// The login page is a template; it goes through the same writer.
	var buf bytes.Buffer
	if err := loginTemplate.Execute(&buf, loginPageData{Next: "/"}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	writeConsolePage(w, buf.Bytes())
	checkCSPPage(t, "login.html", w)
}

// A provider's brand colour reaches its sign-in button through the page's
// nonced <style> element, not a style attribute the CSP would refuse (#143).
func TestLoginProviderAccentIsNonced(t *testing.T) {
	var buf bytes.Buffer
	data := loginPageData{Next: "/", SSOAvailable: true, Providers: []loginProvider{
		{ID: "corp", Label: "Corp", Accent: brandFor("azure").Accent},
		{ID: "git", Label: "Git", Accent: brandFor("github").Accent},
	}}
	if err := loginTemplate.Execute(&buf, data); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	writeConsolePage(w, buf.Bytes())
	nonce := checkCSPPage(t, "login.html", w)
	body := w.Body.String()
	for i, want := range []string{`.sso-button[data-idp="0"] { --idp-accent: #0078d4; }`, `.sso-button[data-idp="1"] { --idp-accent: #8b93a3; }`} {
		if !strings.Contains(body, want) {
			t.Errorf("provider %d: no rule %q in\n%s", i, want, body)
		}
		if !strings.Contains(body, fmt.Sprintf(`class="sso-button" data-idp="%d" href=`, i)) {
			t.Errorf("provider %d: button lacks data-idp", i)
		}
	}
	if !strings.Contains(body, `<style nonce="`+nonce+`">`) {
		t.Errorf("the accent <style> lacks the response's nonce")
	}
}

// The console CSP refuses style attributes (#143): one in a page or in
// markup a script builds would silently not apply. Static declarations use
// the u-* classes in app.css, computed ones sx() in app.js.
func TestConsoleHasNoStyleAttributes(t *testing.T) {
	// Any style= followed by a quote: in markup, or in a string a template
	// splices into a tag ('style="…"' inside a ${} expression).
	attr := regexp.MustCompile(`(?i)\bstyle=\\?["'\x60]|setAttribute\(\s*["']style["']`)
	for name, src := range consoleSources(t) {
		for _, m := range attr.FindAllString(src, -1) {
			t.Errorf("%s: style attribute in %q", name, m)
		}
	}
}

// A nonce CSP only protects pages that never need inline handlers or
// string-evaluated code, so none may creep back in.
func TestConsoleHasNoInlineHandlersOrEval(t *testing.T) {
	handler := regexp.MustCompile(`(?i)<[a-z][^<>]*\son[a-z]+\s*=`)
	evalish := regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(|\bset(Timeout|Interval)\s*\(\s*["'\x60]|["'\x60=]\s*javascript:|setAttribute\(\s*["']on[a-z]+`)
	for name, src := range consoleSources(t) {
		for _, m := range handler.FindAllString(src, -1) {
			t.Errorf("%s: inline event handler attribute in %q", name, m)
		}
		for _, m := range evalish.FindAllString(src, -1) {
			t.Errorf("%s: %q is refused by the console CSP", name, m)
		}
	}
}
