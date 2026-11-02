// Package selfservice holds the Self Service window itself. It lives apart
// from the agent so the console can serve the very same page as a live
// preview while an operator brands it: a preview built from a copy would be
// a second page that drifts from the first.
package selfservice

import (
	"bytes"
	_ "embed"
)

//go:embed window.html
var html []byte

// HTML is the window as an endpoint serves it.
func HTML() []byte { return html }

// PreviewHTML is the same page with the preview switch set. In preview it
// renders sample data instead of asking an agent, takes its branding from
// the console that framed it, and its buttons do nothing.
func PreviewHTML() []byte {
	return bytes.Replace(html, []byte("<head>"),
		[]byte("<head>\n<script>window.MUSTRA_PREVIEW = true;</script>"), 1)
}

// CSP is the window's Content-Security-Policy: this origin only, scripts
// and <style> elements carrying the response's nonce, no style attributes,
// and data: images (the branding logo and background). Branding colours
// and the operator's CSS go into the page's own nonced <style> elements
// as text, and the page sets computed sizes through the CSSOM, so nothing
// needs 'unsafe-inline'. frameAncestors is "'none'" on an endpoint and
// "'self'" for the console's preview.
func CSP(nonce, frameAncestors string) string {
	return "default-src 'self'; script-src 'nonce-" + nonce + "'; " +
		"style-src 'self' 'nonce-" + nonce + "'; style-src-elem 'self' 'nonce-" + nonce + "'; style-src-attr 'none'; " +
		"img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors " + frameAncestors
}

// WithNonce marks every script and style element in page with the nonce.
func WithNonce(page []byte, nonce string) []byte {
	page = bytes.ReplaceAll(page, []byte("<script>"), []byte(`<script nonce="`+nonce+`">`))
	page = bytes.ReplaceAll(page, []byte("<style>"), []byte(`<style nonce="`+nonce+`">`))
	return bytes.ReplaceAll(page, []byte("<style id="), []byte(`<style nonce="`+nonce+`" id=`))
}
