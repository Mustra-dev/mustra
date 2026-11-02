package selfservice

import (
	"regexp"
	"strings"
	"testing"
)

// The window's CSP refuses style attributes, so the page must not carry
// one, and every <style> and <script> element must take the nonce.
func TestWindowNeedsNoInlineStyles(t *testing.T) {
	if m := regexp.MustCompile(`\sstyle\s*=`).FindString(string(html)); m != "" {
		t.Fatalf("window.html has a style attribute (%q); set it through the CSSOM instead", m)
	}
	page := string(WithNonce(html, "n0nce"))
	for _, tag := range []string{"<style", "<script"} {
		total := strings.Count(page, tag)
		nonced := strings.Count(page, tag+` nonce="n0nce"`)
		if total == 0 || total != nonced {
			t.Errorf("%d %s elements, %d with the nonce", total, tag, nonced)
		}
	}
	for _, fa := range []string{"'none'", "'self'"} {
		csp := CSP("n0nce", fa)
		if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "style-src 'self' 'nonce-n0nce'") || !strings.HasSuffix(csp, "frame-ancestors "+fa) {
			t.Errorf("CSP: %s", csp)
		}
	}
}
