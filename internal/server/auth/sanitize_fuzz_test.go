package auth

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzSanitizeNext proves the open-redirect guard: whatever a login "next"
// field carries, sanitizeNext returns either "/" or a same-origin relative
// path — never a value a browser would navigate off-site. The property is
// checked by re-parsing the result as if it were a URL and confirming it
// has no scheme, host or userinfo and begins with a single slash.
func FuzzSanitizeNext(f *testing.F) {
	for _, s := range []string{
		"/dashboard", "//evil.example", "/\\evil.example", "/\t/evil", "https://evil",
		"/path?q=1#frag", "\\\\evil", "/a//b", "javascript:alert(1)", "/%2F%2Fevil",
		"", "/", "/normal/path", "/\u0000", strings.Repeat("/a", 2000), "/@evil.example",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, next string) {
		got := sanitizeNext(next)
		if got == "/" {
			return
		}
		// A non-"/" result is claimed to be a safe same-origin path. Verify
		// independently: it must parse as a bare path, no backslash, no
		// control char, not "//...", no scheme/host/user.
		if got == "" || got[0] != '/' {
			t.Fatalf("sanitizeNext(%q)=%q does not start with /", next, got)
		}
		if strings.HasPrefix(got, "//") || strings.ContainsRune(got, '\\') {
			t.Fatalf("sanitizeNext(%q)=%q is protocol-relative or has a backslash", next, got)
		}
		for _, r := range got {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("sanitizeNext(%q)=%q keeps a control character", next, got)
			}
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("sanitizeNext(%q)=%q does not parse: %v", next, got, err)
		}
		if u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
			t.Fatalf("sanitizeNext(%q)=%q is not same-origin relative (%+v)", next, got, u)
		}
		// And it must be a fixed point: sanitizing it again is identical.
		if sanitizeNext(got) != got {
			t.Fatalf("sanitizeNext not idempotent: %q -> %q -> %q", next, got, sanitizeNext(got))
		}
	})
}
