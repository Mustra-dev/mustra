package auth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSessionTokenHashAndCookieName(t *testing.T) {
	h := HashSessionToken("abc")
	if len(h) != 64 || h == "abc" {
		t.Fatalf("hash = %q", h)
	}
	if SessionCookieName(true) != "__Host-mustra_session" || SessionCookieName(false) != "mustra_session" {
		t.Fatal("unexpected cookie names")
	}
}

func TestCrossSiteLandingBouncesThroughOwnOrigin(t *testing.T) {
	a := &Auth{cookieName: "mustra_session"}
	r := httptest.NewRequest("GET", "/endpoint/agt-1?tab=x", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	rec := httptest.NewRecorder()
	a.denyOrRedirect(rec, r)
	if rec.Code != 200 || rec.Header().Get("Location") != "" {
		t.Fatalf("cross-site landing: code %d location %q, want a 200 same-origin hop", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Body.String(), `url=/endpoint/agt-1?tab=x`) {
		t.Fatalf("hop does not target the original page: %s", rec.Body.String())
	}
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	rec = httptest.NewRecorder()
	a.denyOrRedirect(rec, r)
	if rec.Code != 302 {
		t.Fatalf("same-origin arrival without a session: code %d, want 302 to /login", rec.Code)
	}
}

func TestSameOriginRedirectEscapes(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteSameOriginRedirect(rec, `/x"><script>`)
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatal("target not escaped")
	}
}
