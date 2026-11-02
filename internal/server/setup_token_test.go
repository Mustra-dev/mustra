package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetupTokenRequired(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("POST", "/setup", nil)
	if s.setupTokenOK(r, "") || s.setupTokenOK(r, "anything") {
		t.Fatal("setup admitted with no token prepared")
	}
	s.setupToken.Store("0123456789abcdef0123456789abcdef")
	if s.setupTokenOK(r, "") || s.setupTokenOK(r, "0123456789abcdef0123456789abcdee") {
		t.Fatal("setup admitted without the right token")
	}
	if !s.setupTokenOK(r, "0123456789abcdef0123456789abcdef") {
		t.Fatal("the right token in the body was refused")
	}
	q := httptest.NewRequest("GET", "/setup?token=0123456789abcdef0123456789abcdef", nil)
	if !s.setupTokenOK(q, "") {
		t.Fatal("the right token in the URL was refused")
	}
	c := httptest.NewRequest("POST", "/setup", nil)
	c.AddCookie(&http.Cookie{Name: setupCookieName, Value: "0123456789abcdef0123456789abcdef"})
	if !s.setupTokenOK(c, "") {
		t.Fatal("the setup cookie was refused")
	}
	s.setupToken.Store("")
	if s.setupTokenOK(c, "") {
		t.Fatal("a used-up token still works")
	}
}
