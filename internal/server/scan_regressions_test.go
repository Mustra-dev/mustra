package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Found by a dynamic scan: /static/ and its subdirectories answered with a
// file index.
func TestStaticDirectoriesAreNotListed(t *testing.T) {
	h := staticAssetHandler()
	for _, p := range []string{"/static/", "/static/vendor/", "/static/brand/"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "<a href") {
			t.Errorf("%s: %d %q, want 404 without a listing", p, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/static/app.css", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("a real asset: %d", rec.Code)
	}
}

// An export saved with a source, format or destination nothing handles
// failed every run with a 500; it is refused at save time instead, before
// the handler touches the store.
func TestExportRejectsUnknownSourceFormatDestination(t *testing.T) {
	s := &Server{}
	for _, body := range []string{
		`{"name":"x","source":"test","destination":"file","format":"json"}`,
		`{"name":"x","source":"endpoints","destination":"ftp","format":"json"}`,
		`{"name":"x","source":"endpoints","destination":"file","format":"xml"}`,
	} {
		rec := httptest.NewRecorder()
		s.handleUpsertExport(rec, httptest.NewRequest("POST", "/api/connect/exports", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %q, want 400", body, rec.Code, rec.Body.String())
		}
	}
}

// Malformed references and over-long passwords are the caller's error.
func TestScrubberClassifiesClientErrors(t *testing.T) {
	s := &Server{}
	for _, detail := range []string{
		`mark notification read: ERROR: insert or update on table "notification_reads" violates foreign key constraint "notification_reads_notification_id_fkey" (SQLSTATE 23503)`,
		bcrypt.ErrPasswordTooLong.Error(),
	} {
		h := s.scrubInternalErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, detail, http.StatusInternalServerError)
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/x", nil))
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "SQLSTATE") || strings.Contains(rec.Body.String(), "notification_reads") {
			t.Errorf("%q: %d %q, want a generic 400", detail, rec.Code, rec.Body.String())
		}
	}
}
