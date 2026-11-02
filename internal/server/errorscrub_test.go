package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInternalErrorsAreLoggedNotReturned(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{logger: slog.New(slog.NewTextHandler(&logs, nil))}
	h := s.scrubInternalErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/text":
			http.Error(w, `get agent: ERROR: relation "agents_secret" does not exist (SQLSTATE 42P01)`, http.StatusInternalServerError)
		case "/json":
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "open /var/lib/mustra/x: permission denied"})
		case "/dup":
			http.Error(w, `create deploy credential: ERROR: duplicate key value violates unique constraint "deploy_credentials_name_key" (SQLSTATE 23505)`, http.StatusInternalServerError)
		case "/bad":
			http.Error(w, "name is required", http.StatusBadRequest)
		case "/unavailable":
			http.Error(w, "no credential encryption key is configured", http.StatusServiceUnavailable)
		default:
			w.Write([]byte("ok"))
		}
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/text", nil))
	rid := rec.Header().Get("X-Request-Id")
	if rec.Code != 500 || rid == "" {
		t.Fatalf("status %d, request id %q", rec.Code, rid)
	}
	if strings.Contains(rec.Body.String(), "agents_secret") || strings.Contains(rec.Body.String(), "SQLSTATE") {
		t.Fatalf("internal error leaked to the client: %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), rid) {
		t.Errorf("the generic message should carry the request id: %q", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "agents_secret") || !strings.Contains(logs.String(), rid) {
		t.Errorf("the original error and request id must be logged: %s", logs.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/json", nil))
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("a JSON 500 must stay JSON: %v %q", err, rec.Body.String())
	}
	if strings.Contains(body["error"], "/var/lib") || body["request_id"] != rec.Header().Get("X-Request-Id") {
		t.Errorf("json 500: %v", body)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/dup", nil))
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), "deploy_credentials_name_key") {
		t.Errorf("a unique violation should be a 409 without the constraint name: %d %q", rec.Code, rec.Body.String())
	}

	for path, want := range map[string]string{"/bad": "name is required", "/unavailable": "no credential encryption key", "/ok": "ok"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d %q should pass through", path, rec.Code, rec.Body.String())
		}
	}
}

func TestScrubWriterKeepsStreaming(t *testing.T) {
	s := &Server{}
	h := s.scrubInternalErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("SSE handlers need a Flusher")
		}
		w.Write([]byte("data: 1\n\n"))
		f.Flush()
		if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
			t.Errorf("ResponseController: %v", err)
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/events", nil))
	if !rec.Flushed || rec.Body.String() != "data: 1\n\n" {
		t.Errorf("flushed=%v body=%q", rec.Flushed, rec.Body.String())
	}
}

// Postgres refusing a NUL byte or invalid UTF-8 is the caller's malformed
// input: a 400 without the driver text, not a 500.
func TestUnstorableCharactersAreBadRequests(t *testing.T) {
	s := &Server{}
	h := s.scrubInternalErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `get sensor data: ERROR: invalid byte sequence for encoding "UTF8": 0x00 (SQLSTATE 22021)`, http.StatusInternalServerError)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/agents/x/sensor/facts", nil))
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "SQLSTATE") {
		t.Fatalf("got %d %q, want a 400 without the driver message", rec.Code, rec.Body.String())
	}
}
