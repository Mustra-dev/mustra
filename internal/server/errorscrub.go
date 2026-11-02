package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Internal errors stay in the server log.
//
// Hundreds of handlers answer a failed query or file operation with
// http.Error(w, err.Error(), 500), which put SQL text, constraint and
// column names, file paths and driver messages in front of whoever made
// the request. Rather than rely on every call site, every 500 is caught
// here: the original body is logged with a request ID and the client gets
// a generic message carrying the same ID, so an operator can still find
// the cause. Other statuses pass through unchanged -- a 4xx explains what
// the caller did wrong, and the 502/503 answers deliberately describe an
// unavailable dependency (no vault key, agent unreachable).

const maxLoggedErrorBody = 4 << 10

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

func (s *Server) scrubInternalErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := newRequestID()
		w.Header().Set("X-Request-Id", rid)
		sw := &scrubWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if !sw.suppressed {
			return
		}
		detail := strings.TrimSpace(sw.body.String())
		status, msg := http.StatusInternalServerError,
			"internal server error; the server log has the details (request id "+rid+")"
		// Many create handlers pass a unique-constraint violation straight
		// through as a 500. It is the caller's conflict, not a server fault:
		// say so, without the constraint and column names.
		if strings.Contains(detail, "(SQLSTATE 23505)") {
			status, msg = http.StatusConflict, "that name or identifier is already in use (request id "+rid+")"
		}
		// A NUL byte or invalid UTF-8 in a path, query or JSON string reaches
		// Postgres, which refuses it (22021 invalid byte sequence, 22P05
		// untranslatable character). That is malformed input, not a server
		// fault, and it should not page anyone as an ERROR.
		// A foreign-key violation means the request named something that
		// does not exist (a patch list, a notification): the caller's error.
		if strings.Contains(detail, "(SQLSTATE 23503)") {
			status, msg = http.StatusBadRequest, "the request refers to something that does not exist (request id "+rid+")"
		}
		// bcrypt refuses passwords over 72 bytes rather than truncating them.
		if strings.Contains(detail, bcrypt.ErrPasswordTooLong.Error()) {
			status, msg = http.StatusBadRequest, "passwords are limited to 72 bytes (request id "+rid+")"
		}
		if strings.Contains(detail, "(SQLSTATE 22021)") || strings.Contains(detail, "(SQLSTATE 22P05)") {
			status, msg = http.StatusBadRequest, "the request contains characters that cannot be stored (a NUL byte or invalid UTF-8) (request id "+rid+")"
		}
		if s.logger != nil {
			level := slog.LevelError
			// A browser that navigated away cancels its requests; the
			// resulting "context canceled" is not a server problem.
			if r.Context().Err() != nil || status != http.StatusInternalServerError {
				level = slog.LevelInfo
			}
			s.logger.Log(r.Context(), level, "request failed", "request_id", rid,
				"method", r.Method, "path", r.URL.Path, "status", status, "error", detail)
		}
		writeGenericError(w, status, msg, rid, sw.json)
	})
}

func writeGenericError(w http.ResponseWriter, status int, msg, rid string, asJSON bool) {
	h := w.Header()
	h.Del("Content-Length")
	h.Del("Content-Disposition")
	if asJSON {
		h.Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg, "request_id": rid})
		return
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg + "\n"))
}

// scrubWriter holds back a 500 and its body; everything else is written
// straight through (including streaming responses, which keep Flush).
type scrubWriter struct {
	http.ResponseWriter
	wroteHeader bool
	suppressed  bool
	json        bool
	body        bytes.Buffer
}

func (w *scrubWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if code == http.StatusInternalServerError {
		w.suppressed = true
		w.json = strings.HasPrefix(w.Header().Get("Content-Type"), "application/json")
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *scrubWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.suppressed {
		if room := maxLoggedErrorBody - w.body.Len(); room > 0 {
			if len(b) > room {
				w.body.Write(b[:room])
			} else {
				w.body.Write(b)
			}
		}
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *scrubWriter) Flush() {
	if w.suppressed {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer (SSE
// handlers clear their write deadline through it).
func (w *scrubWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
