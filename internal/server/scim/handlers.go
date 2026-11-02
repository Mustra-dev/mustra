package scim

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/mustra-dev/mustra/internal/store"
)

// Server implements the SCIM 2.0 provisioning API against the console's
// users/groups tables. Entirely independent of internal/server/auth's
// session-based login — provisioning happens whether or not anyone is
// currently logged into the console.
type Server struct {
	store  *store.Store
	logger *slog.Logger

	mu    sync.RWMutex
	token string
}

// New constructs a SCIM server. token is the static bearer token the IdP's
// SCIM provider must present (configured on both sides — see
// docs/ARCHITECTURE.md for why a single static token is the right amount of
// complexity here).
func New(st *store.Store, token string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{store: st, token: token, logger: logger}
}

// SetToken hot-swaps the bearer token an IdP must present (the admin
// settings API's SCIM token field) — no restart needed.
func (s *Server) SetToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
}

func (s *Server) getToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

// Enabled reports whether a SCIM token is configured at all — if not,
// Routes still registers handlers but every request is rejected, which is
// simpler than conditionally registering routes and gives a clear 401
// instead of a 404 if someone points an IdP at this server before it's
// configured.
func (s *Server) Enabled() bool { return s.getToken() != "" }

// Routes returns the SCIM handler mounted at /scim/v2/ — register it in the
// server's mux with `mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scimServer.Routes()))`.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ServiceProviderConfig", s.handleServiceProviderConfig)
	mux.HandleFunc("GET /ResourceTypes", s.handleResourceTypes)
	mux.HandleFunc("GET /Schemas", s.handleSchemas)

	mux.HandleFunc("GET /Users", s.handleListUsers)
	mux.HandleFunc("POST /Users", s.handleCreateUser)
	mux.HandleFunc("GET /Users/{id}", s.handleGetUser)
	mux.HandleFunc("PUT /Users/{id}", s.handleReplaceUser)
	mux.HandleFunc("PATCH /Users/{id}", s.handlePatchUser)
	mux.HandleFunc("DELETE /Users/{id}", s.handleDeleteUser)

	mux.HandleFunc("GET /Groups", s.handleListGroups)
	mux.HandleFunc("POST /Groups", s.handleCreateGroup)
	mux.HandleFunc("GET /Groups/{id}", s.handleGetGroup)
	mux.HandleFunc("PUT /Groups/{id}", s.handleReplaceGroup)
	mux.HandleFunc("PATCH /Groups/{id}", s.handlePatchGroup)
	mux.HandleFunc("DELETE /Groups/{id}", s.handleDeleteGroup)

	return s.requireBearer(mux)
}

func (s *Server) requireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		token := s.getToken()
		// A short token is treated as no token: it is guessable, and SCIM
		// provisions accounts.
		if len(token) < MinTokenLen || len(auth) <= len(prefix) || auth[:len(prefix)] != prefix ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(token)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid or missing bearer token")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{schemaServiceConfig},
		"patch":          map[string]bool{"supported": true},
		"bulk":           map[string]bool{"supported": false},
		"filter":         map[string]any{"supported": true, "maxResults": 200},
		"changePassword": map[string]bool{"supported": false},
		"sort":           map[string]bool{"supported": false},
		"etag":           map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{{
			"type": "oauthbearertoken", "name": "Bearer Token", "description": "Static bearer token",
		}},
	})
}

func (s *Server) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []map[string]any{
		{"id": "User", "name": "User", "endpoint": "/Users", "schema": schemaUser},
		{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": schemaGroup},
	})
}

func (s *Server) handleSchemas(w http.ResponseWriter, r *http.Request) {
	// A minimal stub — enough for clients that fetch this only to satisfy a
	// discovery step, not to drive their own schema-aware UI against us.
	writeJSON(w, http.StatusOK, []map[string]any{
		{"id": schemaUser, "name": "User"},
		{"id": schemaGroup, "name": "Group"},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, scimError{Schemas: []string{schemaError}, Status: httpStatusText(status), Detail: detail})
}

func httpStatusText(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "400"
	case http.StatusUnauthorized:
		return "401"
	case http.StatusNotFound:
		return "404"
	case http.StatusConflict:
		return "409"
	default:
		return "500"
	}
}
