package server

import (
	"net/http"
	"regexp"
	"strconv"
)

// Short numeric IDs (store/idnums.go). The console shows each endpoint,
// deployment and package by its number; these routes accept the number
// wherever they take the text ID, by rewriting the path before the router
// sees it, so no handler has to know numbers exist.
var shortIDRoutes = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`^(/api/agents/)(\d+)(/.*)?$`), "agent"},
	{regexp.MustCompile(`^(/endpoint/)(\d+)(/.*)?$`), "agent"},
	{regexp.MustCompile(`^(/api/patches/deployments/)(\d+)(/.*)?$`), "run"},
	{regexp.MustCompile(`^(/api/deployments/)(\d+)(/.*)?$`), "run"},
	{regexp.MustCompile(`^(/api/software/)(\d+)(/.*)?$`), "package"},
	{regexp.MustCompile(`^(/api/deploy/packages/)(\d+)(/.*)?$`), "package"},
	{regexp.MustCompile(`^(/api/reveal/rules/)(\d+)(/.*)?$`), "rule"},
}

func (s *Server) resolveShortIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, rt := range shortIDRoutes {
			m := rt.re.FindStringSubmatch(r.URL.Path)
			if m == nil {
				continue
			}
			n, err := strconv.ParseInt(m[2], 10, 64)
			if err != nil {
				break
			}
			if id, _ := s.store.IDForNumber(r.Context(), rt.kind, n); id != "" {
				// A page reads its ID from its own address, so a page link by
				// number redirects; an API call is rewritten in place.
				if m[1] == "/endpoint/" {
					target := m[1] + id + m[3]
					if r.URL.RawQuery != "" {
						target += "?" + r.URL.RawQuery
					}
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
				r2 := r.Clone(r.Context())
				r2.URL.Path = m[1] + id + m[3]
				r2.URL.RawPath = ""
				next.ServeHTTP(w, r2)
				return
			}
			break
		}
		next.ServeHTTP(w, r)
	})
}

// listIDNumbersResponse is what GET /api/idnums answers.
type listIDNumbersResponse struct {
	IDs map[string]int64 `json:"ids"`
}

// GET /api/idnums: text ID → number, for the console to display.
func (s *Server) handleIDNumbers(w http.ResponseWriter, r *http.Request) {
	ids, err := s.store.IDNumbers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "private, max-age=30")
	writeJSONResponse(w, listIDNumbersResponse{IDs: ids})
}
