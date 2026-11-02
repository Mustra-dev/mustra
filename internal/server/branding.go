package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// Console branding: an admin can replace mustra's default mark with their
// own logo, shown in the top bar, the rail, and the flyout header. The
// image is stored as the data URL the browser produced (see schema.sql's
// settings table — one more runtime-editable value, no new storage
// machinery, and small enough that a row in Postgres beats standing up
// object storage for a single file).

// maxLogoBytes caps the decoded image. A console logo is a few tens of KB;
// 512KB leaves room for a generous retina PNG while keeping the value a
// sane size to hold in memory and hand back on every page load.
const maxLogoBytes = 512 * 1024

// allowedLogoTypes deliberately excludes SVG: an <img> won't run script
// inside one, but a logo is raster in practice and leaving XML out of the
// upload path removes a whole class of question.
var allowedLogoTypes = map[string]string{
	"image/png":  "png",
	"image/jpeg": "jpg",
	"image/webp": "webp",
	"image/gif":  "gif",
}

// logoURL returns the versioned URL for the current logo, or "" when none
// is set (the console then keeps its built-in mark).
func (s *Server) logoURL() string {
	dataURL, version := s.live.logo()
	if dataURL == "" {
		return ""
	}
	return "/branding/logo?v=" + strconv.FormatUint(version, 10)
}

// parseLogoDataURL validates a `data:image/...;base64,...` URL and returns
// its media type and decoded bytes.
func parseLogoDataURL(dataURL string) (mediaType string, data []byte, err error) {
	return parseImageDataURL(dataURL, maxLogoBytes)
}

// parseImageDataURL is parseLogoDataURL with the size cap chosen by the
// caller: the Self Service window takes a background image as well as a
// logo, and the two have different sensible limits.
func parseImageDataURL(dataURL string, maxBytes int) (mediaType string, data []byte, err error) {
	const prefix = "data:"
	if !strings.HasPrefix(dataURL, prefix) {
		return "", nil, fmt.Errorf("not a data URL")
	}
	rest := dataURL[len(prefix):]
	comma := strings.Index(rest, ",")
	if comma < 0 {
		return "", nil, fmt.Errorf("malformed data URL")
	}
	meta, payload := rest[:comma], rest[comma+1:]
	if !strings.HasSuffix(meta, ";base64") {
		return "", nil, fmt.Errorf("data URL must be base64-encoded")
	}
	mediaType = strings.TrimSuffix(meta, ";base64")
	if _, ok := allowedLogoTypes[mediaType]; !ok {
		return "", nil, fmt.Errorf("unsupported image type %q — use PNG, JPEG, WebP, or GIF", mediaType)
	}
	data, err = base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", nil, fmt.Errorf("decode image: %w", err)
	}
	if len(data) == 0 {
		return "", nil, fmt.Errorf("image is empty")
	}
	if len(data) > maxBytes {
		return "", nil, fmt.Errorf("image is %d KB — the limit is %d KB", len(data)/1024, maxBytes/1024)
	}
	return mediaType, data, nil
}

// handleBrandingLogo serves the uploaded logo as a real image. Registered
// on the unauthenticated mux so the login page can show it too; the URL
// carries a version so it's safe to cache hard and still update instantly
// when an admin replaces the file.
func (s *Server) handleBrandingLogo(w http.ResponseWriter, r *http.Request) {
	dataURL, _ := s.live.logo()
	if dataURL == "" {
		http.NotFound(w, r)
		return
	}
	mediaType, data, err := parseLogoDataURL(dataURL)
	if err != nil {
		s.logger.Warn("stored console logo is unreadable", "error", err)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(data)
}

type updateBrandingRequest struct {
	// LogoDataURL is the image as a `data:image/png;base64,...` URL, or ""
	// to clear it and go back to mustra's built-in mark.
	LogoDataURL string `json:"logo_data_url"`
}

// updateBrandingResponse is what POST /api/admin/branding answers.
type updateBrandingResponse struct {
	LogoURL string `json:"logo_url"`
}

func (s *Server) handleUpdateBranding(w http.ResponseWriter, r *http.Request) {
	var req updateBrandingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())

	if req.LogoDataURL != "" {
		if _, _, err := parseLogoDataURL(req.LogoDataURL); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := s.store.SetSetting(r.Context(), settingBrandingLogoDataURL, req.LogoDataURL, u.Username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.live.setLogo(req.LogoDataURL)

	if req.LogoDataURL == "" {
		s.logger.Info("console logo reset to default", "updated_by", u.Username)
	} else {
		s.logger.Info("console logo updated", "updated_by", u.Username)
	}
	writeJSONResponse(w, updateBrandingResponse{LogoURL: s.logoURL()})
}
