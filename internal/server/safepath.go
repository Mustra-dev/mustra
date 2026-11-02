package server

import (
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Filesystem paths built from anything a request or an agent supplied.
//
// Go's ServeMux unescapes %2F inside a {param}, so a path value is not a
// single path segment just because it came from one: "..%2F..%2Fetc" arrives
// as "../../etc". Every place that turns request or agent input into a path
// on disk goes through two checks here — a strict shape for the identifier,
// and a confirmation that the joined path is still inside the directory it
// was meant for — so a mistake in one is caught by the other.

// packageFileIDPattern is the only shape idgen.New("pf-") produces.
var packageFileIDPattern = regexp.MustCompile(`^pf-[0-9a-f]{32}$`)

// validPackageFileID reports whether id is a package-file identifier the
// server could have minted. Anything else never reaches the filesystem.
func validPackageFileID(id string) bool { return packageFileIDPattern.MatchString(id) }

// pathSegmentPattern is what a single directory or file name built from
// external input may look like: no separators, no leading dot (so neither
// "." nor ".." nor hidden files), bounded length.
var pathSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)*$`)

// safePathSegment reports whether s may be used as one path element.
func safePathSegment(s string) bool {
	return len(s) > 0 && len(s) <= 128 && pathSegmentPattern.MatchString(s)
}

// pathWithin joins base with elems and returns the result only when every
// element is a plain segment and the cleaned path is still inside base.
// The second check is the one that matters if the first is ever loosened.
func pathWithin(base string, elems ...string) (string, error) {
	for _, e := range elems {
		if !safePathSegment(e) {
			return "", fmt.Errorf("unsafe path element %q", e)
		}
	}
	cleanBase := filepath.Clean(base)
	joined := filepath.Join(append([]string{cleanBase}, elems...)...)
	rel, err := filepath.Rel(cleanBase, joined)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path escapes %s", cleanBase)
	}
	return joined, nil
}

// packageFilePath is the on-disk location of one staged package file, or an
// error when id is not one the server minted.
func packageFilePath(id string) (string, error) {
	if !validPackageFileID(id) {
		return "", fmt.Errorf("invalid package file id")
	}
	return pathWithin(packageFileDir(), id)
}

// deployLogDir is where one agent's deployment logs live. The agent id is
// reported by the agent, so it is checked like any other external input.
func deployLogDir(agentID string) (string, error) {
	return pathWithin(packageFileDir(), "deploy-logs", agentID)
}

// serveAsDownload sends a stored file as an opaque attachment. Anything an
// operator or agent put on disk is served this way from the console origin:
// a sniffed text/html or image/svg+xml would execute as the console.
func serveAsDownload(w http.ResponseWriter, r *http.Request, path, name string) {
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "private, no-store")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, "", st.ModTime(), f)
}
