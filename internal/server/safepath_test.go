package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPackageFilePathRejectsTraversal(t *testing.T) {
	t.Setenv("MUSTRA_PACKAGE_FILE_DIR", t.TempDir())
	for _, id := range []string{
		"", ".", "..", "../../etc/passwd", "..%2F..%2Fetc", "pf-../x",
		"pf-0123456789abcdef0123456789abcdeg", "pf-0123456789abcdef0123456789abcdef/../x",
		"/etc/passwd", `pf-..\..\x`, "PF-0123456789ABCDEF0123456789ABCDEF",
	} {
		if p, err := packageFilePath(id); err == nil {
			t.Errorf("packageFilePath(%q) = %q, want an error", id, p)
		}
	}
	good := "pf-0123456789abcdef0123456789abcdef"
	p, err := packageFilePath(good)
	if err != nil {
		t.Fatalf("packageFilePath(%q): %v", good, err)
	}
	if filepath.Dir(p) != filepath.Clean(packageFileDir()) {
		t.Fatalf("path %q is not directly inside %q", p, packageFileDir())
	}
}

func TestPathWithin(t *testing.T) {
	base := t.TempDir()
	for _, elems := range [][]string{{".."}, {"a", ".."}, {"a/b"}, {`a\b`}, {".hidden"}, {""}, {"x", "../../etc"}} {
		if p, err := pathWithin(base, elems...); err == nil {
			t.Errorf("pathWithin(%v) = %q, want an error", elems, p)
		}
	}
	if _, err := pathWithin(base, "deploy-logs", "agt-0123abcd"); err != nil {
		t.Fatalf("ordinary agent log dir refused: %v", err)
	}
	if _, err := deployLogDir("../../../root"); err == nil {
		t.Fatal("deployLogDir accepted a traversal agent id")
	}
}

// TestDeletePackageFileRejectsEncodedTraversal drives the real handler with
// the request the review used: the mux decodes %2F into the path value, and
// the handler must refuse before touching the store or the disk.
func TestDeletePackageFileRejectsEncodedTraversal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MUSTRA_PACKAGE_FILE_DIR", filepath.Join(dir, "pkg"))
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /api/software/files/{fileID}", s.handleDeletePackageFile)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/software/files/..%2Fvictim", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("victim file was removed: %v", err)
	}
}

func TestServeAsDownloadNeverRenders(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("<html><script>alert(1)</script></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	serveAsDownload(rec, httptest.NewRequest(http.MethodGet, "/x", nil), p, "evil.html")
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" || cd[:10] != "attachment" {
		t.Fatalf("Content-Disposition = %q", cd)
	}
}
