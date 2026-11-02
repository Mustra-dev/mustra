package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Package files: the payload a package needs, staged to the endpoint before
// its command runs.
//
// Without them every command has to fetch its own installer, which quietly
// limits the catalog to software reachable from a URL the endpoint can hit —
// ruling out anything licensed, anything internal, and anything on a segment
// with no egress, which between them is most of what anyone actually
// deploys.
//
// The bytes live on disk rather than in Postgres. A 400 MB MSI in a row is
// carried by every backup, every replica and every planner statistic
// thereafter. MinIO is in the compose stack and would be the right answer at
// scale, but it is currently unused, and adding an S3 client to reach a
// service on the same host is a dependency bought for nothing.

const (
	// maxPackageFileBytes caps one upload. Generous enough for an office
	// suite, bounded enough that a mis-click cannot fill the disk.
	maxPackageFileBytes = 2 << 30 // 2 GiB
	// packageFileTokenTTL is how long a download token is good for. It has
	// to outlast a slow endpoint pulling a large file over a poor link, and
	// nothing beyond that.
	packageFileTokenTTL = 2 * time.Hour
)

func packageFileDir() string {
	if d := os.Getenv("MUSTRA_PACKAGE_FILE_DIR"); d != "" {
		return d
	}
	return "/var/lib/mustra/package-files"
}

// downloadTokens gates package-file downloads.
//
// The agent authenticates to NATS, not to HTTP, so it cannot present a
// session to fetch a file. Rather than leaving payloads on an open URL —
// these are installers, often licensed — the server mints a random token
// per dispatch and sends it over the already-authenticated command channel.
// Anyone who can read that channel could already run commands on the
// endpoint, so the token grants nothing they did not have.
type downloadTokens struct {
	mu     sync.Mutex
	issued map[string]tokenGrant
}

type tokenGrant struct {
	fileID  string
	expires time.Time
}

func newDownloadTokens() *downloadTokens {
	return &downloadTokens{issued: map[string]tokenGrant{}}
}

func (d *downloadTokens) mint(fileID string) string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	tok := hex.EncodeToString(raw)

	d.mu.Lock()
	defer d.mu.Unlock()
	// Sweep on write. There is no separate reaper because the only thing
	// that grows this map is minting, so the only moment it can need
	// trimming is here.
	now := time.Now()
	for k, g := range d.issued {
		if now.After(g.expires) {
			delete(d.issued, k)
		}
	}
	d.issued[tok] = tokenGrant{fileID: fileID, expires: now.Add(packageFileTokenTTL)}
	return tok
}

func (d *downloadTokens) valid(tok, fileID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	g, ok := d.issued[tok]
	if !ok || time.Now().After(g.expires) {
		return false
	}
	return g.fileID == fileID
}

// ---- HTTP ----

// listPackageFilesResponse is what GET /api/software/{id}/files answers.
type listPackageFilesResponse struct {
	Files []store.PackageFile `json:"files"`
}

func (s *Server) handleListPackageFiles(w http.ResponseWriter, r *http.Request) {
	files, err := s.store.ListPackageFiles(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if files == nil {
		files = []store.PackageFile{}
	}
	writeJSONResponse(w, listPackageFilesResponse{Files: files})
}

func (s *Server) handleUploadPackageFile(w http.ResponseWriter, r *http.Request) {
	packageID := r.PathValue("id")
	pkg, err := s.store.GetSoftwarePackage(r.Context(), packageID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pkg == nil {
		http.Error(w, "no such package", http.StatusNotFound)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPackageFileBytes)
	src, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "expected a file upload in the \"file\" field: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer src.Close()

	// The endpoint writes this name into a directory, so it must be a bare
	// filename: a name of "../../etc/cron.d/x" would otherwise escape the
	// staging directory on every machine at once.
	name := filepath.Base(strings.ReplaceAll(header.Filename, "\\", "/"))
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		http.Error(w, "that filename is not usable", http.StatusBadRequest)
		return
	}

	if err := os.MkdirAll(packageFileDir(), 0o750); err != nil {
		http.Error(w, "could not prepare storage: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fileID := idgen.New("pf-")
	dst := filepath.Join(packageFileDir(), fileID)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		http.Error(w, "could not store the file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Hashed while it is written rather than by re-reading afterwards: the
	// file is large by assumption, and the hash is what the endpoint checks
	// its download against.
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(out, hasher), src)
	closeErr := out.Close()
	if err != nil || closeErr != nil {
		os.Remove(dst)
		http.Error(w, "could not store the file", http.StatusInternalServerError)
		return
	}

	rec, err := s.store.CreatePackageFile(r.Context(), store.PackageFile{
		ID: fileID, PackageID: packageID, Name: name, SizeBytes: size,
		SHA256:    hex.EncodeToString(hasher.Sum(nil)),
		CreatedBy: auth.CurrentUser(r.Context()).Username,
	})
	if err != nil {
		os.Remove(dst)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "software.file.upload", Actor: auth.CurrentUser(r.Context()).Username,
		Target: pkg.Name, Severity: "notice",
		Detail: map[string]any{"file": name, "bytes": size, "sha256": rec.SHA256},
	})
	s.logger.Info("package file uploaded", "package", pkg.Name, "file", name, "bytes", size)
	writeJSONResponse(w, rec)
}

func (s *Server) handleDeletePackageFile(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("fileID")
	// The id becomes a path on disk. ServeMux unescapes %2F inside a path
	// value, so without this "..%2F..%2F" deleted any file the server could.
	path, perr := packageFilePath(fileID)
	if perr != nil {
		http.Error(w, "no such file", http.StatusNotFound)
		return
	}
	// Only a file the database knows about is removed: the row existing is
	// what makes the blob ours to delete.
	rec, err := s.store.GetPackageFile(r.Context(), fileID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rec == nil || rec.ID != fileID {
		http.Error(w, "no such file", http.StatusNotFound)
		return
	}
	if err := s.store.DeletePackageFile(r.Context(), fileID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "software.file.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: rec.Name, Severity: "notice", Detail: map[string]any{"file_id": fileID, "package_id": rec.PackageID},
	})
	// Best effort: the row is the source of truth, and an orphaned blob is
	// wasted disk rather than a correctness problem.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		s.logger.Warn("could not remove package file from disk", "file_id", fileID, "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDownloadPackageFile serves a staged file to an endpoint. Not behind
// a session — an agent has no session — but behind a per-dispatch token sent
// over the authenticated command channel.
func (s *Server) handleDownloadPackageFile(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("fileID")
	path, perr := packageFilePath(fileID)
	if perr != nil {
		http.Error(w, "no such file", http.StatusNotFound)
		return
	}
	tok := r.URL.Query().Get("t")
	if tok == "" || !s.dlTokens.valid(tok, fileID) {
		http.Error(w, "not authorized to download this file", http.StatusForbidden)
		return
	}
	rec, err := s.store.GetPackageFile(r.Context(), fileID)
	if err != nil || rec == nil {
		http.Error(w, "no such file", http.StatusNotFound)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "the file is missing from storage", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", rec.Name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Mustra-SHA256", rec.SHA256)
	http.ServeContent(w, r, rec.Name, rec.CreatedAt, f)
}
