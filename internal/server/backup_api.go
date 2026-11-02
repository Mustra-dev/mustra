package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// maxUploadedBackup bounds an uploaded archive. A restore reads the whole
// thing, and an unbounded upload is a way to fill the output volume.
const maxUploadedBackup = 8 << 30 // 8 GiB

// listBackupsResponse is what GET /api/backups answers.
type listBackupsResponse struct {
	Backups  []BackupRecord `json:"backups"`
	Excluded []string       `json:"excluded"`
	Settings BackupSettings `json:"settings"`
}

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	all, err := s.listBackups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := s.backupSettings(r.Context())
	// What a backup does not carry matters as much as what it does, and the
	// console is the only place an operator will read it.
	writeJSONResponse(w, listBackupsResponse{
		Backups:  all,
		Settings: cfg,
		Excluded: []string{
			"MUSTRA_CREDENTIAL_ENCRYPTION_KEY, which lives in deploy/.env. " +
				"Stored credentials are encrypted with it: restore onto a deployment with a different key and those rows cannot be decrypted.",
			"The NATS certificates in deploy/nats/certs/, also on the host.",
		},
	})
}

// createBackupRequest is the body of POST /api/backups.
type createBackupRequest struct {
	Note                string `json:"note"`
	IncludePackageFiles bool   `json:"include_package_files"`
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	var body createBackupRequest
	_ = json.NewDecoder(r.Body).Decode(&body)

	u := auth.CurrentUser(r.Context())
	rec, err := s.createBackup(r.Context(), u.Username, body.Note, body.IncludePackageFiles)
	if err != nil {
		s.logger.Error("backup failed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "backup.create", Actor: u.Username, Target: rec.ID, Severity: "notice",
		Detail: map[string]any{"bytes": rec.Bytes, "package_files": rec.IncludesPackageFiles},
	})
	s.pruneBackups(s.backupSettings(r.Context()).Keep)
	writeJSONResponse(w, rec)
}

func (s *Server) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	path, err := backupPath(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "no such backup", http.StatusNotFound)
		return
	}
	defer f.Close()
	u := auth.CurrentUser(r.Context())
	// Downloading a backup takes every credential-bearing row in the
	// database off this machine, so it is audited like any other export of
	// the whole estate.
	s.audit(r.Context(), auditEvent{
		Action: "backup.download", Actor: u.Username, Target: id, Severity: "notice",
	})
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+id+".tar.gz\"")
	http.ServeContent(w, r, id+".tar.gz", statModTime(f), f)
}

// deleteBackupResponse is what DELETE /api/backups/{id} answers.
type deleteBackupResponse struct {
	Deleted string `json:"deleted"`
}

func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	path, err := backupPath(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := os.Remove(path); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "backup.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: id, Severity: "warning",
	})
	writeJSONResponse(w, deleteBackupResponse{Deleted: id})
}

func (s *Server) handleUpdateBackupSettings(w http.ResponseWriter, r *http.Request) {
	var body BackupSettings
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.HourUTC < 0 || body.HourUTC > 23 {
		http.Error(w, "the hour must be between 0 and 23", http.StatusBadRequest)
		return
	}
	if body.Keep < 1 || body.Keep > 365 {
		http.Error(w, "keep between 1 and 365 backups", http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	for key, value := range map[string]string{
		settingBackupScheduleEnabled: boolText(body.Enabled),
		settingBackupHourUTC:         fmt.Sprint(body.HourUTC),
		settingBackupKeep:            fmt.Sprint(body.Keep),
		settingBackupIncludePackages: boolText(body.IncludePackageFiles),
	} {
		if err := s.store.SetSetting(r.Context(), key, value, u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.audit(r.Context(), auditEvent{
		Action: "backup.settings", Actor: u.Username, Target: "schedule", Severity: "notice",
		Detail: map[string]any{"enabled": body.Enabled, "hour_utc": body.HourUTC, "keep": body.Keep},
	})
	writeJSONResponse(w, body)
}

// handleRestoreBackup applies an archive and then stops the server. An
// archive refused before anything was applied (not a mustra backup,
// malformed, too large, unsigned or foreign without ?external=1, failing
// its checksums, or stopped by the dump screen) answers 422.
//
// The confirmation is not decoration. Restoring replaces every row in the
// database, and the shape of mistake worth preventing is the one where
// somebody meant to press Download.
func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r.Context())

	if r.URL.Query().Get("confirm") != "replace-everything" {
		http.Error(w, "a restore replaces the whole database; it needs confirm=replace-everything",
			http.StatusPreconditionRequired)
		return
	}
	// An archive this server did not sign is restored only by an
	// administrator, deliberately, and only after a strict screen.
	external := r.URL.Query().Get("external") == "1"
	if external && !s.requireAdminOr(w, r, auth.PermBackupsRestore, "restore a backup made elsewhere") {
		return
	}
	if err := s.auditStrict(r.Context(), auditEvent{Action: "backup.restore_requested", Actor: u.Username,
		Target: firstNonEmptyString(r.URL.Query().Get("id"), "uploaded archive"), Severity: "critical",
		Detail: map[string]any{"external": external}}); err != nil {
		http.Error(w, "the restore could not be recorded in the audit log, so it was not started", http.StatusServiceUnavailable)
		return
	}

	path, cleanup, err := s.backupToRestore(r)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := s.restoreBackup(r.Context(), path, u.Username, external)
	if err != nil {
		s.logger.Error("restore failed", "error", err)
		s.audit(r.Context(), auditEvent{
			Action: "backup.restore", Actor: u.Username, Target: filepath.Base(path),
			Outcome: "failed", Severity: "critical", Detail: map[string]any{"error": err.Error(), "applied": false},
		})
		// Each status is written as a literal so the drift test can check
		// it against the route's declaration.
		if errors.Is(err, errRestoreRefused) {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "backup.restore", Actor: u.Username, Target: result.Manifest.ID, Severity: "critical",
		Detail: map[string]any{
			"taken_at": result.Manifest.CreatedAt, "applied": true,
			"package_files": result.PackageFiles,
		},
	})
	writeJSONResponse(w, result)

	// Answer first, then go. Every cached thing in this process -- the
	// connection pool, the settings snapshot, the live hub -- refers to a
	// database that no longer exists. The restart policy brings the server
	// back clean; coming back is not optional, so this is SIGTERM to
	// ourselves rather than an exit code somebody has to interpret.
	go func() {
		time.Sleep(time.Second)
		s.logger.Warn("restarting after a restore")
		restartSelf()
	}()
}

// backupToRestore resolves either an archive already on the server or one
// being uploaded. An upload lands in a temp file so the same validation
// runs over both.
func (s *Server) backupToRestore(r *http.Request) (string, func(), error) {
	if id := r.URL.Query().Get("id"); id != "" {
		path, err := backupPath(id)
		return path, nil, err
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return "", nil, fmt.Errorf("send either ?id=<backup> or an archive as multipart form field \"file\"")
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return "", nil, fmt.Errorf("no archive was uploaded")
	}
	defer file.Close()
	if !strings.HasSuffix(header.Filename, ".tar.gz") {
		return "", nil, fmt.Errorf("a mustra backup is a .tar.gz archive")
	}
	tmp, err := os.CreateTemp("", "mustra-upload-*.tar.gz")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.Remove(tmp.Name()) }
	if _, err := io.Copy(tmp, io.LimitReader(file, maxUploadedBackup)); err != nil {
		tmp.Close()
		return "", cleanup, err
	}
	tmp.Close()
	return tmp.Name(), cleanup, nil
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
