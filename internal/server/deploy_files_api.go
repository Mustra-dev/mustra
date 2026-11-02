package server

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// importDeployFileRequest is the body of POST /api/deploy/packages/{id}/import.
type importDeployFileRequest struct {
	URL          string `json:"url" api:"required"`
	Name         string `json:"name"`
	SHA256       string `json:"sha256"`
	CredentialID string `json:"credential_id"`
}

func (s *Server) handleImportDeployFile(w http.ResponseWriter, r *http.Request) {
	var body importDeployFileRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&body) != nil {
		http.Error(w, "invalid import", 400)
		return
	}
	u, e := url.Parse(body.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		http.Error(w, "use an HTTPS URL without embedded credentials", 400)
		return
	}
	if body.Name == "" {
		body.Name = filepath.Base(u.Path)
	}
	if body.Name == "" || body.Name == "." || body.Name == ".." || strings.ContainsAny(body.Name, "/\\") {
		http.Error(w, "use a bare filename", 400)
		return
	}
	pkg, e := s.store.GetSoftwarePackage(r.Context(), r.PathValue("id"))
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if pkg == nil {
		http.NotFound(w, r)
		return
	}
	req, e := http.NewRequestWithContext(r.Context(), http.MethodGet, body.URL, nil)
	if e != nil {
		http.Error(w, "invalid URL", 400)
		return
	}
	allowed := s.importAllowedHosts(r.Context())
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if body.CredentialID != "" && !allowed[host] {
		// A stored secret goes only to a host an administrator approved;
		// otherwise "import" is a way to post the vault to any server.
		s.audit(r.Context(), auditEvent{Action: "deploy.file.import", Actor: auth.CurrentUser(r.Context()).Username,
			Target: host, Outcome: "denied", Severity: "warning", Detail: map[string]any{"reason": "credential to a host that is not allowlisted", "credential_id": body.CredentialID}})
		http.Error(w, host+" is not on the import allowlist, so no stored credential will be sent to it; an administrator can add it under Settings (Import allowlist)", http.StatusForbidden)
		return
	}
	if body.CredentialID != "" {
		if s.vault == nil {
			http.Error(w, "credential vault is not configured", 503)
			return
		}
		credential, e := s.vault.Resolve(r.Context(), body.CredentialID)
		if e != nil || credential == nil {
			http.Error(w, "credential is unavailable", 400)
			return
		}
		if credential.AuthType != "password" {
			http.Error(w, "HTTP imports require a password/token credential", 400)
			return
		}
		if credential.Username == "" {
			req.Header.Set("Authorization", "Bearer "+credential.Secret)
		} else {
			req.SetBasicAuth(credential.Username, credential.Secret)
		}
	}
	client := guardedHTTPClient(allowed, 30*time.Minute)
	response, e := client.Do(req)
	if e != nil {
		s.logger.Warn("package import failed", "host", host, "error", e)
		http.Error(w, "download failed; verify source URL and access", 502)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		http.Error(w, "source returned "+response.Status, 502)
		return
	}
	if e = os.MkdirAll(packageFileDir(), 0750); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	id := idgen.New("pf-")
	path := filepath.Join(packageFileDir(), id)
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	h := sha256.New()
	size, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(response.Body, maxPackageFileBytes+1))
	ce := f.Close()
	if e == nil {
		e = ce
	}
	digest := fmt.Sprintf("%x", h.Sum(nil))
	if size > maxPackageFileBytes || e != nil || body.SHA256 != "" && !strings.EqualFold(body.SHA256, digest) {
		os.Remove(path)
		http.Error(w, "download exceeded the size limit, failed, or did not match SHA-256", 400)
		return
	}
	record, e := s.store.CreatePackageFile(r.Context(), store.PackageFile{ID: id, PackageID: pkg.ID, Name: body.Name, SizeBytes: size, SHA256: digest, CreatedBy: auth.CurrentUser(r.Context()).Username})
	if e != nil {
		os.Remove(path)
		http.Error(w, e.Error(), 500)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "deploy.file.import", Actor: auth.CurrentUser(r.Context()).Username, Target: pkg.ID, Severity: "notice", Detail: map[string]any{"file": id, "sha256": digest, "size": size}})
	writeJSONResponse(w, record)
}
func (s *Server) handleDeployFile(w http.ResponseWriter, r *http.Request) {
	record, e := s.store.GetDeployJob(r.Context(), r.PathValue("job"))
	if e != nil || record == nil {
		http.NotFound(w, r)
		return
	}
	if deploy.Terminal(record.Status) || !record.Job.ExpiresAt.IsZero() && time.Now().After(record.Job.ExpiresAt) {
		http.Error(w, "deployment download grant has ended", 403)
		return
	}
	fileID := r.PathValue("file")
	valid := false
	for _, p := range record.Job.Packages {
		f, ok := p.Files[fileID]
		if !ok {
			continue
		}
		u, e := url.Parse(f.URL)
		if e == nil && u.Path == r.URL.Path && subtle.ConstantTimeCompare([]byte(u.Query().Get("t")), []byte(r.URL.Query().Get("t"))) == 1 && u.Query().Get("t") != "" {
			valid = true
		}
	}
	if !valid {
		http.Error(w, "invalid download token", 403)
		return
	}
	path, pe := packageFilePath(fileID)
	if pe != nil {
		http.NotFound(w, r)
		return
	}
	f, e := s.store.GetPackageFile(r.Context(), fileID)
	if e != nil || f == nil {
		http.NotFound(w, r)
		return
	}
	// Served on the console's own origin, so it must never be rendered: an
	// HTML "package file" sniffed as text/html would run with whatever
	// session the browser that opened the link holds.
	serveAsDownload(w, r, path, f.Name)
}
func (s *Server) handleDeployLogs(w http.ResponseWriter, r *http.Request) {
	record, e := s.store.GetDeployJob(r.Context(), r.PathValue("job"))
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if record == nil {
		http.NotFound(w, r)
		return
	}
	dir, de := deployLogDir(record.Job.AgentID)
	if de != nil {
		http.Error(w, "this deployment's endpoint id cannot name a log directory", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+record.Job.ID+`-logs.zip"`)
		z := zip.NewWriter(w)
		out, err := z.Create(record.Job.ID + ".jsonl")
		if err == nil {
			enc := json.NewEncoder(out)
			err = deploylog.Walk(r.Context(), dir, record.Job.ID, func(ev proto.DeployEvent) error { return enc.Encode(ev) })
		}
		if err != nil {
			if out, e := z.Create("READ-ERROR.txt"); e == nil {
				fmt.Fprint(out, "Incomplete export: ", err)
			}
		}
		if e := z.Close(); e != nil {
			s.logger.Warn("export run logs", "error", e)
		}
		return
	}
	before, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("before"))
	result, e := deploylog.Read(r.Context(), dir, deploylog.ReadOptions{JobID: record.Job.ID, Search: r.URL.Query().Get("search"), Before: before})
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	writeJSONResponse(w, result)
}

func bindDeployArtifact(artifact *proto.SensorArtifact, jobID, base string) {
	if artifact == nil {
		return
	}
	u, e := url.Parse(artifact.File.URL)
	if e != nil {
		return
	}
	key := filepath.Base(u.Path)
	artifact.File.URL = strings.TrimRight(base, "/") + "/deploy-artifacts/" + jobID + "/" + key + "?t=" + idgen.New("dl-")
}
func (s *Server) handleDeployArtifact(w http.ResponseWriter, r *http.Request) {
	record, e := s.store.GetDeployJob(r.Context(), r.PathValue("job"))
	if e != nil || record == nil {
		http.NotFound(w, r)
		return
	}
	if deploy.Terminal(record.Status) || !record.Job.ExpiresAt.IsZero() && time.Now().After(record.Job.ExpiresAt) {
		http.Error(w, "deployment download grant has ended", 403)
		return
	}
	key := r.PathValue("key")
	if !goArtifactID.MatchString(key) {
		http.NotFound(w, r)
		return
	}
	valid := false
	check := func(a *proto.SensorArtifact) {
		if a == nil {
			return
		}
		u, e := url.Parse(a.File.URL)
		if e == nil && u.Path == r.URL.Path && u.Query().Get("t") != "" && subtle.ConstantTimeCompare([]byte(u.Query().Get("t")), []byte(r.URL.Query().Get("t"))) == 1 {
			valid = true
		}
	}
	for _, p := range record.Job.Packages {
		d := proto.DeployDefinition{Variants: []proto.DeployVariant{p.Variant}}
		_ = walkDeployChecks(&d, func(c *proto.DeployCheck, os string) error {
			if c.Sensor != nil {
				for _, def := range c.Sensor.Definitions {
					check(def.Artifact)
				}
			}
			return nil
		}, func(script *proto.DeployScript, os string) error { check(script.Artifact); return nil })
	}
	if !valid {
		http.Error(w, "invalid download token", 403)
		return
	}
	serveAsDownload(w, r, goArtifactPath(key), "sensor.bin")
}
