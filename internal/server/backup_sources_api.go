package server

// Backup systems: Proxmox Backup Server and Rubrik Security Cloud read
// directly (internal/server/backupsrc), alongside what the backups sensor
// reports from Proxmox VE nodes. They add what nothing in Proxmox made
// (a host backed up with the PBS client, Rubrik-protected servers), how
// full the storage is, and verification.
//
// A source is reached through the same guard as a webhook: an internal
// address only when an administrator allowlisted the host. A PBS server's
// own self-signed certificate is pinned by its SHA-256 fingerprint rather
// than trusted blind. The secret is sealed, never returned, and follows
// its server: changing where a source points needs it typed again.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/backupsrc"
	"github.com/mustra-dev/mustra/internal/store"
)

const backupSourcePollEvery = 15 * time.Minute

func backupSourceAAD(id string) string { return "backup_source/secret/" + id }

// backupSourceView is a source as the API shows it: no secret, whether
// one is stored, and the newest read's size.
type backupSourceView struct {
	store.BackupSource
	SecretSet bool `json:"secret_set"`
	// Items is how many protected things the newest read listed.
	Items  int               `json:"items"`
	Stores []backupsrc.Store `json:"stores"`
}

func viewBackupSource(b store.BackupSource) backupSourceView {
	v := backupSourceView{BackupSource: b, SecretSet: b.Secret != "", Stores: []backupsrc.Store{}}
	var r backupsrc.Result
	if len(b.LastResult) > 0 && json.Unmarshal(b.LastResult, &r) == nil {
		v.Items = len(r.Items)
		if r.Stores != nil {
			v.Stores = r.Stores
		}
	}
	return v
}

// listBackupSourcesResponse is what GET /api/backup-sources answers.
type listBackupSourcesResponse struct {
	Sources []backupSourceView `json:"sources"`
	// Kinds are the systems a source can be, by kind, with their names.
	Kinds map[string]string `json:"kinds"`
}

func (s *Server) handleListBackupSources(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListBackupSources(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]backupSourceView, 0, len(list))
	for _, b := range list {
		out = append(out, viewBackupSource(b))
	}
	writeJSONResponse(w, listBackupSourcesResponse{Sources: out, Kinds: backupsrc.Kinds})
}

// saveBackupSourceRequest is the body of POST /api/backup-sources and PUT
// /api/backup-sources/{id}.
type saveBackupSourceRequest struct {
	// Kind is pbs or rubrik; it cannot change on an update.
	Kind string `json:"kind"`
	Name string `json:"name" api:"required"`
	// URL is https://host:8007 for PBS, https://<account>.my.rubrik.com
	// for Rubrik Security Cloud.
	URL string `json:"url" api:"required"`
	// TokenID is the PBS API token (user@realm!name) or the Rubrik
	// service account's client ID.
	TokenID string `json:"token_id" api:"required"`
	// Secret is the token secret or client secret. Empty on an update
	// keeps the stored one, unless the URL, token or fingerprint changes.
	Secret string `json:"secret" api:"writeonly"`
	// Fingerprint pins the server's certificate (SHA-256, hex, colons
	// optional): how a PBS server's self-signed certificate is trusted.
	Fingerprint string `json:"fingerprint"`
	// Datastore limits PBS to one datastore; empty reads them all.
	Datastore string `json:"datastore"`
	// Enabled left out enables the source.
	Enabled *bool `json:"enabled"`
}

func normalizeFingerprint(fp string) (string, error) {
	fp = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(fp)))
	if fp == "" {
		return "", nil
	}
	if b, err := hex.DecodeString(fp); err != nil || len(b) != sha256.Size {
		return "", errors.New("the fingerprint is a SHA-256 certificate fingerprint: 64 hex digits, colons optional")
	}
	return fp, nil
}

func (s *Server) handleSaveBackupSource(w http.ResponseWriter, r *http.Request) {
	var req saveBackupSourceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	var old *store.BackupSource
	if id := r.PathValue("id"); id != "" {
		var err error
		if old, err = s.store.GetBackupSource(ctx, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if old == nil {
			http.Error(w, "no such backup source", http.StatusNotFound)
			return
		}
		req.Kind = old.Kind
	}
	if _, ok := backupsrc.Kinds[req.Kind]; !ok {
		http.Error(w, "kind must be pbs or rubrik", http.StatusBadRequest)
		return
	}
	req.Name, req.TokenID, req.Datastore = strings.TrimSpace(req.Name), strings.TrimSpace(req.TokenID), strings.TrimSpace(req.Datastore)
	if strings.TrimSpace(req.URL) == "" {
		http.Error(w, "a backup source needs its URL", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(req.URL), "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" {
		http.Error(w, "the URL is the system's https address only, like https://pbs.example.com:8007", http.StatusBadRequest)
		return
	}
	req.URL = u.String()
	fp, err := normalizeFingerprint(req.Fingerprint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.TokenID == "" {
		http.Error(w, "a backup source needs a name and a token or client ID", http.StatusBadRequest)
		return
	}
	src := store.BackupSource{Kind: req.Kind, Name: req.Name, URL: req.URL, TokenID: req.TokenID, Fingerprint: fp, Datastore: req.Datastore, Enabled: req.Enabled == nil || *req.Enabled}
	switch {
	case req.Secret != "":
	case old == nil:
		http.Error(w, "a new backup source needs its secret", http.StatusBadRequest)
		return
	case old.URL != req.URL || old.TokenID != req.TokenID || old.Fingerprint != fp:
		// The stored secret goes only to the server, identity and
		// certificate it was saved for.
		http.Error(w, "changing the URL, token or fingerprint needs the secret entered again", http.StatusBadRequest)
		return
	}
	if old != nil {
		src.ID, src.CreatedBy, src.Secret = old.ID, old.CreatedBy, old.Secret
	} else {
		src.ID, src.CreatedBy = newID("bks-"), who
	}
	if req.Secret != "" {
		if src.Secret, err = sealWith(s.vault, backupSourceAAD(src.ID), req.Secret); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	saved, err := s.store.SaveBackupSource(ctx, src)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "backups.source.create"
	if old != nil {
		action = "backups.source.update"
	}
	s.audit(ctx, auditEvent{Action: action, Actor: who, Target: saved.Name, Severity: "notice",
		Detail: map[string]any{"id": saved.ID, "kind": saved.Kind, "url": saved.URL, "token_id": saved.TokenID, "secret_changed": req.Secret != ""}})
	// Read it at once, so the answer says whether it works.
	if saved.Enabled {
		s.pollBackupSource(ctx, *saved)
		if fresh, err := s.store.GetBackupSource(ctx, saved.ID); err == nil && fresh != nil {
			saved = fresh
		}
	}
	writeJSONResponse(w, viewBackupSource(*saved))
}

// deleteBackupSourceResponse is what DELETE /api/backup-sources/{id}
// answers.
type deleteBackupSourceResponse struct {
	Deleted string `json:"deleted"`
}

func (s *Server) handleDeleteBackupSource(w http.ResponseWriter, r *http.Request) {
	src, err := s.store.GetBackupSource(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if src == nil {
		http.Error(w, "no such backup source", http.StatusNotFound)
		return
	}
	if _, err := s.store.DeleteBackupSource(r.Context(), src.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "backups.source.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: src.Name, Severity: "notice",
		Detail: map[string]any{"id": src.ID, "kind": src.Kind}})
	writeJSONResponse(w, deleteBackupSourceResponse{Deleted: src.ID})
}

// POST /api/backup-sources/{id}/poll reads the source now.
func (s *Server) handlePollBackupSource(w http.ResponseWriter, r *http.Request) {
	src, err := s.store.GetBackupSource(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if src == nil {
		http.Error(w, "no such backup source", http.StatusNotFound)
		return
	}
	s.pollBackupSource(r.Context(), *src)
	if fresh, err := s.store.GetBackupSource(r.Context(), src.ID); err == nil && fresh != nil {
		src = fresh
	}
	writeJSONResponse(w, viewBackupSource(*src))
}

// backupSourceClient is the guarded client, with the certificate pinned
// when the source has a fingerprint.
func (s *Server) backupSourceClient(ctx context.Context, src store.BackupSource) *http.Client {
	c := guardedHTTPClient(s.webhookAllowedHosts(ctx), 2*time.Minute)
	if src.Fingerprint != "" {
		if t, ok := c.Transport.(*http.Transport); ok {
			want := src.Fingerprint
			t.TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				// Verification is the pin below, not the system roots: a
				// PBS server's certificate is its own.
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
					if len(raw) == 0 {
						return errors.New("the server sent no certificate")
					}
					sum := sha256.Sum256(raw[0])
					if got := hex.EncodeToString(sum[:]); got != want {
						return fmt.Errorf("the server's certificate fingerprint is %s, not the pinned one", got)
					}
					return nil
				},
			}
		}
	}
	return c
}

// backupPollMu keeps the loop and a "poll now" from reading one source
// twice at once.
var backupPollMu sync.Mutex

func (s *Server) pollBackupSource(ctx context.Context, src store.BackupSource) {
	backupPollMu.Lock()
	defer backupPollMu.Unlock()
	secret, err := openWith(s.vault, backupSourceAAD(src.ID), src.Secret)
	var result []byte
	if err == nil {
		pctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		var r backupsrc.Result
		r, err = backupsrc.Fetch(pctx, s.backupSourceClient(ctx, src), backupsrc.Config{
			Kind: src.Kind, URL: src.URL, TokenID: src.TokenID, Secret: secret, Datastore: src.Datastore})
		cancel()
		if err == nil {
			result, err = json.Marshal(r)
			s.notifyFailedBackupJobs(ctx, src, r)
		}
	}
	msg := ""
	if err != nil {
		msg = err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		if src.LastError != msg {
			s.logger.Warn("backup source read failed", "source", src.Name, "kind", src.Kind, "error", msg)
		}
	}
	if rerr := s.store.RecordBackupSourcePoll(ctx, src.ID, result, msg); rerr != nil {
		s.logger.Warn("recording a backup source read failed", "source", src.Name, "error", rerr)
	}
}

func (s *Server) backupSourceLoop(ctx context.Context) {
	poll := func() {
		list, err := s.store.ListBackupSources(ctx)
		if err != nil {
			return
		}
		for _, src := range list {
			if src.Enabled && ctx.Err() == nil {
				s.pollBackupSource(ctx, src)
			}
		}
	}
	// A minute after start, so a restart does not hammer every system.
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
	}
	poll()
	ticker := time.NewTicker(backupSourcePollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

// notifyFailedBackupJobs raises one notification per job run that failed:
// a run is new when its end time differs from the one the previous read
// recorded, so a job that keeps failing notifies once a run, not once a
// read.
func (s *Server) notifyFailedBackupJobs(ctx context.Context, src store.BackupSource, r backupsrc.Result) {
	var prev backupsrc.Result
	_ = json.Unmarshal(src.LastResult, &prev)
	seen := map[string]bool{}
	for _, j := range prev.Jobs {
		if j.Failed() && j.LastEnd != nil {
			seen[j.Kind+"/"+j.ID+"@"+j.LastEnd.String()] = true
		}
	}
	first := len(src.LastResult) == 0
	for _, j := range r.Jobs {
		if !j.Failed() || j.LastEnd == nil || seen[j.Kind+"/"+j.ID+"@"+j.LastEnd.String()] {
			continue
		}
		// On the very first read, an old failure is history, not news.
		if first && time.Since(*j.LastEnd) > 48*time.Hour {
			continue
		}
		name := map[string]string{"verify": "Verification", "prune": "Prune", "gc": "Garbage collection", "sync": "Sync"}[j.Kind]
		s.notify(ctx, "warning", "Backups", fmt.Sprintf("%s job failed on %s", firstNonEmpty(name, j.Kind), src.Name),
			fmt.Sprintf("Datastore %s, job %s: %s", j.Store, j.ID, safeTruncate(j.State, 300)), "/backup-status")
	}
}
