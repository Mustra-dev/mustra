package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// deployReferencesRequest is the body of POST
// /api/deploy/revisions/{revision}/references; the GET reads none.
type deployReferencesRequest struct {
	Replacement string            `json:"replacement" api:"required"`
	References  map[string]string `json:"references" api:"required"`
}

// deployReferenceList is what GET
// /api/deploy/revisions/{revision}/references answers.
type deployReferenceList struct {
	References []store.DeployReference `json:"references"`
}

// deployReferencesResponse is what POST
// /api/deploy/revisions/{revision}/references answers.
type deployReferencesResponse struct {
	Updated int `json:"updated"`
}

func (s *Server) handleDeployReferences(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("revision")
	refs, e := s.store.DeployReferences(r.Context(), source)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	replacement := r.URL.Query().Get("replacement")
	var body deployReferencesRequest
	if r.Method == http.MethodPost {
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil {
			http.Error(w, "invalid reference update", 400)
			return
		}
		replacement = body.Replacement
	}
	if replacement != "" {
		rev, e := s.store.GetDeployRevision(r.Context(), replacement)
		sourceRev, se := s.store.GetDeployRevision(r.Context(), source)
		if e != nil || se != nil {
			http.Error(w, "cannot read replacement version", 500)
			return
		}
		if rev == nil || sourceRev == nil || !rev.Published || rev.Retired || rev.PackageID != sourceRev.PackageID || rev.ID == source {
			http.Error(w, "select another active published version of this package", 400)
			return
		}
		for i := range refs {
			if e := validateRevisionInputs(rev.Definition, refs[i].Operation, refs[i].OS, refs[i].Parameters); e != nil {
				refs[i].Reason = e.Error()
			} else {
				refs[i].Compatible = true
			}
		}
	}
	if r.Method == http.MethodGet {
		writeJSONResponse(w, deployReferenceList{References: refs})
		return
	}
	if replacement == "" || len(body.References) == 0 {
		http.Error(w, "select a replacement and at least one reference", 400)
		return
	}
	selected := []store.DeployReference{}
	for _, ref := range refs {
		if fingerprint, ok := body.References[ref.Key]; ok {
			if !ref.Compatible || fingerprint != ref.Fingerprint {
				http.Error(w, "reference changed or is incompatible; refresh the preview", 409)
				return
			}
			selected = append(selected, ref)
		}
	}
	if len(selected) != len(body.References) {
		http.Error(w, "references changed since preview", 409)
		return
	}
	if e = s.store.UpdateDeployReferences(r.Context(), source, replacement, auth.CurrentUser(r.Context()).Username, selected); e != nil {
		http.Error(w, e.Error(), 409)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "deploy.references.update", Actor: auth.CurrentUser(r.Context()).Username, Target: source, Severity: "notice", Detail: map[string]any{"replacement": replacement, "references": body.References}})
	writeJSONResponse(w, deployReferencesResponse{Updated: len(selected)})
}

// deleteDeployDraftResponse is what DELETE /api/deploy/revisions/{revision}
// answers.
type deleteDeployDraftResponse struct {
	Deleted         bool  `json:"deleted"`
	TestRunsRemoved int64 `json:"test_runs_removed"`
}

// handleDeleteDeployDraft removes an unpublished revision.
//
// Drafts only, and deliberately so. Retiring is the answer for a published
// revision: deployments, schedules and playbook steps were pinned to it, and
// deleting it would rewrite the record of what endpoints were actually sent.
// A draft has been sent to nobody, so there is nothing to preserve -- except
// when it was dispatched as a test, which the foreign key from deploy_jobs
// catches and which is reported rather than swallowed.
func (s *Server) handleDeleteDeployDraft(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("revision")
	rev, e := s.store.GetDeployRevision(r.Context(), id)
	if e != nil {
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}
	if rev == nil {
		http.NotFound(w, r)
		return
	}
	if rev.Published {
		http.Error(w, "a published version cannot be deleted; retire it instead, so what was already deployed stays on the record", http.StatusBadRequest)
		return
	}

	jobs, deleted, e := s.store.DeleteDeployDraft(r.Context(), id)
	if e != nil {
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}
	if !deleted {
		http.NotFound(w, r)
		return
	}

	// The count matters in the record: this is the one place a draft's test
	// results are removed, and the audit entry is what remains of them.
	s.audit(r.Context(), auditEvent{
		Action: "deploy.draft_delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: firstNonEmptyString(rev.Label, id), Severity: "notice",
		Detail: map[string]any{"revision": id, "package_id": rev.PackageID, "test_runs_removed": jobs},
	})
	writeJSONResponse(w, deleteDeployDraftResponse{Deleted: true, TestRunsRemoved: jobs})
}

// retireDeployRequest is the body of POST /api/deploy/revisions/{revision}/retire.
type retireDeployRequest struct {
	EntirePackage bool   `json:"entire_package"`
	Note          string `json:"note"` // why, kept on the version
}

func (s *Server) handleRetireDeploy(w http.ResponseWriter, r *http.Request) {
	rev, e := s.store.GetDeployRevision(r.Context(), r.PathValue("revision"))
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if rev == nil {
		http.NotFound(w, r)
		return
	}
	var body retireDeployRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil || len(body.Note) > 500 {
		http.Error(w, "invalid retirement", 400)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	if e := s.store.RetireDeployRevision(r.Context(), r.PathValue("revision"), body.EntirePackage, strings.TrimSpace(body.Note), who); e != nil {
		http.Error(w, e.Error(), 409)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "deploy.retire", Actor: who, Target: r.PathValue("revision"), Severity: "notice", Detail: map[string]any{"entire_package": body.EntirePackage, "note": body.Note}})
	w.WriteHeader(http.StatusNoContent)
}
