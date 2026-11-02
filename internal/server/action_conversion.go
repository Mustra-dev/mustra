package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// convertActionResponse is what POST
// /api/deploy/packages/{id}/convert-action answers.
type convertActionResponse struct {
	Message   string                 `json:"message"`
	Revisions []proto.DeployRevision `json:"revisions"`
}

func (s *Server) handleConvertAction(w http.ResponseWriter, r *http.Request) {
	pkg, e := s.store.GetSoftwarePackage(r.Context(), r.PathValue("id"))
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if pkg == nil || pkg.Kind != store.KindAction || pkg.DeployRevision != "" {
		http.Error(w, "select a legacy action package", 400)
		return
	}
	if pkg.Detect.Fact != "" {
		http.Error(w, "This managed agent-update package must retain its special version targeting; it cannot be converted to an unconditional action", 400)
		return
	}
	files, e := s.store.ListPackageFiles(r.Context(), pkg.ID)
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	created := []proto.DeployRevision{}
	for _, operation := range []string{"install", "remove"} {
		definition := proto.DeployDefinition{Version: 2, Kind: store.KindAction, ReviewRequired: true, Variants: []proto.DeployVariant{}}
		for _, p := range pkg.Parameters {
			definition.Parameters = append(definition.Parameters, proto.DeployParameter{Name: p.Name, Label: p.Label, Type: p.Type, Default: p.Default, Required: p.Required, Options: p.Options, Min: p.Min, Max: p.Max})
		}
		for _, platform := range []string{"windows", "darwin", "linux"} {
			ops := pkg.Commands[platform]
			source := ops.Install
			if operation == "remove" {
				source = ops.Remove
			}
			if strings.TrimSpace(source) == "" {
				continue
			}
			language := "shell"
			if platform == "windows" {
				language = "powershell"
			}
			timeout := pkg.CommandTimeoutSeconds
			if timeout <= 0 {
				timeout = 900
			}
			action := proto.DeployAction{Identity: "administrator", DownloadSeconds: 1800, Steps: []proto.DeployStep{{ID: "run", Name: "Run", Script: &proto.DeployScript{Language: language, Source: source, TimeoutSeconds: timeout}}}}
			definition.Variants = append(definition.Variants, proto.DeployVariant{ID: platform, OS: platform, Actions: map[string]proto.DeployAction{"run": action}})
		}
		if len(definition.Variants) == 0 {
			continue
		}
		name := pkg.Name
		if operation == "remove" {
			name += " — compensating action"
		}
		copy := store.SoftwarePackage{ID: idgen.New("sw-"), Name: name, Description: pkg.Description, Kind: store.KindAction, Commands: map[string]store.SoftwareOps{}, GroupIDs: pkg.GroupIDs, ExpireSeconds: pkg.ExpireSeconds, CreatedBy: who}
		if _, e = s.store.UpsertSoftwarePackage(r.Context(), copy); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		for _, f := range files {
			id := idgen.New("pf-")
			srcPath, e := packageFilePath(f.ID)
			if e != nil {
				http.Error(w, e.Error(), 500)
				return
			}
			src, e := os.Open(srcPath)
			if e != nil {
				http.Error(w, e.Error(), 500)
				return
			}
			dst, e := os.OpenFile(filepath.Join(packageFileDir(), id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
			if e != nil {
				src.Close()
				http.Error(w, e.Error(), 500)
				return
			}
			_, e = io.Copy(dst, src)
			src.Close()
			ce := dst.Close()
			if e == nil {
				e = ce
			}
			if e != nil {
				http.Error(w, e.Error(), 500)
				return
			}
			f.ID = id
			f.PackageID = copy.ID
			f.CreatedBy = who
			if _, e = s.store.CreatePackageFile(r.Context(), f); e != nil {
				http.Error(w, e.Error(), 500)
				return
			}
		}
		rev, e := s.store.SaveDeployDraft(r.Context(), proto.DeployRevision{ID: idgen.New("rev-"), PackageID: copy.ID, Label: "1", Definition: definition, CreatedBy: who})
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		created = append(created, *rev)
	}
	s.audit(r.Context(), auditEvent{Action: "deploy.action.convert", Actor: who, Target: pkg.ID, Severity: "notice", Detail: map[string]any{"drafts": len(created)}})
	writeJSONResponse(w, convertActionResponse{Revisions: created, Message: fmt.Sprintf("Created %d drafts. Review script language and parameter environment bindings, and assign copied files to shared or platform scope. Original package and consumers remain unchanged.", len(created))})
}
