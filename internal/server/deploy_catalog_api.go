package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const deploySettingsKey = "deploy.settings"

func (s *Server) deploySettings(ctx context.Context) (proto.DeploySettings, error) {
	settings := proto.DefaultDeploySettings()
	raw, e := s.store.GetSetting(ctx, deploySettingsKey)
	if e != nil {
		return settings, e
	}
	if raw != "" {
		e = json.Unmarshal([]byte(raw), &settings)
	}
	return settings, e
}
func (s *Server) handleDeploySettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		settings, e := s.deploySettings(r.Context())
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		writeJSONResponse(w, settings)
		return
	}
	var settings proto.DeploySettings
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&settings) != nil {
		http.Error(w, "invalid settings", 400)
		return
	}
	for _, logs := range []proto.DeployLogSettings{settings.EndpointLogs, settings.ServerLogs} {
		if e := deploylog.Validate(logs); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
	}
	if settings.CacheMB < 1 || settings.CacheMB > 1048576 {
		http.Error(w, "cache must be 1–1048576 MB", 400)
		return
	}
	raw, _ := json.Marshal(settings)
	if e := s.store.SetSetting(r.Context(), deploySettingsKey, string(raw), auth.CurrentUser(r.Context()).Username); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if s.nc != nil {
		agents, e := s.store.ListAgents(r.Context(), s.staleAfter())
		if e == nil {
			payload, _ := json.Marshal(proto.AgentCommand{Cmd: "deploy_settings", DeploySettings: &settings})
			go func() {
				for _, a := range agents {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					_, _ = s.nc.RequestWithContext(ctx, bnats.Cmd(a.AgentID), payload)
					cancel()
				}
			}()
		}
	}
	s.audit(r.Context(), auditEvent{Action: "deploy.settings", Actor: auth.CurrentUser(r.Context()).Username, Severity: "notice"})
	writeJSONResponse(w, settings)
}

// deployRevisionsRequest is the body of POST
// /api/deploy/packages/{id}/revisions; the GET reads none.
type deployRevisionsRequest struct {
	Name  string `json:"name"`
	Label string `json:"label" api:"required"`
	// RevisionID, when it names an unpublished draft of this package,
	// rewrites that draft instead of creating another. Without it every
	// save minted a revision, so iterating on one version left a stack
	// of identical labels behind.
	RevisionID string                 `json:"revision_id"`
	Definition proto.DeployDefinition `json:"definition" api:"required"`
}

// deployRevisionsResponse is what GET /api/deploy/packages/{id}/revisions
// answers.
type deployRevisionsResponse struct {
	Revisions []proto.DeployRevision `json:"revisions"`
}

func (s *Server) handleDeployRevisions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		packageID := r.PathValue("id")
		if packageID == "all" {
			packageID = ""
		}
		revisions, e := s.store.ListDeployRevisions(r.Context(), packageID)
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		writeJSONResponse(w, deployRevisionsResponse{Revisions: revisions})
		return
	}
	var body deployRevisionsRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&body) != nil {
		http.Error(w, "invalid draft", 400)
		return
	}
	if e := deploy.ValidateDefinition(body.Definition, false); e != nil {
		writeDefinitionError(w, e)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	packageID := r.PathValue("id")
	// Checked before anything is written. It used to be checked after the
	// package row was inserted, so saving a new application without a
	// version label returned 400 and still left an empty package behind --
	// which is where the duplicate catalog entries came from.
	body.Label = strings.TrimSpace(body.Label)
	if body.Label == "" {
		writeDefinitionError(w, &deploy.DefinitionError{Section: "details", Message: "give this a version number (such as 1.0.2) before saving"})
		return
	}
	if !versionNumberRe.MatchString(body.Label) {
		writeDefinitionError(w, &deploy.DefinitionError{Section: "details", Message: "the version number can only contain digits and dots, such as 1.0.2"})
		return
	}
	if packageID == "new" {
		if strings.TrimSpace(body.Name) == "" {
			http.Error(w, "application name is required", 400)
			return
		}
		packageID = idgen.New("sw-")
		_, e := s.store.UpsertSoftwarePackage(r.Context(), store.SoftwarePackage{ID: packageID, Name: body.Name, Kind: func() string {
			if body.Definition.Kind == store.KindAction {
				return store.KindAction
			}
			return store.KindSoftware
		}(), Commands: map[string]store.SoftwareOps{}, CreatedBy: who})
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
	}
	pkg, err := s.store.GetSoftwarePackage(r.Context(), packageID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if pkg == nil {
		http.NotFound(w, r)
		return
	}
	if (pkg.Kind == store.KindAction) != (body.Definition.Kind == store.KindAction) {
		http.Error(w, "package kind cannot change between revisions", 400)
		return
	}
	// Editing a draft updates it. A published revision is immutable, so
	// editing one necessarily starts a new draft -- which is why a miss here
	// falls through to creating one rather than failing.
	if body.RevisionID != "" {
		rev, e := s.store.UpdateDeployDraft(r.Context(), proto.DeployRevision{
			ID: body.RevisionID, PackageID: packageID, Label: body.Label, Definition: body.Definition, CreatedBy: who})
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		if rev != nil {
			writeJSONResponse(w, rev)
			return
		}
	}

	rev, e := s.store.SaveDeployDraft(r.Context(), proto.DeployRevision{ID: idgen.New("rev-"), PackageID: packageID, Label: body.Label, Definition: body.Definition, CreatedBy: who})
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	writeJSONResponse(w, rev)
}

// versionNumberRe: a package version is numbers and dots (1, 1.0, 1.0.2).
var versionNumberRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// publishDeployRequest is the body of POST /api/deploy/revisions/{revision}/publish.
type publishDeployRequest struct {
	RetirePrevious bool `json:"retire_previous"`
}

// publishDeployResponse is what POST
// /api/deploy/revisions/{revision}/publish answers: the published version,
// and the versions it retired.
type publishDeployResponse struct {
	*proto.DeployRevision
	RetiredPrevious []string `json:"retired_previous"`
}

func (s *Server) handlePublishDeploy(w http.ResponseWriter, r *http.Request) {
	// retire_previous: retire this package's other live versions,
	// noting that this one superseded them. An empty body is fine.
	var opts publishDeployRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&opts)
	rev, e := s.store.GetDeployRevision(r.Context(), r.PathValue("revision"))
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if rev == nil {
		http.NotFound(w, r)
		return
	}
	if rev.Published {
		http.Error(w, "revision is already published", 409)
		return
	}
	if e = deploy.ValidateDefinition(rev.Definition, true); e == nil {
		e = s.snapshotDeployChecks(r.Context(), &rev.Definition)
	}
	if e == nil {
		e = s.validateDeployDependencies(r.Context(), rev.PackageID, rev.Definition, map[string]bool{rev.PackageID: true})
	}
	if e != nil {
		writeDefinitionError(w, e)
		return
	}
	if e = s.store.PublishDeployRevision(r.Context(), *rev); e != nil {
		http.Error(w, e.Error(), 409)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	s.audit(r.Context(), auditEvent{Action: "deploy.publish", Actor: who, Target: rev.PackageID, Severity: "notice", Detail: map[string]any{"revision": rev.ID}})
	rev.Published = true
	retired := []string{}
	if opts.RetirePrevious {
		note := "Superseded by " + firstNonEmptyString(rev.Label, rev.ID)
		others, _ := s.store.ListDeployRevisions(r.Context(), rev.PackageID)
		for _, o := range others {
			if o.ID == rev.ID || !o.Published || o.Retired {
				continue
			}
			if err := s.store.RetireDeployRevision(r.Context(), o.ID, false, note, who); err != nil {
				s.logger.Warn("retiring a superseded version failed", "revision", o.ID, "error", err)
				continue
			}
			retired = append(retired, firstNonEmptyString(o.Label, o.ID))
			s.audit(r.Context(), auditEvent{Action: "deploy.retire", Actor: who, Target: o.ID, Severity: "notice", Detail: map[string]any{"note": note}})
		}
	}
	writeJSONResponse(w, publishDeployResponse{rev, retired})
}
func walkDeployChecks(d *proto.DeployDefinition, visit func(*proto.DeployCheck, string) error, script func(*proto.DeployScript, string) error) error {
	var check func(*proto.DeployCheck, string) error
	check = func(c *proto.DeployCheck, os string) error {
		if c == nil {
			return nil
		}
		if e := visit(c, os); e != nil {
			return e
		}
		if c.Script != nil {
			if e := script(c.Script, os); e != nil {
				return e
			}
		}
		for i := range c.Children {
			if e := check(&c.Children[i], os); e != nil {
				return e
			}
		}
		return nil
	}
	var steps func([]proto.DeployStep, string) error
	steps = func(ss []proto.DeployStep, os string) error {
		for i := range ss {
			if e := check(ss[i].If, os); e != nil {
				return e
			}
			if ss[i].Script != nil {
				if e := script(ss[i].Script, os); e != nil {
					return e
				}
			}
			for _, branch := range [][]proto.DeployStep{ss[i].Then, ss[i].Else} {
				if e := steps(branch, os); e != nil {
					return e
				}
			}
		}
		return nil
	}
	for i := range d.Variants {
		v := &d.Variants[i]
		for _, c := range []*proto.DeployCheck{v.Requirements, v.Detection} {
			if e := check(c, v.OS); e != nil {
				return e
			}
		}
		for name, a := range v.Actions {
			for _, c := range []*proto.DeployCheck{a.Requirements, a.Validation} {
				if e := check(c, v.OS); e != nil {
					return e
				}
			}
			if e := steps(a.Steps, v.OS); e != nil {
				return e
			}
			v.Actions[name] = a
		}
	}
	return nil
}
func (s *Server) snapshotDeployChecks(ctx context.Context, d *proto.DeployDefinition) error {
	sensors, e := s.store.ListCustomSensors(ctx)
	if e != nil {
		return e
	}
	byID := map[string]store.CustomSensor{}
	for _, c := range sensors {
		byID[c.ID] = c
		byID[c.SensorKind()] = c
	}
	return walkDeployChecks(d, func(check *proto.DeployCheck, os string) error {
		if check.Kind != "sensor" {
			return nil
		}
		c, ok := byID[check.SensorID]
		if !ok {
			if strings.HasPrefix(check.SensorID, "custom_") || strings.HasPrefix(check.SensorID, "csn-") {
				return fmt.Errorf("custom sensor %s does not exist", check.SensorID)
			}
			check.Sensor = nil
			return nil
		}
		if strings.TrimSpace(c.Commands[os]) == "" {
			return fmt.Errorf("sensor %s has no %s definition", c.Name, os)
		}
		if e := s.buildGoSensors(ctx, c); e != nil {
			return e
		}
		snapshot := &proto.DeploySensor{ID: c.ID, Name: c.Name, Fields: sensoroutput.Fields(c.Fields), Parameters: c.Parameters, Definitions: map[string]proto.CustomSensorDef{}}
		for platform, command := range c.Commands {
			snapshot.Definitions[platform] = proto.CustomSensorDef{ID: c.ID, Name: c.Name, Sensor: c.SensorKind(), Command: command, Platform: c.Platform(platform), Revision: c.Revision(platform), TimeoutSeconds: c.TimeoutSeconds}
		}
		check.Sensor = snapshot
		return nil
	}, func(script *proto.DeployScript, os string) error {
		if e := deploy.ValidateScript(*script, os); e != nil {
			return e
		}
		if script.Language != "go" {
			return nil
		}
		return s.buildGoSensors(ctx, store.CustomSensor{Commands: map[string]string{os: script.Source}, Platforms: map[string]proto.SensorPlatform{os: {Language: "go"}}})
	})
}
func (s *Server) validateDeployDependencies(ctx context.Context, pkg string, d proto.DeployDefinition, path map[string]bool) error {
	if len(path) > 32 {
		return fmt.Errorf("dependency graph exceeds 32 levels")
	}
	for _, v := range d.Variants {
		for _, a := range v.Actions {
			for _, dep := range a.Dependencies {
				if path[dep.PackageID] {
					return fmt.Errorf("dependency cycle involving %s", dep.PackageID)
				}
				rev, e := s.store.GetDeployRevision(ctx, dep.RevisionID)
				if e != nil {
					return e
				}
				if rev == nil || !rev.Published || rev.Retired || rev.PackageID != dep.PackageID {
					return fmt.Errorf("dependency must reference a published revision of its package")
				}
				path[dep.PackageID] = true
				e = s.validateDeployDependencies(ctx, dep.PackageID, rev.Definition, path)
				delete(path, dep.PackageID)
				if e != nil {
					return e
				}
			}
		}
	}
	return nil
}

// deployPackageMetadataRequest is the body of PUT
// /api/deploy/packages/{id}: a package's details, as opposed to what it
// installs or runs, which its revisions hold. Every field replaces the
// stored one as sent, so a field left out is cleared (enabled becomes
// false, group_ids empty); the console sends the whole package it loaded.
// Other package fields in the body (kind, version, commands, detect, …)
// are ignored.
type deployPackageMetadataRequest struct {
	// Name is the package's name in the catalog.
	Name string `json:"name" api:"required"`
	// Description is shown under the name in the catalog and in Self
	// Service.
	Description string `json:"description"`
	// Vendor is who makes the software.
	Vendor string `json:"vendor"`
	// Category groups the package in Self Service.
	Category string `json:"category"`
	// GroupIDs are the computer groups whose members see the package in
	// Self Service; each must exist.
	GroupIDs []string `json:"group_ids"`
	// SelfService offers the package in Self Service. An action package
	// is never offered, whatever this says.
	SelfService bool `json:"self_service"`
	// AllowRequests lets an endpoint's user ask for the package when it
	// is not offered to them. Never set for an action package.
	AllowRequests bool `json:"allow_requests"`
	// SelfServiceRevision pins Self Service to one published revision of
	// this package; empty uses the package's current one.
	SelfServiceRevision string `json:"self_service_revision"`
	// SelfServiceFollowLatest has Self Service install the latest
	// published revision rather than the pinned one.
	SelfServiceFollowLatest bool `json:"self_service_follow_latest"`
	// Enabled makes the package available to deploy.
	Enabled bool `json:"enabled"`
	// ExpireSeconds stops a deployment of the package being worth
	// attempting after that long; 0 never expires.
	ExpireSeconds int `json:"expire_seconds"`
}

func (s *Server) handleDeployPackageMetadata(w http.ResponseWriter, r *http.Request) {
	var body deployPackageMetadataRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&body) != nil {
		http.Error(w, "invalid package metadata", 400)
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
	if strings.TrimSpace(body.Name) == "" {
		http.Error(w, "name is required", 400)
		return
	}
	if body.SelfServiceRevision != "" {
		rev, e := s.store.GetDeployRevision(r.Context(), body.SelfServiceRevision)
		if e != nil || rev == nil || !rev.Published || rev.Retired || rev.PackageID != pkg.ID {
			http.Error(w, "select a published revision of this package", 400)
			return
		}
	}
	groups, e := s.store.ListComputerGroups(r.Context())
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	for _, id := range body.GroupIDs {
		found := false
		for _, g := range groups {
			found = found || g.ID == id
		}
		if !found {
			http.Error(w, "target group no longer exists", 400)
			return
		}
	}
	pkg.Name = body.Name
	pkg.Description = body.Description
	pkg.Vendor = body.Vendor
	pkg.Category = body.Category
	pkg.GroupIDs = body.GroupIDs
	if pkg.Kind == store.KindAction {
		body.SelfService = false
		body.AllowRequests = false
	}
	pkg.SelfService = body.SelfService
	pkg.AllowRequests = body.AllowRequests
	pkg.SelfServiceRevision = body.SelfServiceRevision
	pkg.SelfServiceFollowLatest = body.SelfServiceFollowLatest
	pkg.Enabled = body.Enabled
	pkg.ExpireSeconds = body.ExpireSeconds
	pkg.UpdatedBy = auth.CurrentUser(r.Context()).Username
	updated, e := s.store.UpsertSoftwarePackage(r.Context(), *pkg)
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "deploy.package.settings", Actor: auth.CurrentUser(r.Context()).Username, Target: pkg.ID, Severity: "notice"})
	writeJSONResponse(w, updated)
}

// writeDefinitionError answers a definition that failed validation with 400.
// One that belongs to a place in the editor (deploy.DefinitionError) goes as
// JSON with that place, so the console can open and highlight it; anything
// else stays plain text, which is what every caller already reads.
func writeDefinitionError(w http.ResponseWriter, e error) {
	var de *deploy.DefinitionError
	if errors.As(e, &de) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": de.Error(), "location": de})
		return
	}
	http.Error(w, e.Error(), http.StatusBadRequest)
}
