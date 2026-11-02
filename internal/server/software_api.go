package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"bytes"
	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

// Software deployment. The model is the one the problem settles on, because
// it's the right decomposition: a *package* says how to install, update and
// remove one piece of software per platform and how to recognize it; an
// *applicability scan* decides, per endpoint, which of those operations
// makes sense; and a *deployment* runs one operation against a target,
// tracking each device separately.
//
// The applicability states are the useful part. Rather than "deploy and
// hope", every endpoint lands in exactly one bucket before anything runs:
//
//	installed        — already has it, at the version the package declares
//	update_eligible  — has it, at a different version
//	install_eligible — doesn't have it, and meets the requirements
//	not_applicable   — no command for this OS, or fails a requirement
//
// which is what makes "deploy to everyone who needs it" a safe thing to
// click.

const (
	stateInstalled       = "installed"
	stateUpdateEligible  = "update_eligible"
	stateInstallEligible = "install_eligible"
	stateNotApplicable   = "not_applicable"
)

type applicabilityRow struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Platform string `json:"platform"`
	Site     string `json:"site"`
	Online   bool   `json:"online"`
	State    string `json:"state"`
	Found    string `json:"found_version,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// ---- catalog CRUD ----

// listSoftwareResponse is what GET /api/software answers.
type listSoftwareResponse struct {
	Applicability map[string]map[string]int `json:"applicability"`
	Packages      []store.SoftwarePackage   `json:"packages"`
	// SelfServicePlatforms maps each package offered in Self Service to
	// the platforms its Self Service version can be installed on there,
	// by the rule the endpoint window applies. An endpoint's architecture,
	// distribution and OS version, and the package's requirements, can
	// still rule a machine out.
	SelfServicePlatforms map[string][]string `json:"self_service_platforms"`
}

func (s *Server) handleListSoftware(w http.ResponseWriter, r *http.Request) {
	pkgs, err := s.store.ListSoftwarePackages(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pkgs == nil {
		pkgs = []store.SoftwarePackage{}
	}
	// Applicability counts alongside each package, so the catalog answers
	// "who needs this?" without opening every row.
	counts := map[string]map[string]int{}
	if rows, err := s.applicabilityAll(r.Context(), pkgs); err == nil {
		counts = rows
	}
	writeJSONResponse(w, listSoftwareResponse{Packages: pkgs, Applicability: counts,
		SelfServicePlatforms: s.selfServicePlatformsAll(r.Context(), pkgs)})
}

func (s *Server) handleUpsertSoftware(w http.ResponseWriter, r *http.Request) {
	var body store.SoftwarePackage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	// Drop platforms with no command at all: an entry that can't do
	// anything would show as applicable and then do nothing.
	cleaned := map[string]store.SoftwareOps{}
	for os, ops := range body.Commands {
		ops.Install = strings.TrimSpace(ops.Install)
		ops.Update = strings.TrimSpace(ops.Update)
		ops.Remove = strings.TrimSpace(ops.Remove)
		if ops.Install == "" && ops.Update == "" && ops.Remove == "" {
			continue
		}
		cleaned[strings.ToLower(strings.TrimSpace(os))] = ops
	}
	if len(cleaned) == 0 {
		http.Error(w, "give at least one command for at least one operating system", http.StatusBadRequest)
		return
	}
	body.Commands = cleaned

	// An action package has nothing to detect: it isn't installed, it just
	// runs. Defaulting its detection to its own name is what forced the
	// reboot packages to carry a fake "__never_installed__" app name.
	body.Kind = strings.ToLower(strings.TrimSpace(body.Kind))
	// Assigned back, not just tested. Validating a trimmed copy and storing
	// the raw value let "detect.fact": " agent_version" pass the check and
	// then match neither the fact path (which compares exactly) nor the
	// plain-action path (which tests for empty) — so the package went back
	// to targeting every endpoint on every deploy, which is the exact
	// regression fact detection was added to prevent. The same shape as the
	// untrimmed indicator value fixed earlier tonight.
	body.Detect.Fact = strings.TrimSpace(body.Detect.Fact)
	if body.Detect.Fact != "" && body.Detect.Fact != store.FactAgentVersion {
		http.Error(w, "detect.fact must be "+store.FactAgentVersion+" or empty", http.StatusBadRequest)
		return
	}
	if body.Kind != store.KindAction {
		body.Kind = store.KindSoftware
	}
	if body.Kind == store.KindAction {
		// An action package has nothing to detect in the installed-apps
		// sense — but fact detection is a different thing, and clearing it
		// here is what left the agent-update package eligible on endpoints
		// that had just taken it.
		body.Detect = store.SoftwareDetect{Fact: body.Detect.Fact}
	} else if body.Detect.AppName == "" {
		body.Detect.AppName = body.Name // detecting by its own name is the sane default
	}

	if body.CommandTimeoutSeconds < 0 {
		body.CommandTimeoutSeconds = 0
	}
	if body.ExpireSeconds < 0 {
		body.ExpireSeconds = 0
	}
	if err := validateParameters(body.Parameters); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body.VersionSource = strings.TrimSpace(body.VersionSource)
	if err := validVersionSource(body.VersionSource); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.VersionSource != "" && (body.Kind == store.KindAction || body.Detect.Fact != "") {
		http.Error(w, "only a software package detected by name can follow an upstream release", http.StatusBadRequest)
		return
	}
	if id := r.PathValue("id"); id != "" {
		body.ID = id
	}
	if body.ID == "" {
		body.ID = idgen.New("sw-")
		body.CreatedBy = auth.CurrentUser(r.Context()).Username
	}

	pkg, err := s.store.UpsertSoftwarePackage(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("software package saved", "id", pkg.ID, "name", pkg.Name,
		"platforms", len(pkg.Commands), "by", auth.CurrentUser(r.Context()).Username)
	if pkg.VersionSource != "" {
		// Read the release now rather than up to six hours from now, so
		// the version shown is the one the package will ask for.
		s.followPackageVersion(r.Context(), *pkg, false)
		if fresh, err := s.store.GetSoftwarePackage(r.Context(), pkg.ID); err == nil && fresh != nil {
			pkg = fresh
		}
	}
	writeJSONResponse(w, pkg)
}

func (s *Server) handleDeleteSoftware(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// The package_files rows cascade with the package, so the blobs have to
	// be found BEFORE the delete or they are unreachable forever: nothing
	// left would name them, and they would sit on disk until somebody
	// noticed the volume filling up.
	revisions, err := s.store.ListDeployRevisions(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	published := 0
	for _, rev := range revisions {
		if rev.Published {
			published++
		}
	}
	if published > 0 {
		http.Error(w, fmt.Sprintf("Package has %d published Deploy revision(s); disable it instead of deleting what endpoints were sent", published), 409)
		return
	}
	// Only drafts left, so the package never published anything and there is
	// no history to protect. Take them with it -- otherwise a package that
	// was started and abandoned can never be removed, which is how four
	// identically named entries came to sit in the catalog.
	drafts, testRuns := 0, int64(0)
	for _, rev := range revisions {
		jobs, gone, derr := s.store.DeleteDeployDraft(r.Context(), rev.ID)
		if derr != nil {
			http.Error(w, derr.Error(), 500)
			return
		}
		if gone {
			drafts++
			testRuns += jobs
		}
	}
	if drafts > 0 {
		s.logger.Info("removing a package that never published", "package_id", id,
			"drafts", drafts, "test_runs", testRuns,
			"by", auth.CurrentUser(r.Context()).Username)
	}
	files, ferr := s.store.ListPackageFiles(r.Context(), id)
	if ferr != nil {
		// Refusing is the point of looking first. Carrying on would delete
		// the only rows that name these blobs while leaving them on disk —
		// exactly the "unreachable forever" the comment above describes,
		// reached by ignoring the error that told us we could not see them.
		// A delete that fails is recoverable; one that orphans is not.
		s.logger.Warn("refusing to delete a package whose files could not be listed",
			"package_id", id, "error", ferr)
		http.Error(w, "could not read this package's files, so deleting it now would leave them "+
			"on disk with nothing naming them: "+ferr.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.store.DeleteSoftwarePackage(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, f := range files {
		path, perr := packageFilePath(f.ID)
		if perr != nil {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("could not remove package file from disk", "file_id", f.ID, "error", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- discovery: seed the catalog from what the fleet already runs ----

// discoverSoftwareResponse is what GET /api/software/discover answers.
type discoverSoftwareResponse struct {
	Software []store.DiscoveredSoftware `json:"software"`
}

func (s *Server) handleDiscoverSoftware(w http.ResponseWriter, r *http.Request) {
	minDevices := 1
	if v := r.URL.Query().Get("min_devices"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			minDevices = n
		}
	}
	found, err := s.store.DiscoverInstalledSoftware(r.Context(), minDevices)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Mark what's already in the catalog so the list is a to-do rather than
	// a list to cross-reference by hand.
	pkgs, _ := s.store.ListSoftwarePackages(r.Context())
	known := map[string]bool{}
	for _, p := range pkgs {
		known[strings.ToLower(p.Name)] = true
		if p.Detect.AppName != "" {
			known[strings.ToLower(p.Detect.AppName)] = true
		}
	}
	for i := range found {
		found[i].InCatalog = known[strings.ToLower(found[i].Name)]
	}
	if found == nil {
		found = []store.DiscoveredSoftware{}
	}
	writeJSONResponse(w, discoverSoftwareResponse{Software: found})
}

// adoptSoftwareRequest is the body of POST /api/software/adopt.
type adoptSoftwareRequest struct {
	Name      string   `json:"name" api:"required"`
	Vendor    string   `json:"vendor"`
	Version   string   `json:"version"`
	Platforms []string `json:"platforms" api:"required"`
}

// handleAdoptSoftware turns discovered software into a catalog package,
// guessing the per-OS commands from the platforms it was found on. The
// guess is a starting point an operator edits, not something deployed
// blind — which is why the response is the created package rather than a
// deployment.
func (s *Server) handleAdoptSoftware(w http.ResponseWriter, r *http.Request) {
	var body adoptSoftwareRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	// The name is agent-reported inventory, and it ends up inside a shell
	// command: one endpoint reporting a "name" with a semicolon in it must
	// not become a command that runs on every other endpoint the package
	// is deployed to. So the package is saved disabled, for an operator to
	// read before it can be deployed, and a name that is not a plain
	// package identifier for the platform gets no command at all.
	pkg := store.SoftwarePackage{
		ID: idgen.New("sw-"), Kind: store.KindSoftware, Name: strings.TrimSpace(body.Name), Vendor: body.Vendor,
		Version: body.Version, Source: "discovered", Enabled: false,
		Detect:    store.SoftwareDetect{AppName: strings.TrimSpace(body.Name), Match: "exact"},
		Commands:  map[string]store.SoftwareOps{},
		CreatedBy: auth.CurrentUser(r.Context()).Username,
		Description: "Adopted from software already installed across the fleet. " +
			"Check the commands below, then enable the package to make it deployable.",
	}
	unsafe := false
	for _, os := range body.Platforms {
		ops, ok := guessCommands(os, pkg.Name)
		if !ok {
			if _, known := packageNamePatterns[os]; known {
				unsafe = true
			}
			continue
		}
		pkg.Commands[os] = ops
	}
	if len(pkg.Commands) == 0 {
		if unsafe {
			http.Error(w, "that name is not a plain package identifier, so no command was generated for it — create the package by hand and write the commands yourself", http.StatusBadRequest)
			return
		}
		http.Error(w, "couldn't guess a command for any of those platforms — create the package by hand", http.StatusBadRequest)
		return
	}

	out, err := s.store.UpsertSoftwarePackage(r.Context(), pkg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("software package adopted from fleet", "name", out.Name,
		"by", auth.CurrentUser(r.Context()).Username)
	writeJSONResponse(w, out)
}

// packageNamePatterns are the characters a package identifier may use
// per platform's package manager: Debian package names, Homebrew formula
// and cask tokens (with a tap prefix and an @version), winget identifiers
// (Publisher.Name). Everything a shell could read as more than a word —
// spaces, quotes, metacharacters — is outside all three, by construction
// rather than by a list of bad characters.
var packageNamePatterns = map[string]*regexp.Regexp{
	"linux":   regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`),
	"darwin":  regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._+@-]|/[A-Za-z0-9])*$`),
	"windows": regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`),
}

// guessCommands proposes the native package-manager commands for a
// platform. Deliberately the boring answer for each OS rather than
// anything clever — an operator who needs something else edits it, and a
// wrong guess they can see beats a hidden one. A name that is not a plain
// package identifier for the platform gets no command: the name came from
// an endpoint's inventory, and the command runs through a shell.
func guessCommands(os, name string) (store.SoftwareOps, bool) {
	if re, ok := packageNamePatterns[os]; !ok || !re.MatchString(name) || len(name) > 200 {
		return store.SoftwareOps{}, false
	}
	switch os {
	case "linux":
		return store.SoftwareOps{
			Install: "apt-get install -y " + name,
			Update:  "apt-get install -y --only-upgrade " + name,
			Remove:  "apt-get remove -y " + name,
		}, true
	case "darwin":
		return store.SoftwareOps{
			Install: "brew install " + name,
			Update:  "brew upgrade " + name,
			Remove:  "brew uninstall " + name,
		}, true
	case "windows":
		return store.SoftwareOps{
			Install: "winget install --silent --accept-package-agreements --accept-source-agreements --id " + name,
			Update:  "winget upgrade --silent --accept-package-agreements --accept-source-agreements --id " + name,
			Remove:  "winget uninstall --silent --id " + name,
		}, true
	}
	return store.SoftwareOps{}, false
}

// ---- applicability ----

// softwareApplicabilityResponse is what GET
// /api/software/{id}/applicability answers.
type softwareApplicabilityResponse struct {
	Counts    map[string]int         `json:"counts"`
	Endpoints []applicabilityRow     `json:"endpoints"`
	Package   *store.SoftwarePackage `json:"package"`
}

// handleSoftwareApplicability answers, per endpoint, what this package
// could do there.
func (s *Server) handleSoftwareApplicability(w http.ResponseWriter, r *http.Request) {
	pkg, err := s.store.GetSoftwarePackage(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pkg == nil {
		http.Error(w, "no such package", http.StatusNotFound)
		return
	}
	rows, counts, err := s.applicability(r.Context(), *pkg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, softwareApplicabilityResponse{Package: pkg, Endpoints: rows, Counts: counts})
}

// applicability evaluates one package against every endpoint.
func (s *Server) applicability(ctx context.Context, pkg store.SoftwarePackage) ([]applicabilityRow, map[string]int, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, nil, err
	}
	installed, err := s.installedAppsByAgent(ctx)
	if err != nil {
		return nil, nil, err
	}
	scoped, err := s.agentsInGroups(ctx, pkg.GroupIDs)
	if err != nil {
		return nil, nil, err
	}

	counts := map[string]int{}
	rows := make([]applicabilityRow, 0, len(agents))
	for _, a := range agents {
		row := applicabilityRow{
			AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS,
			Platform: a.Platform, Site: a.Site, Online: a.Online,
		}
		row.State, row.Found, row.Reason = evaluateApplicability(pkg, a, installed[a.AgentID], scoped)
		counts[row.State]++
		rows = append(rows, row)
	}
	return rows, counts, nil
}

// applicabilityAll computes just the counts, for every package at once. It
// loads the fleet and the installed-apps snapshots one time rather than
// once per package, which is the difference between a catalog page that
// loads instantly and one that does N round trips.
func (s *Server) applicabilityAll(ctx context.Context, pkgs []store.SoftwarePackage) (map[string]map[string]int, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	installed, err := s.installedAppsByAgent(ctx)
	if err != nil {
		return nil, err
	}

	out := make(map[string]map[string]int, len(pkgs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, pkg := range pkgs {
		wg.Add(1)
		go func(pkg store.SoftwarePackage) {
			defer wg.Done()
			scoped, err := s.agentsInGroups(ctx, pkg.GroupIDs)
			if err != nil {
				return
			}
			counts := map[string]int{}
			for _, a := range agents {
				state, _, _ := evaluateApplicability(pkg, a, installed[a.AgentID], scoped)
				counts[state]++
			}
			mu.Lock()
			out[pkg.ID] = counts
			mu.Unlock()
		}(pkg)
	}
	wg.Wait()
	return out, nil
}

// evaluateApplicability is the whole decision for one package on one
// endpoint. Kept pure so the same logic serves the catalog counts, the
// per-package endpoint list, and the deployment target resolution — three
// places that would otherwise drift apart.
// meetsRequirements checks a package's hardware and architecture gates
// against one endpoint.
//
// Split out because Self Service was deciding what to offer with its own
// logic that never consulted Requirements at all — so a package restricted
// to amd64 was offered on an arm64 Mac, and because install authorization
// is derived from that same state, it would have been allowed to run.
// One implementation, both callers.
func meetsRequirements(pkg store.SoftwarePackage, a store.AgentRecord) (bool, string) {
	if len(pkg.Requirements.Arch) > 0 {
		match := false
		for _, arch := range pkg.Requirements.Arch {
			if strings.EqualFold(arch, a.Arch) {
				match = true
				break
			}
		}
		if !match {
			return false, "needs " + strings.Join(pkg.Requirements.Arch, " or ") + ", this is " + a.Arch
		}
	}
	if pkg.Requirements.MinRAMMB > 0 && a.MemTotalMB > 0 && uint64(a.MemTotalMB) < pkg.Requirements.MinRAMMB {
		return false, "needs " + strconv.FormatUint(pkg.Requirements.MinRAMMB, 10) + " MB RAM"
	}
	return true, ""
}

func evaluateApplicability(pkg store.SoftwarePackage, a store.AgentRecord,
	apps map[string]string, scoped map[string]bool) (state, found, reason string) {

	if scoped != nil && !scoped[a.AgentID] {
		return stateNotApplicable, "", "outside this package's computer groups"
	}
	if pkg.DeployDefinition != nil {
		v, err := deploy.SelectVariant(*pkg.DeployDefinition, a.OS, a.Arch, a.Platform, a.PlatformVersion)
		if err != nil {
			return stateNotApplicable, "", err.Error()
		}
		if pkg.Kind == store.KindAction {
			return stateInstallEligible, "", "Runs on every invocation for this platform"
		}
		return stateInstallEligible, v.Version, "Fresh detection and requirements run on the endpoint"
	}
	ops, ok := pkg.Commands[a.OS]
	if !ok {
		return stateNotApplicable, "", "no command defined for " + a.OS
	}
	if ok, why := meetsRequirements(pkg, a); !ok {
		return stateNotApplicable, "", why
	}

	// The agent is the one piece of software whose installed version mustra
	// knows without a sensor, and comparing it against the build being
	// served is what stops the agent-update package staying eligible on
	// endpoints that have just taken it.
	if pkg.Detect.Fact == store.FactAgentVersion {
		return agentVersionState(version.Agent(), a.AgentVersion, ops, a.OS)
	}

	found = matchInstalled(pkg.Detect, pkg.Name, apps)
	switch {
	case found == "":
		if ops.Install == "" {
			return stateNotApplicable, "", "not installed, and this package has no install command for " + a.OS
		}
		return stateInstallEligible, "", ""
	case pkg.Version != "" && found != pkg.Version && !(pkg.VersionSource != "" && sameReleaseVersion(found, pkg.Version)):
		if ops.Update == "" {
			return stateInstalled, found, "a different version is installed, but this package has no update command"
		}
		return stateUpdateEligible, found, ""
	default:
		return stateInstalled, found, ""
	}
}

// hasCommandFor reports whether this package can actually carry out an
// operation on this platform.
//
// Applicability answers "should this endpoint get it", which is not the
// same question as "is there anything to run". A package installed on eight
// machines with no remove command passed the remove check on all eight: the
// run was recorded with eight targets, the reply said targets=8 skipped=0,
// and then the dispatcher dropped every one of them on an empty command
// string with no action row and no log. The deployment showed as running
// for three hours and "no response" for ever after.
func hasCommandFor(pkg store.SoftwarePackage, os, operation string) bool {
	if pkg.DeployDefinition != nil {
		for _, v := range pkg.DeployDefinition.Variants {
			if v.OS == os {
				if _, ok := v.Actions[operation]; ok {
					return true
				}
			}
		}
		return false
	}
	ops, ok := pkg.Commands[os]
	if !ok {
		return false
	}
	return legacyCommand(pkg, ops, operation) != ""
}

// legacyCommand picks the command a package without a DeployDefinition runs
// for an operation. hasCommandFor and both dispatchers use it, so "is there
// anything to run" and "what is run" cannot disagree.
//
// A legacy action package has one command, stored as its install command
// (the editor labels it "Install / Legacy Run"), so the Deploy view's "run"
// means that command. "run" against a software package means nothing.
// An update falls back to the install command: most package managers'
// install also upgrades.
func legacyCommand(pkg store.SoftwarePackage, ops store.SoftwareOps, operation string) string {
	switch operation {
	case "install":
		return ops.Install
	case "update":
		if ops.Update != "" {
			return ops.Update
		}
		return ops.Install
	case "remove":
		return ops.Remove
	case "run":
		if pkg.Kind == store.KindAction {
			return ops.Install
		}
	}
	return ""
}

// matchInstalled looks the package up in an endpoint's installed-apps
// snapshot and returns the version found, or "".
func matchInstalled(detect store.SoftwareDetect, fallbackName string, apps map[string]string) string {
	name := detect.AppName
	if name == "" {
		name = fallbackName
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || apps == nil {
		return ""
	}
	if detect.Match == "contains" {
		for appName, version := range apps {
			if strings.Contains(appName, name) {
				if version == "" {
					return "installed"
				}
				return version
			}
		}
		return ""
	}
	version, ok := apps[name]
	if !ok {
		return ""
	}
	if version == "" {
		return "installed"
	}
	return version
}

// installedAppsByAgent loads every endpoint's installed-apps snapshot as
// lowercased name -> version. One query for the whole fleet.
func (s *Server) installedAppsByAgent(ctx context.Context) (map[string]map[string]string, error) {
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorInstalledApps))
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]string, len(rows))
	for _, row := range rows {
		var apps []proto.InstalledApp
		if err := json.Unmarshal(row.Data, &apps); err != nil {
			continue
		}
		byName := make(map[string]string, len(apps))
		for _, app := range apps {
			byName[strings.ToLower(app.Name)] = app.Version
		}
		out[row.AgentID] = byName
	}
	return out, nil
}

// agentsInGroups resolves a package's group scope to a set of agent IDs.
// A package with no groups returns nil, meaning "every endpoint" — which
// callers must distinguish from an empty set, meaning "no endpoint".
func (s *Server) agentsInGroups(ctx context.Context, groupIDs []string) (map[string]bool, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}
	all, err := s.store.ListComputerGroups(ctx)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, id := range groupIDs {
		wanted[id] = true
	}
	devices, _, err := s.devicesForMatching(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, g := range all {
		if !wanted[g.ID] {
			continue
		}
		if g.Kind == "static" {
			for _, id := range g.MemberIDs {
				out[id] = true
			}
			continue
		}
		for _, d := range devices {
			if groups.Matches(d, g.Rules, g.MatchMode != "any") {
				out[d.AgentID] = true
			}
		}
	}
	return out, nil
}

// ---- deployment ----

// deploymentLabel names a run the way someone would say it out loud. An
// action package is already a verb -- "Reboot Computer" -- so prefixing it
// with the operation produced "Install Reboot Computer", which reads as
// nonsense and was the first thing anyone noticed about it.
func deploymentLabel(pkg store.SoftwarePackage, operation string) string {
	if pkg.Kind == store.KindAction {
		if operation == "remove" {
			return "Cancel " + pkg.Name
		}
		return pkg.Name
	}
	switch operation {
	case "install":
		return "Install " + pkg.Name
	case "update":
		return "Update " + pkg.Name
	case "remove":
		return "Remove " + pkg.Name
	}
	return pkg.Name
}

type softwareDeployRequest struct {
	PackageID string   `json:"package_id" api:"required"`
	Operation string   `json:"operation" api:"required"` // install | update | remove
	AgentIDs  []string `json:"agent_ids"`                // empty means every eligible endpoint
	// PlanID rolls the deployment out in stages instead of all at once,
	// halting if a ring's success criteria aren't met.
	PlanID string `json:"plan_id,omitempty"`
	// Parameters supplies values for the package's declared parameters.
	// Missing entries fall back to each parameter's default.
	Parameters map[string]string `json:"parameters,omitempty"`
	// OverrideWindows dispatches even when the endpoint's maintenance
	// windows are closed. Needs deploy.override_windows.
	OverrideWindows bool `json:"override_windows,omitempty"`
}

// handleDeploySoftware runs one operation against a target. Like patch
// deployment it creates a run first, so the Deployments view shows it even
// if this request never returns.
// explicitTargetsRequired refuses a package marked RequireExplicitTargets
// unless the caller named the endpoints.
//
// The guard is on the server, not the button, because the button is not the
// only caller: both deployment paths and anything holding an API token reach
// the same dispatch. A package that removes the agent is one mis-click from
// a fleet that cannot be managed remotely any more -- including to put the
// agent back -- so "all online endpoints" has to be unavailable rather than
// merely discouraged.
func explicitTargetsRequired(w http.ResponseWriter, pkg *store.SoftwarePackage, agentIDs []string) bool {
	if !pkg.RequireExplicitTargets || len(agentIDs) > 0 {
		return false
	}
	http.Error(w, pkg.Name+" must be run against endpoints you select; it cannot be run fleet-wide",
		http.StatusBadRequest)
	return true
}

// deploySoftwareResponse is what POST /api/software/deploy answers.
type deploySoftwareResponse struct {
	Operation string `json:"operation"`
	Plan      string `json:"plan"`
	RunID     string `json:"run_id"`
	Skipped   int    `json:"skipped"`
	Targets   int    `json:"targets"`
}

func (s *Server) handleDeploySoftware(w http.ResponseWriter, r *http.Request) {
	var req softwareDeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Operation != "install" && req.Operation != "update" && req.Operation != "remove" && req.Operation != "run" {
		http.Error(w, `operation must be "install", "update", "remove" or "run"`, http.StatusBadRequest)
		return
	}
	pkg, err := s.store.GetSoftwarePackage(r.Context(), req.PackageID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pkg == nil {
		http.Error(w, "no such package", http.StatusNotFound)
		return
	}

	if req.Operation == "run" && pkg.DeployRevision == "" && pkg.Kind != store.KindAction {
		http.Error(w, `"run" applies to action packages; use install, update or remove for software`, http.StatusBadRequest)
		return
	}
	if explicitTargetsRequired(w, pkg, req.AgentIDs) {
		return
	}
	// Access control on what was *asked for*, before applicability narrows
	// it. An operator who named an endpoint they may not touch should be
	// told that, not told it was ineligible: the two are different facts
	// and only one of them is about them.
	if len(req.AgentIDs) > 0 && !s.checkTargets(w, r, "deploy", req.AgentIDs) {
		return
	}
	if !s.requireContent(w, r, "packages", pkg.ID, pkg.Name) {
		return
	}
	if !s.requireOverride(w, r, req.OverrideWindows) {
		return
	}

	if pkg.DeployRevision != "" {
		raw, _ := json.Marshal(deployRequest{PlanID: req.PlanID, PackageID: pkg.ID, Operation: req.Operation, AgentIDs: req.AgentIDs, Parameters: req.Parameters, OverrideWindows: req.OverrideWindows})
		r.Body = io.NopCloser(bytes.NewReader(raw))
		s.handleDeployRun(w, r)
		return
	}

	// Nothing published and no commands: a package added from the library,
	// or one still being written, is a draft until someone publishes it.
	// Saying so beats "no endpoint is eligible", which sends people looking
	// at their endpoints.
	if len(pkg.Commands) == 0 {
		http.Error(w, "this package has nothing published to run yet: open it in Deploy → Software Catalog, review its draft and publish it first", http.StatusConflict)
		return
	}

	// Resolve parameters before anything is targeted: a bad value should
	// stop the deployment here, not after it has been sent to half the
	// fleet with a half-substituted command.
	if len(pkg.Parameters) > 0 {
		values, perr := resolveParameters(pkg.Parameters, req.Parameters)
		if perr != nil {
			http.Error(w, perr.Error(), http.StatusBadRequest)
			return
		}
		substituted := make(map[string]store.SoftwareOps, len(pkg.Commands))
		for os, ops := range pkg.Commands {
			substituted[os] = store.SoftwareOps{
				Install: substituteParameters(ops.Install, values),
				Update:  substituteParameters(ops.Update, values),
				Remove:  substituteParameters(ops.Remove, values),
			}
		}
		pkg.Commands = substituted
	}

	rows, _, err := s.applicability(r.Context(), *pkg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Resolve targets. An explicit list is still filtered by applicability:
	// selecting a row in the UI must not be able to send an install command
	// to a machine the package has no command for.
	explicit := map[string]bool{}
	for _, id := range req.AgentIDs {
		explicit[id] = true
	}
	// How many the caller meant, so the reply can account for the gap.
	requested := len(req.AgentIDs)
	if requested == 0 {
		requested = len(rows)
	}
	var targets []applicabilityRow
	for _, row := range rows {
		if len(explicit) > 0 && !explicit[row.AgentID] {
			continue
		}
		if !operationApplies(*pkg, req.Operation, row.State) {
			continue
		}
		// And there must be something to run. Otherwise the target is
		// counted, promised in the reply, and silently dropped downstream.
		if !hasCommandFor(*pkg, row.OS, req.Operation) {
			continue
		}
		targets = append(targets, row)
	}
	if len(targets) == 0 {
		http.Error(w, "no endpoint is eligible for that operation right now", http.StatusBadRequest)
		return
	}

	// A fleet-wide deployment names nobody, so what is out of reach is
	// dropped and counted rather than refused: refusing "every eligible
	// endpoint" because one of them is off-limits would be unusable.
	targetIDs := make([]string, 0, len(targets))
	for _, t := range targets {
		targetIDs = append(targetIDs, t.AgentID)
	}
	ids := targetIDs
	allowed, ok := s.authorizeEndpointAction(w, r, endpointAction{
		Module: "deploy", Summary: fmt.Sprintf("%s %s on %d endpoint(s)", req.Operation, pkg.Name, len(targets)),
		Explicit: req.AgentIDs, NarrowFleet: true,
		Fleet:    func(context.Context) ([]string, error) { return ids, nil },
		Content:  []contentRef{{Kind: "packages", ID: pkg.ID, Name: pkg.Name}},
		Approval: &approvalRef{Handler: "software.deploy", Body: req},
	})
	if !ok {
		return
	}
	if allowed != nil && len(req.AgentIDs) == 0 && len(allowed) < len(targets) {
		keep := map[string]bool{}
		for _, id := range allowed {
			keep[id] = true
		}
		narrowed := targets[:0:0]
		for _, t := range targets {
			if keep[t.AgentID] {
				narrowed = append(narrowed, t)
			}
		}
		targets, targetIDs = narrowed, allowed
	}

	who := auth.CurrentUser(r.Context()).Username
	runID := idgen.New("run-")
	targetDesc := pkg.Name
	if len(explicit) > 0 {
		targetDesc = pkg.Name + " (selected endpoints)"
	}
	// Resolved before anything is recorded. It used to be looked up after
	// the run row and the audit event were already written, so a deleted or
	// mistyped plan id returned 400 on top of an orphan deployment that no
	// agent would ever report against — shown as running for three hours and
	// then "no response" for ever — and an audit line claiming an N-endpoint
	// deploy the operator had just been told failed. There is no delete path
	// for a run, so that record is permanent.
	var plan *store.DeploymentPlan
	if req.PlanID != "" {
		p, perr := s.store.GetDeploymentPlan(r.Context(), req.PlanID)
		if perr != nil {
			http.Error(w, perr.Error(), http.StatusInternalServerError)
			return
		}
		if p == nil {
			http.Error(w, "no such deployment plan", http.StatusBadRequest)
			return
		}
		plan = p
	}

	if err := s.store.RecordPatchJobRun(r.Context(), store.PatchJobRun{
		ID: runID, TargetDesc: targetDesc, AgentCount: len(targets),
		ScheduleName: deploymentLabel(*pkg, req.Operation), TriggeredBy: who,
	}); err != nil {
		s.logger.Warn("record software run failed", "error", err)
	}

	s.logger.Info("software deployment starting", "package", pkg.Name, "operation", req.Operation,
		"targets", len(targets), "run_id", runID, "by", who)
	s.audit(r.Context(), auditEvent{
		Action: "software." + req.Operation, Actor: who, Target: pkg.Name,
		Severity: "notice",
		Detail: map[string]any{
			"run_id": runID, "endpoints": len(targets), "plan": req.PlanID,
			"selected": len(req.AgentIDs) > 0,
		},
	})

	// Fan out in the background: a hundred endpoints running an installer
	// is minutes of work, and the browser tab that started it shouldn't
	// have to stay open. A staged rollout takes longer still — a plan with
	// wait windows is legitimately hours — so the same applies doubly.
	bg := context.WithoutCancel(r.Context())
	staged := ""
	if plan != nil {
		staged = plan.Name
		go s.runStagedDeployment(bg, *pkg, req.Operation, *plan, targets, runID, who)
	} else {
		go s.runSoftwareDeployment(bg, *pkg, req.Operation, targets, runID, who, req.OverrideWindows)
	}

	// Say what was left out. Applicability filters the target list even when
	// the caller named endpoints explicitly, so "deployed to 12" after
	// selecting 40 is otherwise a silent disagreement between what somebody
	// asked for and what happened.
	skipped := requested - len(targets)
	if skipped < 0 {
		skipped = 0
	}
	writeJSONResponse(w, deploySoftwareResponse{
		RunID: runID, Operation: req.Operation, Targets: len(targets),
		Skipped: skipped, Plan: staged,
	})
}

// agentVersionState classifies one endpoint against the agent build the
// control plane is serving.
//
// Split out from evaluateApplicability so the serving version is an
// argument rather than a package-level call: a test binary has no ldflags,
// so version.Current() there is "dev", and a rule this consequential should
// be testable at every version rather than only at whatever the build
// happened to stamp.
func agentVersionState(serving, running string, ops store.SoftwareOps, os string) (state, found, reason string) {
	switch {
	case running == "":
		return stateInstallEligible, "", "no agent version reported yet"
	case !versionParses(serving):
		// An unstamped control plane cannot say what is newer than what.
		// Reporting every endpoint as needing an update would be the whole
		// fleet nagged on the strength of a build flag nobody set.
		return stateInstalled, running, "the control plane is not reporting a comparable version"
	case versionIsNewer(serving, running):
		if ops.Update == "" && ops.Install == "" {
			return stateInstalled, running, "behind, but this package has no command for " + os
		}
		return stateUpdateEligible, running, "control plane is serving " + serving
	case versionIsNewer(running, serving):
		// Ahead of the control plane, which happens mid-rollout and is not
		// something to "fix" by pushing an older build at it.
		return stateInstalled, running, "ahead of the control plane, which is serving " + serving
	default:
		return stateInstalled, running, "already on " + serving
	}
}

func operationApplies(pkg store.SoftwarePackage, operation, state string) bool {
	if pkg.DeployDefinition != nil {
		return state != stateNotApplicable
	}
	// An action package is never "installed", so the applicability states
	// that gate software don't apply to it. If it has a command for this
	// platform it can run -- otherwise "Cancel" could never dispatch,
	// because nothing is ever in the installed state to cancel.
	if pkg.Kind == store.KindAction && pkg.Detect.Fact == "" {
		return state != stateNotApplicable
	}
	switch operation {
	case "install":
		return state == stateInstallEligible
	case "update":
		return state == stateUpdateEligible
	case "remove":
		return state == stateInstalled || state == stateUpdateEligible
	case "run":
		// Only an action that detects a fact reaches here (the agent-version
		// update action). Running it is only meaningful where that fact says
		// there is something to do, so an up-to-date agent is not re-run.
		return pkg.Kind == store.KindAction && (state == stateInstallEligible || state == stateUpdateEligible)
	}
	return false
}

func (s *Server) runSoftwareDeployment(ctx context.Context, pkg store.SoftwarePackage,
	operation string, targets []applicabilityRow, runID, who string, overrideWindows bool) {

	if pkg.DeployRevision != "" {
		s.runPublishedSoftware(ctx, pkg, operation, targets, runID, who)
		return
	}
	// Resolved once for the whole deployment rather than per endpoint: the
	// token is per dispatch, not per machine, and minting a hundred of them
	// for one push buys nothing.
	files := s.packageFileRefs(ctx, pkg.ID)

	sem := make(chan struct{}, 10) // ten at a time: enough to be quick, not enough to melt a repo mirror
	var wg sync.WaitGroup
	for _, target := range targets {
		command := legacyCommand(pkg, pkg.Commands[target.OS], operation)
		if command == "" {
			continue
		}
		wg.Add(1)
		go func(target applicabilityRow, command string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			actionID := idgen.New("act-")
			summary := deploymentLabel(pkg, operation)
			if err := s.store.StartAgentAction(ctx, store.AgentAction{
				ID: actionID, RunID: runID, AgentID: target.AgentID, Kind: "software_" + operation,
				Summary: summary, RequestedBy: who,
			}); err != nil {
				s.logger.Warn("record software action failed", "error", err)
			}
			// Legacy packages run synchronously, so a closed maintenance
			// window skips the endpoint with the reason on its action
			// rather than holding a goroutine open until the window opens.
			if !overrideWindows {
				if v := s.windowCheck(ctx, target.AgentID, "deploy", time.Now()); !v.Allowed {
					if err := s.store.FinishAgentAction(ctx, target.AgentID, actionID, "skipped", v.Reason); err != nil {
						s.logger.Warn("finish software action failed", "error", err)
					}
					return
				}
			}

			out, err := s.sendSoftwareCommand(ctx, target.AgentID, command, pkg.CommandTimeoutSeconds, files)
			status := softwareActionOutcome(err)
			detail := safeTruncate(softwareOutcomeDetail(status, err, out), 8000)
			if err := s.store.FinishAgentAction(ctx, target.AgentID, actionID, status, detail); err != nil {
				s.logger.Warn("finish software action failed", "error", err)
			}
			if status == "succeeded" {
				s.afterRemediation(ctx, target.AgentID)
			}
			// One event per endpoint. A deployment that half-worked is the
			// case worth being able to reconstruct, and a single event for
			// the whole run cannot express it.
			outcome := "ok"
			sev := "info"
			if status != "succeeded" {
				outcome, sev = "failed", "warning"
			}
			s.audit(ctx, auditEvent{
				Action: "software." + operation + ".endpoint", Actor: who,
				Target: pkg.Name, AgentID: target.AgentID, Outcome: outcome, Severity: sev,
				Detail: map[string]any{"run_id": runID, "hostname": target.Hostname, "status": status},
			})
		}(target, command)
	}
	wg.Wait()
	s.logger.Info("software deployment finished", "package", pkg.Name, "run_id", runID)
}

// sendSoftwareCommand asks one agent to run a package operation and waits
// for its result. The timeout is generous because installers are slow;
// the agent acknowledges immediately and streams nothing, so a long wait
// here costs one goroutine and nothing on the endpoint.
// packageFileRefs turns a package's stored files into fetchable references,
// minting a download token for each. An empty result is the normal case —
// most packages install from a repository and need no payload at all.
func (s *Server) packageFileRefs(ctx context.Context, packageID string) []proto.PackageFileRef {
	files, err := s.store.ListPackageFiles(ctx, packageID)
	if err != nil || len(files) == 0 {
		if err != nil {
			s.logger.Warn("could not list package files", "package_id", packageID, "error", err)
		}
		return nil
	}
	base, err := s.agentPublicURLOrEmpty(ctx)
	if err != nil || strings.TrimSpace(base) == "" {
		// Without a URL an endpoint can reach, staging cannot work at all,
		// and running the command anyway would execute against a file that
		// is not there.
		s.logger.Error("package has files but the server has not recorded a reachable console URL — "+
			"set the console public URL in Settings", "package_id", packageID)
		return nil
	}
	out := make([]proto.PackageFileRef, 0, len(files))
	for _, f := range files {
		tok := s.dlTokens.mint(f.ID)
		if tok == "" {
			continue
		}
		out = append(out, proto.PackageFileRef{
			Name: f.Name, SHA256: f.SHA256, Size: f.SizeBytes,
			URL: strings.TrimRight(base, "/") + "/package-files/" + f.ID + "?t=" + tok,
		})
	}
	return out
}

func (s *Server) sendSoftwareCommand(ctx context.Context, agentID, command string,
	timeoutSeconds int, files []proto.PackageFileRef) (string, error) {

	payload, err := json.Marshal(proto.AgentCommand{
		Cmd: "run_software", Command: command, TimeoutSeconds: timeoutSeconds,
		Files: files,
	})
	if err != nil {
		return "", err
	}
	// The request/reply wait has to outlast whatever the package is allowed
	// to take on the endpoint, or the server gives up on a command that is
	// still legitimately running.
	wait := 20 * time.Minute
	if timeoutSeconds > 0 {
		wait = time.Duration(timeoutSeconds)*time.Second + time.Minute
	}
	rctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(agentID), payload)
	if err != nil {
		return "", err
	}
	var result proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return "", err
	}
	if !result.OK {
		return result.Output, errAgent(result.Error)
	}
	return result.Output, nil
}

type errAgent string

func (e errAgent) Error() string {
	if e == "" {
		return "the endpoint reported a failure with no detail"
	}
	return string(e)
}

var _ = runtime.GOOS
