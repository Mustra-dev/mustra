package server

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	gonats "github.com/nats-io/nats.go"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

// Self Service is the window a person opens on their own machine. Every
// authorization decision lives here rather than in the agent: the local UI
// says "install item X", the server decides whether that device is entitled
// and answers with the package name to run. An agent never accepts a
// package name from its own UI, so a person with local access can't talk it
// into installing something arbitrary — the same reasoning that keeps
// apply_patches a fixed command rather than a shell string.

func (s *Server) subscribeSelfService(ctx context.Context) (*gonats.Subscription, error) {
	return s.nc.Subscribe(bnats.SelfServiceWildcard(), func(msg *gonats.Msg) {
		agentID := strings.TrimPrefix(msg.Subject, "beacon.selfservice.")
		if agentID == "" || agentID == msg.Subject {
			return
		}
		if !s.agentReplyAllowed(ctx, msg, replyAgent, agentID) {
			return
		}
		var req proto.SelfServiceRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			s.respondSelfService(ctx, msg, agentID, proto.SelfServiceReply{Error: "malformed request"})
			return
		}
		reply := s.handleSelfService(ctx, agentID, req)
		s.respondSelfService(ctx, msg, agentID, reply)
	})
}

func (s *Server) respondSelfService(ctx context.Context, msg *gonats.Msg, agentID string, reply proto.SelfServiceReply) {
	payload, err := json.Marshal(reply)
	if err != nil {
		return
	}
	s.respondToAgent(ctx, msg, replyAgent, agentID, payload)
}

func (s *Server) handleSelfService(ctx context.Context, agentID string, req proto.SelfServiceRequest) proto.SelfServiceReply {
	switch req.Action {
	case "state":
		reply := s.selfServiceState(ctx, agentID)
		// Branding goes out even when the state itself failed: a device not
		// in inventory yet should still see its organisation's window.
		s.selfServiceBrandingReply(ctx, &reply, req.BrandingVersion)
		return reply
	case "install":
		return s.selfServiceInstall(ctx, agentID, req)
	case "request":
		return s.selfServiceRequest(ctx, agentID, req)
	case "install_result":
		return s.selfServiceInstallResult(ctx, agentID, req)
	case "update_agent":
		return s.selfServiceUpdateAgent(ctx, agentID)
	case "telemetry_config":
		cfg := s.telemetryConfigFor(ctx, agentID)
		return proto.SelfServiceReply{OK: true, Telemetry: &cfg}
	default:
		return proto.SelfServiceReply{Error: "unknown action: " + req.Action}
	}
}

// selfServiceState resolves which Self Service packages this device may
// install: one with no groups is offered to everyone, otherwise the device
// must be in one of its groups — or have had a request approved, which
// grants the package without moving the machine into a group.
func (s *Server) selfServiceState(ctx context.Context, agentID string) proto.SelfServiceReply {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return proto.SelfServiceReply{Error: err.Error()}
	}
	var me *store.AgentRecord
	for i := range agents {
		if agents[i].AgentID == agentID {
			me = &agents[i]
			break
		}
	}
	if me == nil {
		return proto.SelfServiceReply{Error: "this device isn't in inventory yet"}
	}

	items, err := s.store.ListSoftwarePackages(ctx)
	if err != nil {
		return proto.SelfServiceReply{Error: err.Error()}
	}

	// Group membership, evaluated once for this device.
	memberOf := map[string]bool{}
	if allGroups, err := s.store.ListComputerGroups(ctx); err == nil && len(allGroups) > 0 {
		devices, _, derr := s.devicesForMatching(ctx)
		if derr == nil {
			var dev *groups.Device
			for i := range devices {
				if devices[i].AgentID == agentID {
					dev = &devices[i]
					break
				}
			}
			for _, g := range allGroups {
				switch {
				case g.Kind == "static":
					for _, id := range g.MemberIDs {
						if id == agentID {
							memberOf[g.ID] = true
						}
					}
				case dev != nil && groups.Matches(*dev, g.Rules, g.MatchMode != "any"):
					memberOf[g.ID] = true
				}
			}
		}
	}

	// What's already installed, so the window can say so instead of
	// offering to install it again.
	// Name to version, in the shape matchInstalled expects. This used to be
	// a set of names checked by exact key, which ignored Detect.Match ==
	// "contains" — and the migration that carried the old catalog into the
	// package model stamps "contains" on every item it moves, so precisely
	// those were reported as not installed and offered again on machines
	// that already had them.
	installed := map[string]string{}
	if rec, err := s.store.GetSensorData(ctx, agentID, string(proto.SensorInstalledApps)); err == nil && rec != nil {
		var apps []proto.InstalledApp
		if json.Unmarshal(rec.Data, &apps) == nil {
			for _, a := range apps {
				installed[strings.ToLower(a.Name)] = a.Version
			}
		}
	}

	out := proto.SelfServiceReply{OK: true, Hostname: me.Hostname, AgentID: agentID,
		LatestAgentVersion: version.Agent()}
	for _, it := range items {
		// Only packages published to Self Service, and only where this
		// device's OS actually has an install command — otherwise the
		// window offers a button that could never work.
		if !it.Enabled || !it.SelfService {
			continue
		}
		it, ok := s.selfServiceVersion(ctx, it)
		if !ok {
			continue
		}
		pkg, ok := selfServiceOffer(it, me.OS, me.Arch, me.Platform, me.PlatformVersion)
		if !ok {
			continue
		}
		// The same hardware and architecture gates the operator-facing
		// catalog applies. Offering a package this endpoint cannot run is
		// worse here than there, because install authorization is derived
		// from this very list.
		if ok, _ := meetsRequirements(it, *me); !ok {
			continue
		}
		entitled := len(it.GroupIDs) == 0
		for _, gid := range it.GroupIDs {
			if memberOf[gid] {
				entitled = true
				break
			}
		}
		if !entitled {
			if ok, err := s.store.ApprovedRequestExists(ctx, it.ID, agentID); err == nil && ok {
				entitled = true
			}
		}
		pending := false
		if !entitled {
			pending, _ = s.store.PendingRequestFor(ctx, it.ID, agentID)
		}
		if !entitled && !pending && !it.AllowRequests {
			continue // not offered, and can't be asked for
		}
		out.Items = append(out.Items, proto.SelfServiceItem{
			ID: it.ID, Name: it.Name, Description: it.Description, Category: it.Category,
			Icon: it.Icon, Package: pkg, Entitled: entitled, Pending: pending,
			CanRequest: !entitled && !pending && it.AllowRequests,
			Installed:  matchInstalled(it.Detect, it.Name, installed) != "",
		})
	}

	if actions, err := s.store.ListAgentActions(ctx, agentID, 25); err == nil {
		for _, a := range actions {
			out.Activity = append(out.Activity, proto.SelfServiceActivity{
				Kind: a.Kind, Summary: a.Summary, Status: a.Status, Detail: a.Detail,
				StartedAt: a.StartedAt.UTC().Format("2006-01-02T15:04:05Z"), By: a.RequestedBy,
			})
		}
	}
	return out
}

// selfServiceVersion is the package as Self Service offers it: its pinned
// self_service_revision, unless it follows the latest published version.
// false means the pinned revision is gone, and the package is not offered.
func (s *Server) selfServiceVersion(ctx context.Context, it store.SoftwarePackage) (store.SoftwarePackage, bool) {
	if it.DeployRevision == "" || it.SelfServiceFollowLatest || it.SelfServiceRevision == "" {
		return it, true
	}
	revision, err := s.store.GetDeployRevision(ctx, it.SelfServiceRevision)
	if err != nil || revision == nil {
		return it, false
	}
	it.DeployRevision = revision.ID
	it.DeployDefinition = &revision.Definition
	return it, true
}

// selfServiceOffer is what Self Service would install from the package
// (as selfServiceVersion resolved it) on an endpoint of this OS, arch,
// distribution and OS version: the install command, or for a versioned
// package its matching variant's install action. false means the window
// must not offer it there, because the button could never work.
func selfServiceOffer(it store.SoftwarePackage, os, arch, distribution, osVersion string) (string, bool) {
	if it.DeployDefinition == nil {
		pkg := it.Commands[os].Install
		return pkg, pkg != ""
	}
	variant, err := deploy.SelectVariant(*it.DeployDefinition, os, arch, distribution, osVersion)
	if err != nil || !selfServiceInstalls(*it.DeployDefinition, *variant) {
		return "", false
	}
	return "[managed deployment]", true
}

// selfServiceInstalls reports whether a variant can be installed from Self
// Service: it has an install action, and that needs no parameters, since
// nobody at the endpoint may supply them.
func selfServiceInstalls(def proto.DeployDefinition, variant proto.DeployVariant) bool {
	action, ok := variant.Actions["install"]
	return ok && len(deploy.MergeParameters(def.Parameters, variant.Parameters, action.Parameters)) == 0
}

// selfServicePlatforms is the platforms some endpoint could be offered the
// package on, by the rule selfServiceOffer applies. Which variant an
// endpoint gets also depends on its architecture, distribution and OS
// version, and the package's requirements are checked per endpoint, so a
// listed platform is where it can be offered, not a promise to every
// machine on it.
func selfServicePlatforms(it store.SoftwarePackage) []string {
	set := map[string]bool{}
	if it.DeployDefinition != nil {
		for _, v := range it.DeployDefinition.Variants {
			if selfServiceInstalls(*it.DeployDefinition, v) {
				set[v.OS] = true
			}
		}
	} else {
		for os, ops := range it.Commands {
			if ops.Install != "" {
				set[os] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for os := range set {
		out = append(out, os)
	}
	sort.Strings(out)
	return out
}

// selfServicePlatformsAll is selfServicePlatforms for each package offered
// in Self Service, keyed by package ID, as the console's Self Service page
// lists them. A disabled package is included, so the page can show what it
// would offer.
func (s *Server) selfServicePlatformsAll(ctx context.Context, pkgs []store.SoftwarePackage) map[string][]string {
	out := map[string][]string{}
	for _, it := range pkgs {
		if !it.SelfService {
			continue
		}
		if it, ok := s.selfServiceVersion(ctx, it); ok {
			out[it.ID] = selfServicePlatforms(it)
		} else {
			out[it.ID] = []string{}
		}
	}
	return out
}

// selfServiceInstall authorizes an install and returns the package to run.
// The device must currently be entitled — an approval that was later
// revoked, or a group it has since left, stops working immediately.
func (s *Server) selfServiceInstall(ctx context.Context, agentID string, req proto.SelfServiceRequest) proto.SelfServiceReply {
	state := s.selfServiceState(ctx, agentID)
	if state.Error != "" {
		return proto.SelfServiceReply{Error: state.Error}
	}
	var item *proto.SelfServiceItem
	for i := range state.Items {
		if state.Items[i].ID == req.ItemID {
			item = &state.Items[i]
			break
		}
	}
	if item == nil {
		return proto.SelfServiceReply{Error: "that item isn't in this device's catalog"}
	}
	if !item.Entitled {
		return proto.SelfServiceReply{Error: "this device isn't entitled to install " + item.Name}
	}

	pkg, err := s.store.GetSoftwarePackage(ctx, item.ID)
	if err != nil {
		return proto.SelfServiceReply{Error: err.Error()}
	}
	if pkg != nil && pkg.DeployRevision != "" {
		agents, e := s.store.ListAgents(ctx, s.staleAfter())
		if e != nil {
			return proto.SelfServiceReply{Error: e.Error()}
		}
		revisionID := pkg.DeployRevision
		if !pkg.SelfServiceFollowLatest && pkg.SelfServiceRevision != "" {
			revisionID = pkg.SelfServiceRevision
		}
		rev, e := s.store.GetDeployRevision(ctx, revisionID)
		if e != nil || rev == nil || !rev.Published || rev.PackageID != pkg.ID {
			return proto.SelfServiceReply{Error: "published revision is unavailable"}
		}
		for _, target := range agents {
			if target.AgentID != agentID {
				continue
			}
			// Entitlement above includes approved exceptions to the offer groups.
			// Keep hardware checks and dependency scope; do not undo that approval here.
			authorized := *pkg
			authorized.GroupIDs = nil
			job, e := s.planDeploy(ctx, authorized, *rev, target, deployRequest{Operation: "install"})
			if e != nil {
				return proto.SelfServiceReply{Error: e.Error()}
			}
			job.RunID = idgen.New("run-")
			who := "self-service:" + req.User
			s.audit(ctx, auditEvent{Action: "software.install", Actor: who, Target: pkg.Name, Severity: "notice", Detail: map[string]any{"agent_id": agentID, "revision": rev.ID, "run_id": job.RunID}})
			if e = s.store.CreateDeployRun(ctx, store.PatchJobRun{ID: job.RunID, TargetDesc: target.Hostname, ScheduleName: "Self Service: " + pkg.Name, TriggeredBy: who}, []proto.DeployJob{job}); e != nil {
				return proto.SelfServiceReply{Error: e.Error()}
			}
			return proto.SelfServiceReply{OK: true, Deploy: &job, RunID: job.RunID, Message: "Deployment queued"}
		}
		return proto.SelfServiceReply{Error: "endpoint unavailable"}
	}
	runID := idgen.New("run-")
	requestedBy := req.User
	if requestedBy == "" {
		requestedBy = "self-service"
	}
	if err := s.store.RecordPatchJobRun(ctx, store.PatchJobRun{
		ID: runID, TargetDesc: "device: " + state.Hostname, AgentCount: 1,
		ScheduleName: "Self Service: " + item.Name, TriggeredBy: requestedBy,
	}); err != nil {
		s.logger.Warn("record self-service run failed", "error", err)
	}
	if err := s.store.StartAgentAction(ctx, store.AgentAction{
		ID: idgen.New("act-"), RunID: runID, AgentID: agentID, Kind: "catalog_install",
		Summary: "Install " + item.Name, RequestedBy: requestedBy,
	}); err != nil {
		s.logger.Warn("record self-service action failed", "error", err)
	}
	s.logger.Info("self service install authorized", "agent_id", agentID, "item", item.Name,
		"package", item.Package, "user", requestedBy)
	return proto.SelfServiceReply{OK: true, Package: item.Package, RunID: runID,
		Message: "installing " + item.Name}
}

// selfServiceInstallResult closes out the action once the agent has run the
// package manager.
// selfServiceInstallResult records how an install went on the endpoint that
// ran it — and only on that endpoint.
//
// It used to take the run ID alone and finish actions[0], the
// alphabetically-first host in that run. Two things followed. Any holder of
// the shared agent credential could report an outcome for a machine that is
// not theirs: send install_result for a bulk patch run and the first host in
// it is marked succeeded, pre-empting or overwriting its real result. And
// even with nobody misbehaving, two endpoints in one run both wrote to the
// same row, so one of them silently reported for the other.
//
// The agent ID comes from the NATS subject, which the agent cannot forge
// without the server seeing a different subject, and the action is matched
// on (run, agent).
func (s *Server) selfServiceInstallResult(ctx context.Context, agentID string, req proto.SelfServiceRequest) proto.SelfServiceReply {
	if req.RunID == "" {
		return proto.SelfServiceReply{Error: "missing run id"}
	}
	actions, err := s.store.ActionsForRun(ctx, req.RunID)
	if err != nil {
		return proto.SelfServiceReply{Error: "could not read that run"}
	}
	var actionID string
	for _, a := range actions {
		if a.AgentID == agentID {
			actionID = a.ID
			break
		}
	}
	if actionID == "" {
		// Not this endpoint's run. Said plainly rather than "no such run",
		// because the two are different problems for whoever is reading it.
		return proto.SelfServiceReply{Error: "this endpoint has no action in that run"}
	}
	status := "failed"
	if req.OK {
		status = "succeeded"
	}
	if err := s.store.FinishAgentAction(ctx, agentID, actionID, status, safeTruncate(req.Detail, 4000)); err != nil {
		return proto.SelfServiceReply{Error: err.Error()}
	}
	return proto.SelfServiceReply{OK: true}
}

// selfServiceUpdateAgent hands back the update this agent may apply.
//
// A current agent applies Update: a binary URL and a manifest signed with
// the deployment key it pinned at enrollment, verified and installed by the
// agent itself (internal/agent/selfupdate.go). UpdateCommand, the installer
// one-liner, is still sent for agents that predate signed updates; it is
// built from the configured public URL (never a request header) and
// quoted. Neither is ever accepted from the window. That
// is the same rule that keeps a package name server-resolved: the local UI
// asks for a thing by intent, the server decides what actually runs.
//
// It reuses the install script rather than inventing an update path, because
// the installer already solves the hard parts: a service cannot overwrite
// its own running binary, so it has to stop, replace and restart, and it has
// to preserve the identity database or the endpoint comes back as a new
// machine and loses its history.
func (s *Server) selfServiceUpdateAgent(ctx context.Context, agentID string) proto.SelfServiceReply {
	base, err := s.agentPublicURL(ctx)
	if err != nil {
		return proto.SelfServiceReply{Error: err.Error()}
	}

	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return proto.SelfServiceReply{Error: err.Error()}
	}
	agentOS, agentArch, running, site := "", "", "", ""
	for i := range agents {
		if agents[i].AgentID == agentID {
			agentOS, agentArch, running, site = agents[i].OS, agents[i].Arch, agents[i].AgentVersion, agents[i].Site
			break
		}
	}

	// Checked here, not only in the window. The Self Service page hides the
	// update button when an endpoint is current, but that is JavaScript on
	// the endpoint itself and a loopback curl walks straight past it. The
	// consequence is not a wasted reinstall: an endpoint ahead of the
	// control plane — ordinary mid-rollout — would be handed an installer
	// for an older build and quietly downgraded.
	serving := version.Agent()
	if msg := unversionedAgentBuild(serving, running); msg != "" {
		return proto.SelfServiceReply{Error: msg}
	}
	if running != "" && !versionIsNewer(serving, running) {
		if versionIsNewer(running, serving) {
			return proto.SelfServiceReply{
				Error: "this endpoint is on " + running + ", ahead of the " + serving +
					" this server is serving — updating would move it backwards"}
		}
		return proto.SelfServiceReply{Error: "already on " + running + ", which is the current version"}
	}

	cmd := legacyUpdateCommand(base, agentOS, site)
	if cmd == "" {
		return proto.SelfServiceReply{Error: "no updater for " + agentOS}
	}

	s.logger.Info("self service agent update authorized", "agent_id", agentID,
		"os", agentOS, "from", running, "to", serving)
	offer, err := s.updateOfferFor(ctx, agentOS, agentArch, "")
	if err != nil {
		// An agent that verifies updates has nothing to apply without a
		// signed manifest; an older one still has the command.
		s.logger.Warn("no signed update available", "agent_id", agentID, "os", agentOS, "arch", agentArch, "error", err)
	}
	return proto.SelfServiceReply{OK: true, UpdateCommand: cmd, Update: offer,
		LatestAgentVersion: serving,
		// The agent's version, not the server's. They are deliberately
		// different numbers now, and quoting the server's told the operator
		// they were getting a build that does not exist.
		Message: "updating to " + serving}
}
func (s *Server) selfServiceRequest(ctx context.Context, agentID string, req proto.SelfServiceRequest) proto.SelfServiceReply {
	item, err := s.store.GetSoftwarePackage(ctx, req.ItemID)
	if err != nil || item == nil {
		return proto.SelfServiceReply{Error: "no such catalog item"}
	}
	if !item.AllowRequests {
		return proto.SelfServiceReply{Error: item.Name + " can't be requested"}
	}
	if pending, _ := s.store.PendingRequestFor(ctx, item.ID, agentID); pending {
		return proto.SelfServiceReply{OK: true, Message: "you've already asked for this — it's awaiting a decision"}
	}
	user := req.User
	if user == "" {
		user = "unknown"
	}
	if err := s.store.CreateCatalogRequest(ctx, store.CatalogRequest{
		ID: idgen.New("creq-"), ItemID: item.ID, AgentID: agentID, RequestedBy: user, Reason: req.Reason,
	}); err != nil {
		return proto.SelfServiceReply{Error: err.Error()}
	}
	s.logger.Info("self service request raised", "agent_id", agentID, "item", item.Name, "user", user)
	return proto.SelfServiceReply{OK: true, Message: "request sent — an administrator will review it"}
}

// legacyUpdateCommand is the installer one-liner an agent from before
// signed updates runs to update itself. It names the endpoint's current
// site: the installer rewrites the service definition, and without ?site=
// it writes the default, so every console update of an old agent used to
// move it out of its site (and out of the groups, schedules and policies
// that target that site). A site the installer would refuse is left out
// rather than failing the update.
func legacyUpdateCommand(base, agentOS, site string) string {
	query := ""
	if site != "" && validSite(site) {
		query = "?site=" + site
	}
	switch agentOS {
	case "windows":
		// PowerShell statements, not a command line. The agent already runs
		// this inside a Start-Process powershell, so returning another
		// "powershell.exe ..." here meant three nested shells, and the
		// innermost one was launched by bare name -- resolved through a
		// service's PATH, which answered "Access is denied" and did so in a
		// detached process where nobody saw it. The update reported started
		// and nothing happened.
		//
		// Staged to a file rather than piped into iex, matching the update
		// action package, which is the form proven on real endpoints.
		return "irm " + psQuoteString(base+"/install.ps1"+query) + " -UseBasicParsing -OutFile $env:TEMP\\mustra-install.ps1; " +
			"& $env:TEMP\\mustra-install.ps1"
	case "linux", "darwin":
		return "curl -fsSL " + shQuote(base+"/install.sh"+query) + " | bash"
	}
	return ""
}

// unversionedAgentBuild explains why an update cannot be compared when
// either side has no release version ("dev", or a bare commit from git
// describe on an untagged clone). versionIsNewer answers no for those, so
// the refusal used to read "already on <version>, which is the current
// version", which is not what is wrong. An endpoint with no recorded
// version is left to the existing rule.
func unversionedAgentBuild(serving, running string) string {
	if running == "" {
		return ""
	}
	if _, _, ok := parseVersionParts(serving); !ok {
		return "this server serves agent build \"" + serving + "\", which has no release version to compare with the endpoint's " +
			running + "; rebuild the server with one (make up VERSION=x.y.z AGENT_VERSION=x.y.z, or set MUSTRA_VERSION and " +
			"MUSTRA_AGENT_VERSION for docker compose build)"
	}
	if _, _, ok := parseVersionParts(running); !ok {
		return "this endpoint runs agent build \"" + running + "\", which has no release version, so an update cannot tell " +
			"whether " + serving + " is newer; reinstall it with an enrollment token from Client Management"
	}
	return ""
}
