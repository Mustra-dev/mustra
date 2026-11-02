package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	mustra "github.com/mustra-dev/mustra"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

// httpUpdateClient is separate from the OSV client's: an update check is a
// single foreground request an admin is waiting on, so it fails fast rather
// than holding the page.
var httpUpdateClient = &http.Client{Timeout: 12 * time.Second}

type agentVersionCount struct {
	Version string `json:"version"`
	Count   int    `json:"count"`
}

type aboutResponse struct {
	Server        version.Info        `json:"server"`
	StartedAt     string              `json:"started_at"`
	AgentVersions []agentVersionCount `json:"agent_versions"`
	Changelog     string              `json:"changelog"`
	UpdateRepo    string              `json:"update_repo"`
}

// handleAbout reports what's running: this build's identity, how long it's
// been up, and which agent versions are actually out on the fleet (an
// upgrade that only half-landed is otherwise invisible).
func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	counts := map[string]int{}
	if agents, err := s.store.ListAgents(r.Context(), s.staleAfter()); err == nil {
		for _, a := range agents {
			v := a.AgentVersion
			if v == "" {
				v = "unknown"
			}
			counts[v]++
		}
	}
	versions := make([]agentVersionCount, 0, len(counts))
	for v, n := range counts {
		versions = append(versions, agentVersionCount{Version: v, Count: n})
	}
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].Count != versions[j].Count {
			return versions[i].Count > versions[j].Count
		}
		return versions[i].Version < versions[j].Version
	})

	settings, _ := s.store.GetAllSettings(r.Context())
	writeJSONResponse(w, aboutResponse{
		Server:        version.Current(),
		StartedAt:     s.startedAt.UTC().Format(time.RFC3339),
		AgentVersions: versions,
		Changelog:     mustra.Changelog,
		UpdateRepo:    settings[settingUpdateRepo],
	})
}

// versionResponse is what GET /api/version answers.
type versionResponse struct {
	Agent     string `json:"agent"`
	BuildTime string `json:"build_time"`
	Commit    string `json:"commit"`
	Server    string `json:"server"`
}

// GET /api/version: what's running, for the profile menu and every page's
// footer. /api/about says the same and more (the changelog, the fleet's agent
// versions), which is too much to fetch on each page.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	v := version.Current()
	writeJSONResponse(w, versionResponse{
		Server: v.Version, Commit: v.ShortSHA, BuildTime: v.BuildTime, Agent: version.Agent(),
	})
}

type updateCheckResponse struct {
	Checked  bool   `json:"checked"`
	UpToDate bool   `json:"up_to_date"`
	Message  string `json:"message"`

	// RunningVersion is what this build calls itself; LatestVersion is the
	// newest published release. Releases rather than commits: a commit on
	// the default branch is not something anybody can install, so comparing
	// against one told an operator they were behind and left them with
	// nothing to do about it.
	RunningVersion string `json:"running_version,omitempty"`
	LatestVersion  string `json:"latest_version,omitempty"`
	LatestName     string `json:"latest_name,omitempty"`
	LatestDate     string `json:"latest_date,omitempty"`
	ReleaseURL     string `json:"release_url,omitempty"`
	ReleaseNotes   string `json:"release_notes,omitempty"`
	// UpgradeCommand is how to actually take the update. The server runs as
	// a container with no access to the daemon that owns it, so it can say
	// what to run and cannot run it -- offering a button that did nothing
	// would be worse than printing the command.
	UpgradeCommand string `json:"upgrade_command,omitempty"`
}

// releaseNotesLimit keeps a chatty release body from becoming the page.
const releaseNotesLimit = 1200

// handleUpdateCheck asks GitHub for the newest published release and
// compares its version to this build's.
//
// Releases, not commits. This compared the default branch's HEAD before,
// which meant it went red the moment anybody pushed anything and pointed at
// something nobody could install. A release is a thing an operator can
// actually move to, and the version on it is the version this build reports
// on the same page.
//
// It reports honestly when it cannot tell — an unconfigured repository, a
// private one with no token, a build with no version stamped in, or a
// repository with no releases yet are all "don't know", never a cheerful
// "you're up to date".
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.GetAllSettings(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	repo := strings.TrimSpace(settings[settingUpdateRepo])
	token := strings.TrimSpace(settings[settingUpdateToken])

	if repo == "" {
		writeJSONResponse(w, updateCheckResponse{
			Message: "No upstream repository is configured — set one below to check for updates.",
		})
		return
	}
	running := version.Current().Version
	if running == "" || running == "dev" {
		writeJSONResponse(w, updateCheckResponse{
			Message: "This build reports its version as \"dev\", so there is nothing to compare against a release. Builds made through deploy/Dockerfile.server carry a real one.",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpUpdateClient.Do(req)
	if err != nil {
		writeJSONResponse(w, updateCheckResponse{Message: "Couldn't reach GitHub: " + err.Error(), RunningVersion: running})
		return
	}
	defer resp.Body.Close()

	// 404 is both "no such repository" and "this repository has published no
	// releases", and the difference matters to whoever is reading it.
	if resp.StatusCode == http.StatusNotFound {
		writeJSONResponse(w, updateCheckResponse{
			Message: fmt.Sprintf("GitHub returned 404 for %s. Either it has published no releases yet, "+
				"or it is private and needs a token with read access below.", repo),
			RunningVersion: running,
		})
		return
	}
	if resp.StatusCode != http.StatusOK {
		writeJSONResponse(w, updateCheckResponse{
			Message:        fmt.Sprintf("GitHub returned %s.", resp.Status),
			RunningVersion: running,
		})
		return
	}

	var payload struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		HTMLURL     string `json:"html_url"`
		PublishedAt string `json:"published_at"`
		Body        string `json:"body"`
		Draft       bool   `json:"draft"`
		Prerelease  bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		writeJSONResponse(w, updateCheckResponse{Message: "Couldn't read GitHub's response: " + err.Error(), RunningVersion: running})
		return
	}

	latest := normalizeVersionTag(payload.TagName)
	if latest == "" {
		writeJSONResponse(w, updateCheckResponse{
			Message:        fmt.Sprintf("%s's newest release is tagged %q, which isn't a version this can compare.", repo, payload.TagName),
			RunningVersion: running,
		})
		return
	}

	out := updateCheckResponse{
		Checked:        true,
		RunningVersion: running,
		LatestVersion:  latest,
		LatestName:     payload.Name,
		LatestDate:     payload.PublishedAt,
		ReleaseURL:     payload.HTMLURL,
	}

	switch {
	case versionIsNewer(latest, running):
		out.Message = fmt.Sprintf("Version %s is available. This server is running %s.", latest, running)
		out.ReleaseNotes = truncateNotes(payload.Body)
		// Named explicitly rather than "pull the new image": the stack has
		// two services and starting only one of them is how a server ends
		// up waiting on a script-tools that never became healthy.
		out.UpgradeCommand = "docker compose pull server script-tools && docker compose up -d server script-tools"
	case versionIsNewer(running, latest):
		// Ahead of the newest release: a build from source, which is normal
		// here and not something to nag about.
		out.UpToDate = true
		out.Message = fmt.Sprintf("Running %s, which is ahead of %s's newest release (%s).", running, repo, latest)
	default:
		out.UpToDate = true
		out.Message = fmt.Sprintf("Already up to date — %s is the newest release of %s.", running, repo)
	}

	u := auth.CurrentUser(r.Context())
	s.logger.Info("update check", "repo", repo, "running", running, "latest", latest,
		"up_to_date", out.UpToDate, "requested_by", u.Username)
	writeJSONResponse(w, out)
}

// normalizeVersionTag turns a release tag into a comparable version.
// Releases here are tagged "v0.71.2"; the leading v is convention, not part
// of the version the binary reports.
func normalizeVersionTag(tag string) string {
	tag = strings.TrimSpace(tag)
	tag = strings.TrimPrefix(tag, "v")
	if _, _, ok := parseVersionParts(tag); !ok {
		return ""
	}
	return tag
}

// truncateNotes keeps a release body to something that fits beside a
// button, cutting at a line break so it does not end mid-word.
func truncateNotes(body string) string {
	body = strings.TrimSpace(body)
	if len(body) <= releaseNotesLimit {
		return body
	}
	cut := body[:releaseNotesLimit]
	if i := strings.LastIndexByte(cut, '\n'); i > releaseNotesLimit/2 {
		cut = cut[:i]
	}
	return strings.TrimSpace(cut) + "\n…"
}

// agentActionsResponse is what GET /api/agents/{id}/actions answers.
type agentActionsResponse struct {
	Actions []store.AgentAction `json:"actions"`
}

// handleAgentActions returns everything mustra has done to one device,
// whoever started it — a patch job, a bulk deployment, an agent push. This
// is the same feed Self Service shows a machine about itself.
func (s *Server) handleAgentActions(w http.ResponseWriter, r *http.Request) {
	actions, err := s.store.ListAgentActions(r.Context(), r.PathValue("id"), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, agentActionsResponse{Actions: actions})
}

// agentVersionHistoryResponse is what GET /api/agents/{id}/versions
// answers.
type agentVersionHistoryResponse struct {
	History []store.AgentVersionChange `json:"history"`
}

// handleAgentVersionHistory returns one agent's version transitions — what
// it's running now and what it ran before.
func (s *Server) handleAgentVersionHistory(w http.ResponseWriter, r *http.Request) {
	history, err := s.store.AgentVersionHistory(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, agentVersionHistoryResponse{History: history})
}

// recentVersionChange is an entry of what GET /api/agent-versions answers.
type recentVersionChange struct {
	store.AgentVersionChange
	Hostname string `json:"hostname"`
}

// recentAgentVersionsResponse is what GET /api/agent-versions answers.
type recentAgentVersionsResponse struct {
	Changes []recentVersionChange `json:"changes"`
}

// handleRecentAgentVersions is the fleet-wide upgrade feed, so a rollout in
// progress is visible as it happens rather than only in hindsight.
func (s *Server) handleRecentAgentVersions(w http.ResponseWriter, r *http.Request) {
	changes, err := s.store.RecentAgentVersionChanges(r.Context(), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := make(map[string]string, len(agents))
	for _, a := range agents {
		names[a.AgentID] = a.Hostname
	}
	out := make([]recentVersionChange, 0, len(changes))
	for _, c := range changes {
		out = append(out, recentVersionChange{AgentVersionChange: c, Hostname: names[c.AgentID]})
	}
	writeJSONResponse(w, recentAgentVersionsResponse{Changes: out})
}
