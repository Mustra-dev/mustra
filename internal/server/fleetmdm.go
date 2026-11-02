package server

// macOS updates through an MDM (Fleet).
//
// On Apple Silicon, softwareupdate installs macOS itself only with the
// password of a user who owns the disk. The agent runs as root with no such
// password, so it skips macOS updates there (see applyPatchesDarwin). An MDM
// that holds the Mac's Bootstrap Token can install them without one, using
// Apple's ScheduleOSUpdate command. Fleet passes raw MDM commands through
// its API on every tier, so when a Fleet URL and API token are configured,
// the end of a Mac's patch job hands the pending macOS update to Fleet.
//
// The macOS install is its own action in the same deployment run: it
// finishes when the Mac reports the new version, not when Fleet accepts
// the command. Linux and Windows patching never involve the MDM.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	settingFleetURL        = "mdm.fleet_url"
	settingFleetToken      = "mdm.fleet_token"
	settingFleetMacOSMajor = "mdm.fleet_macos_major"

	macOSMDMKind = "macos_mdm_update"
	// macOSMDMLimit is how long an install may take, from the command to
	// the Mac reporting the new version: download, install and restart.
	macOSMDMLimit = 4 * time.Hour
)

type fleetClient struct {
	base  string
	token string
	http  *http.Client
}

// fleetConfig reads the Fleet integration. A nil client means it is off.
func (s *Server) fleetConfig(ctx context.Context) (*fleetClient, bool, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return nil, false, err
	}
	base := strings.TrimRight(strings.TrimSpace(settings[settingFleetURL]), "/")
	stored := settings[settingFleetToken]
	if base == "" || stored == "" {
		return nil, false, nil
	}
	token, err := s.openSetting(settingFleetToken, stored)
	if err != nil {
		return nil, false, err
	}
	return &fleetClient{base: base, token: token, http: &http.Client{Timeout: 20 * time.Second}},
		settings[settingFleetMacOSMajor] == "true", nil
}

// sealSetting stores a secret setting through the credential vault when
// there is one, and says so in a prefix either way.
func (s *Server) sealSetting(key, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if s.vault == nil {
		return "plain:" + value, nil
	}
	ct, err := s.vault.Seal(value, vault.SettingAAD(key))
	if err != nil {
		return "", err
	}
	return "vault:" + base64.StdEncoding.EncodeToString(ct), nil
}

func (s *Server) openSetting(key, stored string) (string, error) {
	switch {
	case strings.HasPrefix(stored, "plain:"):
		return strings.TrimPrefix(stored, "plain:"), nil
	case strings.HasPrefix(stored, "vault:"):
		if s.vault == nil {
			return "", errors.New("this secret is encrypted but no credential encryption key is configured (MUSTRA_CREDENTIAL_ENCRYPTION_KEY)")
		}
		ct, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, "vault:"))
		if err != nil {
			return "", err
		}
		plain, _, err := s.vault.Open(ct, vault.SettingAAD(key))
		return plain, err
	}
	return "", errors.New("unrecognised stored secret")
}

func validateFleetURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("the Fleet URL must be http(s)://host[:port]")
	}
	return nil
}

func (c *fleetClient) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	return c.send(ctx, method, path, "application/json", rd, out)
}

// send is do with the body already encoded, for the multipart upload of a
// configuration profile.
func (c *fleetClient) send(ctx context.Context, method, path, contentType string, rd io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "mustra")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Fleet: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		var fe struct {
			Message string `json:"message"`
			Errors  []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &fe) == nil && fe.Message != "" {
			msg = fe.Message
			if len(fe.Errors) > 0 && fe.Errors[0].Reason != fe.Message {
				msg += ": " + fe.Errors[0].Reason
			}
		}
		return fmt.Errorf("Fleet %s %s: %d %s", method, path, resp.StatusCode, safeTruncate(msg, 300))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// me checks the URL and token, for the settings page's Test button.
func (c *fleetClient) me(ctx context.Context) (string, error) {
	var r struct {
		User struct {
			Email      string `json:"email"`
			GlobalRole string `json:"global_role"`
		} `json:"user"`
	}
	if err := c.do(ctx, "GET", "/api/v1/fleet/me", nil, &r); err != nil {
		return "", err
	}
	return r.User.Email + " (" + r.User.GlobalRole + ")", nil
}

// hostUUID finds the Mac in Fleet by hostname. The agent reports no serial
// number, and Fleet lists the hostname macOS reports, case aside.
func (c *fleetClient) hostUUID(ctx context.Context, hostname string) (string, error) {
	short := strings.TrimSuffix(strings.ToLower(hostname), ".local")
	var r struct {
		Hosts []struct {
			UUID         string `json:"uuid"`
			Hostname     string `json:"hostname"`
			ComputerName string `json:"computer_name"`
			Platform     string `json:"platform"`
		} `json:"hosts"`
	}
	if err := c.do(ctx, "GET", "/api/v1/fleet/hosts?per_page=50&query="+url.QueryEscape(short), nil, &r); err != nil {
		return "", err
	}
	var found []string
	for _, h := range r.Hosts {
		if h.Platform != "darwin" {
			continue
		}
		if strings.TrimSuffix(strings.ToLower(h.Hostname), ".local") == short || strings.EqualFold(h.ComputerName, short) {
			found = append(found, h.UUID)
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("no Mac named %s is enrolled in Fleet", hostname)
	case 1:
		return found[0], nil
	}
	return "", fmt.Errorf("%d Macs in Fleet are named %s; rename one so they can be told apart", len(found), hostname)
}

// command sends one raw MDM command to one Mac and returns its UUID.
func (c *fleetClient) command(ctx context.Context, hostUUID, requestType string, fields string) (string, error) {
	id := commandUUID()
	payload := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CommandUUID</key><string>` + id + `</string><key>Command</key><dict><key>RequestType</key><string>` +
		requestType + `</string>` + fields + `</dict></dict></plist>`
	var r struct {
		CommandUUID string `json:"command_uuid"`
	}
	err := c.do(ctx, "POST", "/api/v1/fleet/commands/run", map[string]any{
		"command": base64.StdEncoding.EncodeToString([]byte(payload)), "host_uuids": []string{hostUUID},
	}, &r)
	if err == nil && r.CommandUUID == "" {
		err = errors.New("Fleet returned no command UUID")
	}
	return r.CommandUUID, err
}

// result returns a command's status (Pending, Acknowledged, Error,
// NotNow) and its decoded response.
func (c *fleetClient) result(ctx context.Context, commandUUID string) (string, map[string]any, error) {
	var r struct {
		Results []struct {
			Status string `json:"status"`
			Result string `json:"result"`
		} `json:"results"`
	}
	if err := c.do(ctx, "GET", "/api/v1/fleet/commands/results?command_uuid="+url.QueryEscape(commandUUID), nil, &r); err != nil {
		return "", nil, err
	}
	if len(r.Results) == 0 {
		return "Pending", nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(r.Results[0].Result)
	if err != nil {
		return r.Results[0].Status, nil, nil
	}
	v, _ := parsePlist(raw)
	m, _ := v.(map[string]any)
	return r.Results[0].Status, m, nil
}

// await polls a command until the Mac answers or limit passes.
func (c *fleetClient) await(ctx context.Context, commandUUID string, limit time.Duration) (string, map[string]any, error) {
	deadline := time.Now().Add(limit)
	for {
		status, res, err := c.result(ctx, commandUUID)
		if err != nil || (status != "Pending" && status != "") || time.Now().After(deadline) {
			return status, res, err
		}
		select {
		case <-ctx.Done():
			return status, res, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

type macOSUpdate struct {
	ProductKey string
	Name       string
	Version    string
	Major      bool
}

func availableOSUpdates(res map[string]any) []macOSUpdate {
	list, _ := res["AvailableOSUpdates"].([]any)
	var out []macOSUpdate
	for _, it := range list {
		d, _ := it.(map[string]any)
		if d == nil {
			continue
		}
		u := macOSUpdate{}
		u.ProductKey, _ = d["ProductKey"].(string)
		u.Name, _ = d["HumanReadableName"].(string)
		u.Version, _ = d["Version"].(string)
		u.Major, _ = d["IsMajorOSUpdate"].(bool)
		if strings.Contains(u.ProductKey, "_major") {
			u.Major = true
		}
		if u.ProductKey != "" && u.Version != "" {
			out = append(out, u)
		}
	}
	return out
}

// errorChain renders an MDM error response's ErrorChain.
func errorChain(res map[string]any) string {
	chain, _ := res["ErrorChain"].([]any)
	var parts []string
	for _, it := range chain {
		if d, _ := it.(map[string]any); d != nil {
			if s, _ := d["LocalizedDescription"].(string); s != "" {
				parts = append(parts, s)
			}
		}
	}
	if len(parts) == 0 {
		return "the Mac refused the command"
	}
	return strings.Join(parts, "; ")
}

// pickMacOSUpdate chooses what to install: the newest update the agent
// reported pending and the patch lists allow, minor versions only unless
// major upgrades are turned on. With no inventory (pending nil) the Mac's
// own list is used, still subject to the patch lists.
func pickMacOSUpdate(available []macOSUpdate, pending []proto.PatchInfo, allowed func(string) bool, allowMajor bool) (macOSUpdate, bool) {
	var best macOSUpdate
	found := false
	for _, u := range available {
		if u.Major && !allowMajor {
			continue
		}
		ok := pending == nil && allowed(u.Name)
		for _, p := range pending {
			if p.NewVersion == u.Version && strings.HasPrefix(p.Name, "macOS") && allowed(p.Name) {
				ok = true
				break
			}
		}
		if ok && (!found || macOSVersionNewer(u.Version, best.Version)) {
			best, found = u, true
		}
	}
	return best, found
}

var targetVersionRE = regexp.MustCompile(`\(target ([0-9][0-9.]*)[,)]`)

// macOSUpdateViaMDM runs after a Mac's patch job has finished: the agent
// installed what it can, and the macOS update it had to skip goes to the
// MDM. Idempotent per run, since a redelivered result calls it again.
func (s *Server) macOSUpdateViaMDM(ctx context.Context, agentID, runID, patchActionID string) {
	fleet, allowMajor, err := s.fleetConfig(ctx)
	if err != nil {
		s.logger.Warn("read Fleet settings", "error", err)
		return
	}
	if fleet == nil || runID == "" {
		return
	}
	agent := s.agentByID(ctx, agentID)
	if agent == nil {
		s.logger.Info("macOS update through the MDM not started", "agent_id", agentID, "reason", "endpoint not found")
		return
	}
	if agent.OS != "darwin" {
		return
	}
	// The patch job told the agent the same thing (patchpolicy_api.go): a
	// Mac Fleet cannot update had its macOS update downloaded by the agent,
	// and the person at it is asked to install it.
	if !fleet.canInstallMacOS(ctx, agent.PlatformVersion) {
		s.logger.Info("macOS update left to the person at the Mac", "agent_id", agentID, "run_id", runID,
			"reason", "Fleet installs macOS "+agent.PlatformVersion+" only with a Premium license")
		return
	}
	skip := func(why string, err error) {
		s.logger.Info("macOS update through the MDM not started", "agent_id", agentID, "run_id", runID, "reason", why, "error", err)
	}
	if exists, err := s.store.AgentActionExists(ctx, runID, agentID, macOSMDMKind); err != nil || exists {
		skip("already handled for this run", err)
		return
	}
	// The agent's last inventory says whether anything is pending. Right
	// after an agent update there is none yet; then the Mac's own answer
	// through the MDM decides (pending stays nil).
	var pending []proto.PatchInfo
	if rec, err := s.store.GetSensorData(ctx, agentID, "patches"); err == nil && rec != nil {
		if err := json.Unmarshal(rec.Data, &pending); err != nil {
			pending = nil
		}
		hasMacOS := false
		for _, p := range pending {
			hasMacOS = hasMacOS || (strings.HasPrefix(p.Name, "macOS") && p.RestartRequired)
		}
		if !hasMacOS {
			skip("no macOS update pending", nil)
			return
		}
	}
	allowed := func(string) bool { return true }
	if plans, err := s.planPatches(ctx, []string{agentID}); err == nil && plans[agentID].Restricted {
		ok := map[string]bool{}
		for _, n := range plans[agentID].Allowed {
			ok[n] = true
		}
		allowed = func(n string) bool { return ok[n] }
	}
	requestedBy, restartMode, _ := s.store.ActionOrigin(ctx, patchActionID)

	actionID := idgen.New("act-")
	open := func(summary string) {
		_ = s.store.StartAgentActionWithStatus(ctx, store.AgentAction{
			ID: actionID, RunID: runID, AgentID: agentID, Kind: macOSMDMKind, Summary: summary, RequestedBy: requestedBy,
		}, "started", "Asking Fleet which macOS updates the Mac offers")
	}
	fail := func(why string) {
		_ = s.store.FinishAgentAction(ctx, agentID, actionID, "failed", why)
		s.notify(ctx, "warning", "Patch", "macOS update through Fleet failed on "+agent.Hostname, safeTruncate(why, 300), "/patches#deployments")
	}

	open("Install macOS through Fleet MDM")
	hostUUID, err := fleet.hostUUID(ctx, agent.Hostname)
	if err != nil {
		fail(err.Error())
		return
	}
	if macOSMajor(agent.PlatformVersion) >= macOSDeclarativeOnly {
		s.macOSUpdateViaDeclaration(ctx, fleet, agent, actionID, hostUUID, pending, allowed, allowMajor, restartMode, fail)
		return
	}
	cmdID, err := fleet.command(ctx, hostUUID, "AvailableOSUpdates", "")
	if err != nil {
		fail(err.Error())
		return
	}
	status, res, err := fleet.await(ctx, cmdID, 3*time.Minute)
	switch {
	case err != nil:
		fail(err.Error())
		return
	case status == "Error":
		fail("The Mac could not list its updates: " + errorChain(res))
		return
	case status != "Acknowledged":
		fail("The Mac did not answer Fleet within 3 minutes (asleep or offline?). Run the patch job again when it is awake.")
		return
	}
	update, ok := pickMacOSUpdate(availableOSUpdates(res), pending, allowed, allowMajor)
	if !ok {
		why := "No macOS update to install: the Mac offers none that the patch lists allow"
		if !allowMajor {
			why += ", and major upgrades are turned off in Settings → macOS MDM"
		}
		_ = s.store.FinishAgentAction(ctx, agentID, actionID, "skipped", why)
		return
	}
	// With a restart asked for, macOS installs at once and restarts by
	// itself. Without one it downloads the update and asks whoever is
	// signed in to install it, so nobody loses their work to a restart.
	action, now := "InstallLater", false
	if restartMode == "if_required" || restartMode == "always" {
		action, now = "InstallASAP", true
	}
	_ = s.store.SetActionSummary(ctx, actionID, fmt.Sprintf("Install %s through Fleet MDM (target %s)", update.Name, update.Version))
	fields := `<key>Updates</key><array><dict><key>ProductKey</key><string>` + xmlEscape(update.ProductKey) +
		`</string><key>InstallAction</key><string>` + action + `</string></dict></array>`
	cmdID, err = fleet.command(ctx, hostUUID, "ScheduleOSUpdate", fields)
	if err != nil {
		fail(err.Error())
		return
	}
	_ = s.store.SetAgentActionProgress(ctx, agentID, actionID, "started", "Sent "+update.Name+" to the Mac through Fleet ("+action+")")
	status, res, err = fleet.await(ctx, cmdID, 10*time.Minute)
	switch {
	case err != nil:
		_ = s.store.SetAgentActionProgress(ctx, agentID, actionID, "started", "Sent through Fleet; could not read the answer: "+err.Error())
	case status == "Error":
		fail("The Mac refused " + update.Name + ": " + errorChain(res))
	case status != "Acknowledged":
		_ = s.store.SetAgentActionProgress(ctx, agentID, actionID, "started", "Sent through Fleet; the Mac has not picked it up yet (asleep?). It installs when it wakes.")
	case now:
		_ = s.store.SetAgentActionProgress(ctx, agentID, actionID, "installing",
			"The Mac accepted "+update.Name+". It downloads, installs and restarts on its own; this finishes when it reports the new version.")
	default:
		_ = s.store.FinishAgentAction(ctx, agentID, actionID, "pending_restart",
			"The Mac accepted "+update.Name+" and downloads it; macOS asks the signed-in user to install it and restart. "+
				"Apply with a restart option to install it without asking.")
	}
}

// macOSMDMWatchLoop finishes macOS installs: succeeded once the Mac reports
// the target version, failed when that has not happened in time.
func (s *Server) macOSMDMWatchLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		open, err := s.store.OpenAgentActions(ctx, macOSMDMKind)
		if err != nil || len(open) == 0 {
			continue
		}
		for _, act := range open {
			m := targetVersionRE.FindStringSubmatch(act.Summary)
			agent := s.agentByID(ctx, act.AgentID)
			if agent == nil {
				continue
			}
			// A declaration's install may wait for its deadline; it is
			// removed from Fleet once the install is over either way.
			deadline, declared := macOSActionDeadline(act.Summary)
			if m != nil && !macOSVersionNewer(m[1], agent.PlatformVersion) {
				_ = s.store.FinishAgentAction(ctx, act.AgentID, act.ID, "succeeded", "macOS "+agent.PlatformVersion+" is installed.")
				if declared {
					s.removeMacOSDeclaration(ctx)
				}
				continue
			}
			if agent.Online && !versionIsNewer(macOSProgressAgentVersion, agent.AgentVersion) {
				s.reportMacOSProgress(ctx, act, m)
			}
			if declared {
				if time.Now().After(deadline.Add(24 * time.Hour)) {
					why := fmt.Sprintf("The Mac still reports macOS %s a day after the update's deadline. Check System Settings → General → Software Update on it.", agent.PlatformVersion)
					_ = s.store.FinishAgentAction(ctx, act.AgentID, act.ID, "failed", why)
					s.removeMacOSDeclaration(ctx)
				}
				continue
			}
			if time.Since(act.StartedAt) > macOSMDMLimit {
				why := fmt.Sprintf("The Mac still reports macOS %s %s after the update was sent. Check System Settings → General → Software Update on it.",
					agent.PlatformVersion, shortAgo(act.StartedAt))
				_ = s.store.FinishAgentAction(ctx, act.AgentID, act.ID, "failed", why)
			}
		}
	}
}

func (s *Server) agentByID(ctx context.Context, id string) *store.AgentRecord {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil
	}
	for i := range agents {
		if agents[i].AgentID == id {
			return &agents[i]
		}
	}
	return nil
}

// commandUUID is a random (version 4) UUID, the form MDM command IDs take.
func commandUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]))
}

// macOSProgressAgentVersion is the first agent that reads softwareupdated's
// progress for the console.
const macOSProgressAgentVersion = "0.57.18"

// reportMacOSProgress shows how far the Mac has got, read by the agent from
// softwareupdated's log. The MDM's OSUpdateStatus is no use for this: on
// the MacBook it kept answering with an old download error while the
// update downloaded and prepared.
func (s *Server) reportMacOSProgress(ctx context.Context, act store.AgentAction, target []string) {
	payload, _ := json.Marshal(proto.AgentCommand{Cmd: "macos_update_progress"})
	rctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(act.AgentID), payload)
	if err != nil {
		return
	}
	var res proto.AgentCommandResult
	if json.Unmarshal(msg.Data, &res) != nil || !res.OK || res.Output == "" {
		return
	}
	var p struct {
		Phase   string  `json:"phase"`
		Percent float64 `json:"percent"`
		Stalled bool    `json:"stalled"`
	}
	if json.Unmarshal([]byte(res.Output), &p) != nil {
		return
	}
	stage, status := "Installing", "installing"
	switch p.Phase {
	case "DOWNLOADING_UPDATE":
		stage, status = "Downloading", "downloading"
	case "PREPARING_UPDATE":
		stage = "Preparing"
	}
	what := "macOS"
	if target != nil {
		what = "macOS " + target[1]
	}
	detail := fmt.Sprintf("%s %s: %.0f%% overall", stage, what, p.Percent)
	if p.Stalled {
		detail += " (macOS reports it stalled)"
	}
	detail += ". It restarts on its own when ready; this finishes when the Mac reports the new version."
	if detail != act.Detail {
		_ = s.store.SetAgentActionProgress(ctx, act.AgentID, act.ID, status, detail)
	}
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// parsePlist decodes an XML property list into maps, slices, strings,
// int64s and bools: enough to read MDM command responses.
func parsePlist(data []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local != "plist" {
			return plistValue(d, se)
		}
	}
}

func plistValue(d *xml.Decoder, se xml.StartElement) (any, error) {
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		key := ""
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					var k string
					if err := d.DecodeElement(&k, &t); err != nil {
						return nil, err
					}
					key = k
					continue
				}
				v, err := plistValue(d, t)
				if err != nil {
					return nil, err
				}
				m[key] = v
			case xml.EndElement:
				return m, nil
			}
		}
	case "array":
		var a []any
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := plistValue(d, t)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			case xml.EndElement:
				return a, nil
			}
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	case "integer":
		var n int64
		err := d.DecodeElement(&n, &se)
		return n, err
	default:
		var s string
		err := d.DecodeElement(&s, &se)
		return s, err
	}
}
