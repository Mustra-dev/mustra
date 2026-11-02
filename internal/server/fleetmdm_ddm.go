package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// macOS 27 removed the MDM software update commands (AvailableOSUpdates,
// ScheduleOSUpdate, OSUpdateStatus): a Mac answers "Unknown command". The
// replacement is a declarative management configuration,
// com.apple.configuration.softwareupdate.enforcement.specific: a target
// version and a local date and time by which the Mac installs it, asking
// the signed-in user until then. Apple accepts it from macOS 14 on
// supervised Macs (Automated Device Enrollment, or a user-approved
// enrollment, which macOS supervises).
//
// Mustra uploads it to Fleet as a configuration profile. Aiming a profile
// at one Mac takes labels or teams, which are Fleet Premium; on the free
// tier a profile reaches every Mac Fleet has not assigned to a team. So
// the update is sent only when the Mac being patched is the only such
// Mac, and is refused otherwise, rather than updating Macs nobody patched.

const (
	// macOSDeclarativeOnly is the first macOS that no longer accepts the
	// MDM software update commands.
	macOSDeclarativeOnly = 27
	// macOSDeclarationID identifies mustra's one update declaration; a new
	// target replaces it.
	macOSDeclarationID = "com.mustra.macos-update"
	// macOSAskDeadline is how long the signed-in user may put the update
	// off when the patch run asked for no restart.
	macOSAskDeadline = 72 * time.Hour
)

// macOSMajor is the major version of "27.0.1", or 0.
func macOSMajor(v string) int {
	n, _ := strconv.Atoi(strings.SplitN(strings.TrimSpace(v), ".", 2)[0])
	return n
}

// macOSUpdateDeclaration is the declaration's JSON. deadline is the Mac's
// local date and time; Apple's format has no zone.
func macOSUpdateDeclaration(version string, deadline time.Time) []byte {
	b, _ := json.MarshalIndent(map[string]any{
		"Type":       "com.apple.configuration.softwareupdate.enforcement.specific",
		"Identifier": macOSDeclarationID,
		"Payload": map[string]any{
			"TargetOSVersion":     version,
			"TargetLocalDateTime": deadline.Format("2006-01-02T15:04:05"),
		},
	}, "", "  ")
	return b
}

// macOSDeadline: with a restart asked for, a date already past, so the Mac
// installs at once (Apple: it force-installs once the date has passed, or
// an hour after it next starts). Otherwise the signed-in user has
// macOSAskDeadline to install it themselves. The server does not know the
// Mac's time zone, so the time is UTC: a day in the past is past
// everywhere, and three days is three days give or take its offset.
func macOSDeadline(now time.Time, installNow bool) time.Time {
	if installNow {
		return now.UTC().Add(-24 * time.Hour)
	}
	return now.UTC().Add(macOSAskDeadline)
}

// pickMacOSTarget chooses the version to install from the agent's
// inventory: the newest macOS update the patch lists allow, a major
// upgrade only when those are turned on.
func pickMacOSTarget(pending []proto.PatchInfo, installed string, allowed func(string) bool, allowMajor bool) (proto.PatchInfo, bool) {
	var best proto.PatchInfo
	found := false
	for _, p := range pending {
		if !strings.HasPrefix(p.Name, "macOS") || p.NewVersion == "" || !allowed(p.Name) {
			continue
		}
		if !allowMajor && macOSMajor(p.NewVersion) > macOSMajor(installed) {
			continue
		}
		if !found || macOSVersionNewer(p.NewVersion, best.NewVersion) {
			best, found = p, true
		}
	}
	return best, found
}

type fleetHost struct {
	UUID     string `json:"uuid"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	TeamID   *int   `json:"team_id"`
}

// unassignedMacs lists the MDM-enrolled Macs in no Fleet team: the Macs a
// free-tier configuration profile reaches.
func (c *fleetClient) unassignedMacs(ctx context.Context) ([]fleetHost, error) {
	var out []fleetHost
	for page := 0; page < 20; page++ {
		var r struct {
			Hosts []fleetHost `json:"hosts"`
		}
		path := "/api/v1/fleet/hosts?mdm_enrollment_status=enrolled&per_page=500&page=" + strconv.Itoa(page)
		if err := c.do(ctx, "GET", path, nil, &r); err != nil {
			return nil, err
		}
		for _, h := range r.Hosts {
			if h.Platform == "darwin" && h.TeamID == nil {
				out = append(out, h)
			}
		}
		if len(r.Hosts) < 500 {
			break
		}
	}
	return out, nil
}

// profileUUIDs returns the UUIDs of the configuration profiles with the
// given identifier (in no team).
func (c *fleetClient) profileUUIDs(ctx context.Context, identifier string) ([]string, error) {
	var r struct {
		Profiles []struct {
			UUID       string `json:"profile_uuid"`
			Identifier string `json:"identifier"`
		} `json:"profiles"`
	}
	if err := c.do(ctx, "GET", "/api/v1/fleet/configuration_profiles?per_page=1000", nil, &r); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range r.Profiles {
		if p.Identifier == identifier {
			out = append(out, p.UUID)
		}
	}
	return out, nil
}

// replaceDeclaration uploads a declaration, removing any profile with the
// same identifier first: on the free tier a profile cannot be edited.
func (c *fleetClient) replaceDeclaration(ctx context.Context, identifier, filename string, body []byte) (string, error) {
	if err := c.removeDeclaration(ctx, identifier); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("profile", filename)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(body); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}
	var r struct {
		UUID string `json:"profile_uuid"`
	}
	if err := c.send(ctx, "POST", "/api/v1/fleet/configuration_profiles", mw.FormDataContentType(), &buf, &r); err != nil {
		return "", err
	}
	return r.UUID, nil
}

func (c *fleetClient) removeDeclaration(ctx context.Context, identifier string) error {
	ids, err := c.profileUUIDs(ctx, identifier)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := c.do(ctx, "DELETE", "/api/v1/fleet/configuration_profiles/"+url.PathEscape(id), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// macOSUpdateViaDeclaration installs macOS on a Mac that no longer takes
// the MDM update commands. The action is open until the watch loop sees
// the new version (or the deadline passes by a day); then the declaration
// is removed, so it never applies to a Mac enrolled later.
func (s *Server) macOSUpdateViaDeclaration(ctx context.Context, fleet *fleetClient, agent *store.AgentRecord, actionID, hostUUID string,
	pending []proto.PatchInfo, allowed func(string) bool, allowMajor bool, restartMode string, fail func(string)) {
	if pending == nil {
		fail("macOS " + agent.PlatformVersion + " takes updates only by declaration, and the agent has not reported which macOS updates the Mac offers yet. Run the patch job again in a few minutes.")
		return
	}
	target, ok := pickMacOSTarget(pending, agent.PlatformVersion, allowed, allowMajor)
	if !ok {
		why := "No macOS update to install: the Mac offers none that the patch lists allow"
		if !allowMajor {
			why += ", and major upgrades are turned off in Administration → macOS MDM"
		}
		_ = s.store.FinishAgentAction(ctx, agent.AgentID, actionID, "skipped", why)
		return
	}
	macs, err := fleet.unassignedMacs(ctx)
	if err != nil {
		fail(err.Error())
		return
	}
	mine := false
	var names []string
	for _, h := range macs {
		mine = mine || h.UUID == hostUUID
		names = append(names, h.Hostname)
	}
	switch {
	case !mine:
		fail("The Mac is in a Fleet team. Mustra sends macOS updates as a profile for Macs in no team (aiming one at a team or a single Mac needs Fleet Premium labels); install it from System Settings → General → Software Update.")
		return
	case len(macs) > 1:
		fail(fmt.Sprintf("Fleet's free tier cannot aim an update at one Mac, and %d Macs are in no Fleet team (%s), so all of them would install macOS %s. "+
			"Install it from System Settings → General → Software Update, or move the other Macs to a Fleet team.",
			len(macs), strings.Join(names, ", "), target.NewVersion))
		return
	}
	installNow := restartMode == "if_required" || restartMode == "always"
	deadline := macOSDeadline(time.Now(), installNow)
	if _, err := fleet.replaceDeclaration(ctx, macOSDeclarationID, "mustra-macos-update.json", macOSUpdateDeclaration(target.NewVersion, deadline)); err != nil {
		why := "Fleet would not take the update declaration: " + err.Error()
		if strings.Contains(err.Error(), ": 402 ") {
			why = "Fleet installs macOS " + strconv.Itoa(macOSDeclarativeOnly) + " and later only with a Fleet Premium license (software update declarations). " +
				"Without one the agent downloads the update and asks the person at the Mac to install it; run the patch job again to do that."
		}
		fail(why)
		return
	}
	_ = s.store.SetActionSummary(ctx, actionID, fmt.Sprintf("Install %s through Fleet MDM (target %s, deadline %s)",
		target.Name, target.NewVersion, deadline.Format("2006-01-02T15:04")))
	msg := "Fleet delivers macOS " + target.NewVersion + " to the Mac as a declaration; it downloads, installs and restarts on its own. This finishes when it reports the new version."
	if !installNow {
		msg = "Fleet delivers macOS " + target.NewVersion + " to the Mac as a declaration. macOS asks the signed-in user to install it, and installs and restarts by itself after about " +
			deadline.Format("Jan 2 15:04") + " UTC if they have not. This finishes when it reports the new version."
	}
	_ = s.store.SetAgentActionProgress(ctx, agent.AgentID, actionID, "installing", msg)
}

var deadlineRE = regexp.MustCompile(`deadline (\d{4}-\d\d-\d\dT\d\d:\d\d)`)

// macOSActionDeadline reads "deadline 2026-10-30T20:15" from a summary.
func macOSActionDeadline(summary string) (time.Time, bool) {
	m := deadlineRE.FindStringSubmatch(summary)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02T15:04", m[1])
	return t, err == nil
}

// removeMacOSDeclaration deletes the update declaration from Fleet once an
// install is over, best effort: a stale one would make a Mac enrolled later
// install that version at a deadline long past.
func (s *Server) removeMacOSDeclaration(ctx context.Context) {
	fleet, _, err := s.fleetConfig(ctx)
	if err != nil || fleet == nil {
		return
	}
	if err := fleet.removeDeclaration(ctx, macOSDeclarationID); err != nil {
		s.logger.Warn("remove the macOS update declaration from Fleet", "error", err)
	}
}

// macOSVersionNewer reports whether macOS version a is newer than b. macOS
// numbers have two or three parts ("27.1", "26.7.1"), which
// versionIsNewer's x.y.z parser rejects, so it always answered false: a
// two-part target counted as installed at once. A missing part is 0.
func macOSVersionNewer(a, b string) bool {
	pa, pb := strings.Split(strings.TrimSpace(a), "."), strings.Split(strings.TrimSpace(b), ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// canInstallMacOS says whether Fleet can install macOS on a Mac running
// this version: always through the MDM commands before macOS 27; from 27
// only by declaration, which Fleet accepts with a Premium license alone.
// When it cannot, the agent downloads the update and asks the person at
// the Mac to install it instead.
func (c *fleetClient) canInstallMacOS(ctx context.Context, platformVersion string) bool {
	if macOSMajor(platformVersion) < macOSDeclarativeOnly {
		return true
	}
	premium, err := c.premium(ctx)
	return err == nil && premium
}

// premium reports whether Fleet runs with a Premium license.
func (c *fleetClient) premium(ctx context.Context) (bool, error) {
	var r struct {
		License struct {
			Tier string `json:"tier"`
		} `json:"license"`
	}
	if err := c.do(ctx, "GET", "/api/v1/fleet/config", nil, &r); err != nil {
		return false, err
	}
	return r.License.Tier == "premium", nil
}
