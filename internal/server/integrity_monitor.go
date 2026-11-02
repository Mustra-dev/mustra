package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Integrity Monitor management: watchlists, monitors and labels.
//
// The mechanism — hashing on the endpoint, diffing on the server, and
// real-time events — was already there; this is the layer that says
// *what* to watch per group of endpoints and *which* changes are the
// ordinary business of running a fleet. A monitor is a watchlist applied
// to computer groups; the union of an endpoint's monitors is its watch
// set, pushed as a "watch" command and re-applied every five minutes so
// an endpoint that joins a group, or restarts, converges. Labels are rules
// evaluated as a change or event is recorded: any matching label tags
// it, and a label marked "expected" classifies it as change that needs
// no investigation — which is the difference between a change log and a
// finding.

const watchApplyEvery = 5 * time.Minute

// effectiveWatch is the watch set one endpoint should run.
type effectiveWatch struct {
	Config   proto.WatchConfig
	Monitors []string // monitor names, for the status view
}

// effectiveWatchSets computes the watch set for every agent from the
// enabled monitors. An endpoint under no monitor gets an empty set with
// an empty revision, which the agent treats as "built-in only".
func (s *Server) effectiveWatchSets(ctx context.Context, agents []store.AgentRecord) (map[string]*effectiveWatch, error) {
	monitors, err := s.store.ListIntegrityMonitors(ctx)
	if err != nil {
		return nil, err
	}
	lists, err := s.store.ListWatchlists(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]store.Watchlist{}
	for _, w := range lists {
		byID[w.ID] = w
	}
	out := map[string]*effectiveWatch{}
	for _, a := range agents {
		// Monitors starts empty, not nil: the status view sends it as a
		// list, and an endpoint under no monitor still has a row.
		out[a.AgentID] = &effectiveWatch{Monitors: []string{}}
	}
	for _, m := range monitors {
		if !m.Enabled || len(m.GroupIDs) == 0 {
			continue
		}
		wl, ok := byID[m.WatchlistID]
		if !ok {
			continue
		}
		members, err := s.agentsInGroups(ctx, m.GroupIDs)
		if err != nil {
			return nil, err
		}
		for id := range members {
			ew := out[id]
			if ew == nil {
				continue
			}
			ew.Config.Paths = append(ew.Config.Paths, wl.Paths...)
			ew.Config.RegistryKeys = append(ew.Config.RegistryKeys, wl.RegistryKeys...)
			ew.Config.FollowSymlinks = ew.Config.FollowSymlinks || wl.FollowSymlinks
			ew.Monitors = append(ew.Monitors, m.Name)
		}
	}
	for _, ew := range out {
		ew.Config.Paths = uniqueSorted(ew.Config.Paths)
		ew.Config.RegistryKeys = uniqueSorted(ew.Config.RegistryKeys)
		sort.Strings(ew.Monitors)
		ew.Config.Revision = watchRevision(ew.Config)
	}
	return out, nil
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// watchRevision identifies a set by its content; an empty set has an
// empty revision so an unmonitored endpoint reports "" and matches.
func watchRevision(c proto.WatchConfig) string {
	if len(c.Paths) == 0 && len(c.RegistryKeys) == 0 && !c.FollowSymlinks {
		return ""
	}
	h := sha256.New()
	for _, p := range c.Paths {
		fmt.Fprintf(h, "p:%s\n", p)
	}
	for _, k := range c.RegistryKeys {
		fmt.Fprintf(h, "r:%s\n", k)
	}
	fmt.Fprintf(h, "s:%v\n", c.FollowSymlinks)
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func (s *Server) pushWatch(ctx context.Context, a store.AgentRecord, c proto.WatchConfig) error {
	payload, err := json.Marshal(proto.AgentCommand{Cmd: "watch", Watch: &c})
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(a.AgentID), payload)
	if err != nil {
		return fmt.Errorf("did not respond: %w", err)
	}
	var result proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return fmt.Errorf("unreadable reply: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("%s", result.Error)
	}
	return nil
}

// applyWatchSets pushes to every online endpoint whose reported revision
// differs from what its monitors say. Returns pushed and failed by host.
func (s *Server) applyWatchSets(ctx context.Context) (pushed int, failed map[string]string) {
	failed = map[string]string{}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return 0, failed
	}
	sets, err := s.effectiveWatchSets(ctx, agents)
	if err != nil {
		s.logger.Warn("resolve integrity monitors", "error", err)
		return 0, failed
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, a := range agents {
		ew := sets[a.AgentID]
		if ew == nil || !a.Online || ew.Config.Revision == a.WatchRevision {
			continue
		}
		wg.Add(1)
		go func(a store.AgentRecord, c proto.WatchConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			err := s.pushWatch(ctx, a, c)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed[a.Hostname] = err.Error()
				return
			}
			pushed++
		}(a, ew.Config)
	}
	wg.Wait()
	return pushed, failed
}

func (s *Server) watchApplyLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	s.seedIntegrityLabels(ctx)
	ticker := time.NewTicker(watchApplyEvery)
	defer ticker.Stop()
	for {
		pushed, failed := s.applyWatchSets(ctx)
		if pushed > 0 || len(failed) > 0 {
			s.logger.Info("integrity watch sets applied", "pushed", pushed, "failed", len(failed))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// --- labels ---------------------------------------------------------------

// labelCriteria are the conditions a label needs; every field set must
// hold. Time windows are in the given zone (UTC when blank); weekdays are
// 0=Sunday..6. Process and user are accepted for platforms that report
// them and currently never match, because no agent reports them yet —
// kept in the model so a rule written today survives the day they do.
type labelCriteria struct {
	PathPrefix   string   `json:"path_prefix,omitempty"`
	PathSuffix   string   `json:"path_suffix,omitempty"`
	PathContains string   `json:"path_contains,omitempty"`
	Kinds        []string `json:"kinds,omitempty"` // added | removed | modified | create | write | remove | rename | chmod
	GroupIDs     []string `json:"group_ids,omitempty"`
	Weekdays     []int    `json:"weekdays,omitempty"`
	Start        string   `json:"start,omitempty"` // HH:MM
	End          string   `json:"end,omitempty"`   // HH:MM
	Timezone     string   `json:"timezone,omitempty"`
	// DuringMaintenance matches while a maintenance window covering the
	// endpoint is open: the change-window rule.
	DuringMaintenance bool   `json:"during_maintenance,omitempty"`
	Process           string `json:"process,omitempty"`
	User              string `json:"user,omitempty"`
}

type compiledLabel struct {
	store.IntegrityLabel
	crit    labelCriteria
	members map[string]bool // nil when the label has no group criterion
}

// labelCache keeps compiled labels for a minute; every diff and every
// event batch consults them.
type labelCache struct {
	mu      sync.Mutex
	labels  []compiledLabel
	loaded  time.Time
	windows map[string]bool
}

func (s *Server) compiledLabels(ctx context.Context) []compiledLabel {
	s.labelsMu.Lock()
	defer s.labelsMu.Unlock()
	if time.Since(s.labelsAt) < time.Minute && s.labels != nil {
		return s.labels
	}
	list, err := s.store.ListIntegrityLabels(ctx)
	if err != nil {
		s.logger.Warn("load integrity labels", "error", err)
		return s.labels
	}
	out := make([]compiledLabel, 0, len(list))
	for _, l := range list {
		if !l.Enabled {
			continue
		}
		c := compiledLabel{IntegrityLabel: l}
		if err := json.Unmarshal(l.Criteria, &c.crit); err != nil {
			continue
		}
		if len(c.crit.GroupIDs) > 0 {
			m, err := s.agentsInGroups(ctx, c.crit.GroupIDs)
			if err != nil {
				continue
			}
			if m == nil {
				m = map[string]bool{}
			}
			c.members = m
		}
		out = append(out, c)
	}
	s.labels, s.labelsAt = out, time.Now()
	return out
}

func (s *Server) invalidateLabels() {
	s.labelsMu.Lock()
	s.labels, s.labelsAt = nil, time.Time{}
	s.labelsMu.Unlock()
}

// invalidateWatchRoots drops the cached watch sets. Saving a watchlist or
// a monitor must call this: the agent applies the new set and republishes
// its snapshot within seconds, and a diff that read a stale set would
// baseline the wrong roots — reporting the files a new watchlist covers
// as "added", then suppressing the first real change under them.
func (s *Server) invalidateWatchRoots() {
	s.watchRootsMu.Lock()
	s.watchRoots, s.watchRootsAt = nil, time.Time{}
	s.watchRootsMu.Unlock()
}

// seedIntegrityLabels writes the default labels on a fresh install: the
// change every fleet sees that is not change anyone configured. They are
// ordinary labels afterwards — edit or delete them.
//
// Windows rewrites a built-in scheduled task's definition file every time
// the task runs, so a quiet domain controller reports a thousand modified
// files a week from tasks nobody touched. Measured on this fleet before
// the label existed: 1,177 and 1,160 on two DCs over seven days, 360 of
// them one task. Left unlabelled it buries every real finding.
func (s *Server) seedIntegrityLabels(ctx context.Context) {
	existing, err := s.store.ListIntegrityLabels(ctx)
	if err != nil || len(existing) > 0 {
		return
	}
	crit, _ := json.Marshal(labelCriteria{
		PathPrefix: `C:\Windows\System32\Tasks\Microsoft\Windows\`,
		Kinds:      []string{"modified"},
	})
	l := store.IntegrityLabel{
		ID: idgen.New("lbl-"), Name: "Windows scheduled-task housekeeping", Expected: true,
		Criteria: crit, Priority: 10, Enabled: true, CreatedBy: "mustra",
	}
	if err := s.store.UpsertIntegrityLabel(ctx, l); err != nil {
		s.logger.Warn("seed integrity label failed", "error", err)
		return
	}
	// Apply it to what is already recorded. A label classifies a kind of
	// change, so change of that kind recorded yesterday is no more worth
	// investigating than the same change tomorrow — and a fleet that
	// already has thousands of these would otherwise start with an
	// "awaiting investigation" count that means nothing.
	n, err := s.store.ApplyExpectedLabelToPastChanges(ctx, `C:\Windows\System32\Tasks\Microsoft\Windows\`, "modified", l.Name)
	if err != nil {
		s.logger.Warn("labelling past changes failed", "error", err)
	}
	s.logger.Info("seeded default integrity labels", "count", 1, "past_changes_labelled", n)
}

// labelChange returns the labels that match, and whether any of them
// marks the change expected (with the label's name as the reason).
func (s *Server) labelChange(ctx context.Context, agentID, path, kind string, at time.Time) (labels []string, expected bool, because string) {
	for _, l := range s.compiledLabels(ctx) {
		if !s.labelMatches(ctx, l, agentID, path, kind, at) {
			continue
		}
		labels = append(labels, l.Name)
		if l.Expected && !expected {
			expected, because = true, "label: "+l.Name
		}
	}
	return labels, expected, because
}

func (s *Server) labelMatches(ctx context.Context, l compiledLabel, agentID, path, kind string, at time.Time) bool {
	c := l.crit
	lp := strings.ToLower(path)
	if c.PathPrefix != "" && !strings.HasPrefix(lp, strings.ToLower(c.PathPrefix)) {
		return false
	}
	if c.PathSuffix != "" && !strings.HasSuffix(lp, strings.ToLower(c.PathSuffix)) {
		return false
	}
	if c.PathContains != "" && !strings.Contains(lp, strings.ToLower(c.PathContains)) {
		return false
	}
	if len(c.Kinds) > 0 {
		ok := false
		for _, k := range c.Kinds {
			if strings.EqualFold(k, kind) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if l.members != nil && !l.members[agentID] {
		return false
	}
	if c.Process != "" || c.User != "" {
		return false // no agent attributes a change to a process or user yet
	}
	if len(c.Weekdays) > 0 || c.Start != "" || c.End != "" {
		loc := time.UTC
		if c.Timezone != "" {
			if z, err := time.LoadLocation(c.Timezone); err == nil {
				loc = z
			}
		}
		t := at.In(loc)
		if len(c.Weekdays) > 0 {
			ok := false
			for _, d := range c.Weekdays {
				if int(t.Weekday()) == d {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
		if c.Start != "" && c.End != "" {
			mins := t.Hour()*60 + t.Minute()
			sm, em := hhmm(c.Start), hhmm(c.End)
			if sm >= 0 && em >= 0 {
				if sm <= em {
					if mins < sm || mins >= em {
						return false
					}
				} else if mins < sm && mins >= em { // crosses midnight
					return false
				}
			}
		}
	}
	if c.DuringMaintenance {
		v := s.windowCheck(ctx, agentID, "software", at)
		// windowCheck says "allowed" both when a window is open and when
		// no window covers the endpoint; the rule wants the former only.
		if !v.Allowed || !s.hasWindow(ctx, agentID) {
			return false
		}
	}
	return true
}

func hhmm(v string) int {
	var h, m int
	if _, err := fmt.Sscanf(v, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return -1
	}
	return h*60 + m
}

// hasWindow reports whether any maintenance window covers the endpoint.
func (s *Server) hasWindow(ctx context.Context, agentID string) bool {
	if err := s.refreshWindowGate(ctx); err != nil {
		return false
	}
	g := &s.windows
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, w := range g.windows {
		if !w.Enabled {
			continue
		}
		m, ok := g.members[w.ID]
		if ok && m == nil { // nil = every endpoint
			return true
		}
		if m[agentID] {
			return true
		}
	}
	return false
}

// --- new-root baselining ---------------------------------------------------

// watchRootsFor returns the roots (paths and registry keys) the monitors
// currently give one endpoint, with the set's revision. Cached briefly:
// every integrity snapshot asks.
func (s *Server) watchRootsFor(ctx context.Context, agentID string) (string, []string) {
	s.watchRootsMu.Lock()
	if time.Since(s.watchRootsAt) > time.Minute || s.watchRoots == nil {
		s.watchRootsMu.Unlock()
		agents, err := s.store.ListAgents(ctx, s.staleAfter())
		if err != nil {
			return "", nil
		}
		sets, err := s.effectiveWatchSets(ctx, agents)
		if err != nil {
			return "", nil
		}
		s.watchRootsMu.Lock()
		s.watchRoots, s.watchRootsAt = sets, time.Now()
	}
	ew := s.watchRoots[agentID]
	s.watchRootsMu.Unlock()
	if ew == nil {
		return "", nil
	}
	roots := append(append([]string{}, ew.Config.Paths...), ew.Config.RegistryKeys...)
	return ew.Config.Revision, roots
}

// changedWatchRoots compares the endpoint's current roots with what its
// last diffed snapshot covered and returns the roots that are new and the
// roots that are gone. Files under a new root appearing in this snapshot
// are baseline, not "added"; files under a dropped root vanishing from it
// are the watch ending, not "removed". It records the current roots for
// next time.
func (s *Server) changedWatchRoots(ctx context.Context, agentID string) (fresh, dropped []string) {
	rev, roots := s.watchRootsFor(ctx, agentID)
	prevRev, prevRoots, err := s.store.GetWatchBaseline(ctx, agentID)
	if err != nil {
		return nil, nil
	}
	if prevRev == rev && prevRoots != nil {
		return nil, nil
	}
	had := map[string]bool{}
	for _, r := range prevRoots {
		had[r] = true
	}
	have := map[string]bool{}
	for _, r := range roots {
		have[r] = true
		if !had[r] {
			fresh = append(fresh, r)
		}
	}
	for _, r := range prevRoots {
		if !have[r] {
			dropped = append(dropped, r)
		}
	}
	if err := s.store.SetWatchBaseline(ctx, agentID, rev, roots); err != nil {
		s.logger.Warn("record watch baseline", "agent", agentID, "error", err)
	}
	return fresh, dropped
}

// underAnyRoot says whether a path sits under one of the roots.
func underAnyRoot(path string, roots []string) bool {
	lp := strings.ToLower(path)
	for _, r := range roots {
		lr := strings.ToLower(strings.TrimRight(r, `/\`))
		if lp == lr || strings.HasPrefix(lp, lr+"/") || strings.HasPrefix(lp, lr+`\`) {
			return true
		}
	}
	return false
}

// --- status ---------------------------------------------------------------

type watchStatusRow struct {
	AgentID       string   `json:"agent_id"`
	Hostname      string   `json:"hostname"`
	OS            string   `json:"os"`
	Online        bool     `json:"online"`
	AgentVersion  string   `json:"agent_version"`
	Monitors      []string `json:"monitors"`
	Paths         int      `json:"paths"`
	RegistryKeys  int      `json:"registry_keys"`
	WantRevision  string   `json:"want_revision"`
	HaveRevision  string   `json:"have_revision"`
	Applied       bool     `json:"applied"`
	NeedsUpgrade  bool     `json:"needs_upgrade"`
	FollowSymlink bool     `json:"follow_symlinks"`
}

func (s *Server) watchStatus(ctx context.Context) ([]watchStatusRow, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	sets, err := s.effectiveWatchSets(ctx, agents)
	if err != nil {
		return nil, err
	}
	out := make([]watchStatusRow, 0, len(agents))
	for _, a := range agents {
		ew := sets[a.AgentID]
		row := watchStatusRow{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Online: a.Online, AgentVersion: a.AgentVersion, HaveRevision: a.WatchRevision, Monitors: []string{}}
		if ew != nil {
			row.Monitors = ew.Monitors
			row.Paths = len(ew.Config.Paths)
			row.RegistryKeys = len(ew.Config.RegistryKeys)
			row.WantRevision = ew.Config.Revision
			row.FollowSymlink = ew.Config.FollowSymlinks
		}
		row.Applied = row.WantRevision == row.HaveRevision
		row.NeedsUpgrade = row.WantRevision != "" && !row.Applied && !versionIsNewer(a.AgentVersion, "0.48.99")
		out = append(out, row)
	}
	return out, nil
}
