package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/swinventory"
)

// Software Inventory & Usage: the installed-apps sensor normalised into
// products, graded by how often each one actually runs, priced when an
// operator tracks it, and removable where it sits unused.
//
// Usage comes from the process starts the fleet already reports (Hunt's
// process timeline), rolled up per day because process_events is only kept
// for 48 hours, plus whatever the endpoint itself records (Windows
// Prefetch, Spotlight's last-used date) in the installed-apps snapshot.
// Nothing new runs on the endpoint for this.

const (
	swinventoryInterval   = 15 * time.Minute
	swinventoryUsageKeep  = 100 * 24 * time.Hour
	swinventoryMaxWindow  = 90
	swinventoryCacheTTL   = 60 * time.Second
	swinventoryDefaultWin = 30
)

// swinventoryLoop keeps the presence table and the daily usage rollup
// current.
func (s *Server) swinventoryLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(60 * time.Second):
	}
	ticker := time.NewTicker(swinventoryInterval)
	defer ticker.Stop()
	for {
		s.swinventoryRollup(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// swinventoryRollup recomputes yesterday and today from process_events
// (both are always inside the 48-hour retention), prunes old days, and
// refreshes presence from every endpoint's latest installed-apps snapshot.
func (s *Server) swinventoryRollup(ctx context.Context) {
	start := time.Now()
	y := start.UTC().Truncate(24 * time.Hour).Add(-24 * time.Hour)
	if n, err := s.store.RollupUsageDays(ctx, y); err != nil {
		s.logger.Warn("software usage rollup failed", "error", err)
	} else if n > 0 {
		s.logger.Debug("software usage rolled up", "rows", n)
	}
	if _, err := s.store.PruneUsageDays(ctx, swinventoryUsageKeep); err != nil {
		s.logger.Warn("software usage prune failed", "error", err)
	}
	snaps, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorInstalledApps))
	if err != nil {
		s.logger.Warn("software presence rollup failed", "error", err)
		return
	}
	agents := 0
	for _, snap := range snaps {
		var apps []proto.InstalledApp
		if err := json.Unmarshal(snap.Data, &apps); err != nil || len(apps) == 0 {
			continue
		}
		rows := presenceRows(apps, snap.OS)
		if err := s.store.UpsertPresence(ctx, snap.AgentID, start, rows); err != nil {
			s.logger.Warn("software presence upsert failed", "agent", snap.AgentID, "error", err)
			continue
		}
		agents++
	}
	s.swinvMu.Lock()
	s.swinvCache = map[int]*swInventory{}
	s.swinvRolledAt = time.Now()
	s.swinvMu.Unlock()
	s.logger.Debug("software presence refreshed", "agents", agents, "took", time.Since(start).Round(time.Millisecond))
}

// presenceRows normalises one endpoint's snapshot, one row per product:
// two registry entries for the same product (32- and 64-bit, two
// versions) collapse into the one with the higher version, keeping any
// executable or date the other carried.
func presenceRows(apps []proto.InstalledApp, os string) []store.PresenceRow {
	byKey := map[string]*store.PresenceRow{}
	var order []string
	for _, a := range apps {
		if strings.TrimSpace(a.Name) == "" {
			continue
		}
		p := swinventory.Normalize(a.Name, a.Publisher, os)
		var used time.Time
		if a.LastUsed != "" {
			used, _ = time.Parse(time.RFC3339, a.LastUsed)
		}
		row := store.PresenceRow{ProductKey: p.Key, Name: p.Name, Vendor: p.Vendor, Version: a.Version, Executable: swinventory.ExeKey(a.Executable), InstallDate: a.InstallDate, LastUsedReported: used}
		if cur, ok := byKey[p.Key]; ok {
			if swinventory.CompareVersions(row.Version, cur.Version) > 0 {
				cur.Version = row.Version
			}
			if cur.Executable == "" {
				cur.Executable = row.Executable
			}
			if cur.InstallDate == "" || (row.InstallDate != "" && row.InstallDate < cur.InstallDate) {
				cur.InstallDate = row.InstallDate
			}
			if row.LastUsedReported.After(cur.LastUsedReported) {
				cur.LastUsedReported = row.LastUsedReported
			}
			if cur.Vendor == "" {
				cur.Vendor = row.Vendor
			}
			continue
		}
		byKey[p.Key] = &row
		order = append(order, p.Key)
	}
	out := make([]store.PresenceRow, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

// --- the inventory view ---------------------------------------------------

type swDevice struct {
	AgentID     string `json:"agent_id"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Online      bool   `json:"online"`
	Version     string `json:"version"`
	Executable  string `json:"executable,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
	FirstSeen   string `json:"first_seen"`
	LastUsed    string `json:"last_used,omitempty"`
	DaysUsed    int    `json:"days_used"`
	Launches    int64  `json:"launches"`
	Level       string `json:"usage"`
	Used        bool   `json:"used"`
	// lastUsedAt and firstSeenAt back the remove-unused decision.
	lastUsedAt  time.Time
	firstSeenAt time.Time
}

type swProduct struct {
	Key         string         `json:"key"`
	Name        string         `json:"name"`
	Vendor      string         `json:"vendor"`
	Component   bool           `json:"component"`
	Platforms   []string       `json:"platforms"`
	Versions    []string       `json:"versions"`
	Executables []string       `json:"executables"`
	Installed   int            `json:"installed"`
	Used        int            `json:"used"`
	Unused      int            `json:"unused"`
	Unknown     int            `json:"unknown"`
	Levels      map[string]int `json:"levels"`
	FirstSeen   string         `json:"first_seen"`
	LastUsed    string         `json:"last_used,omitempty"`
	Tracked     bool           `json:"tracked"`
	TrackedID   string         `json:"tracked_id,omitempty"`
	CostCents   int64          `json:"cost_per_seat_cents,omitempty"`
	Currency    string         `json:"currency,omitempty"`
	AnnualCents int64          `json:"est_annual_cents"`
	WasteCents  int64          `json:"est_waste_cents"`
	PackageID   string         `json:"package_id,omitempty"`
	InCatalog   bool           `json:"in_catalog"`
	devices     []swDevice
}

type swSummary struct {
	Products     int   `json:"products"`
	Applications int   `json:"applications"`
	Tracked      int   `json:"tracked"`
	Endpoints    int   `json:"endpoints"`
	UnusedSeats  int   `json:"unused_seats"`
	AnnualCents  int64 `json:"est_annual_cents"`
	WasteCents   int64 `json:"est_waste_cents"`
	WindowDays   int   `json:"window_days"`
	HistoryDays  int   `json:"history_days"`
	// RolledUpAt is null until the first rollup, a minute after the
	// server starts.
	RolledUpAt *time.Time `json:"rolled_up_at"`
}

type swInventory struct {
	products []*swProduct
	byKey    map[string]*swProduct
	summary  swSummary
	builtAt  time.Time
}

func (s *Server) swinventory(ctx context.Context, windowDays int) (*swInventory, error) {
	if windowDays <= 0 {
		windowDays = swinventoryDefaultWin
	}
	if windowDays > swinventoryMaxWindow {
		windowDays = swinventoryMaxWindow
	}
	s.swinvMu.Lock()
	if s.swinvCache == nil {
		s.swinvCache = map[int]*swInventory{}
	}
	if inv := s.swinvCache[windowDays]; inv != nil && time.Since(inv.builtAt) < swinventoryCacheTTL {
		s.swinvMu.Unlock()
		return inv, nil
	}
	s.swinvMu.Unlock()

	inv, err := s.buildSwinventory(ctx, windowDays)
	if err != nil {
		return nil, err
	}
	s.swinvMu.Lock()
	s.swinvCache[windowDays] = inv
	s.swinvMu.Unlock()
	return inv, nil
}

func (s *Server) buildSwinventory(ctx context.Context, windowDays int) (*swInventory, error) {
	presence, err := s.store.ListPresence(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	usage, err := s.store.ListUsage(ctx, windowDays)
	if err != nil {
		return nil, err
	}
	tracked, err := s.store.ListTrackedProducts(ctx)
	if err != nil {
		return nil, err
	}
	pkgs, _ := s.store.ListSoftwarePackages(ctx)
	catalog := map[string]string{}
	for _, p := range pkgs {
		catalog[swinventory.Key(p.Name)] = p.ID
		if p.Detect.AppName != "" {
			catalog[swinventory.Key(p.Detect.AppName)] = p.ID
		}
	}
	trackedByKey := map[string]store.TrackedProduct{}
	for _, t := range tracked {
		trackedByKey[t.ProductKey] = t
	}
	// seen is every process name that started anywhere in the fleet inside
	// the window. A dpkg package whose name never shows up as a process
	// ("coreutils", "bsdutils") is not something anyone launches by that
	// name, so its usage is unknown rather than "unused on 37 endpoints".
	use := map[string]map[string]store.UsageRow{}
	seen := map[string]bool{}
	for _, u := range usage {
		m := use[u.AgentID]
		if m == nil {
			m = map[string]store.UsageRow{}
			use[u.AgentID] = m
		}
		m[u.Exe] = u
		seen[u.Exe] = true
	}
	// Grade against the history that exists: with three days of rollup, a
	// 30-day window would call everything "light" for a month. The window
	// the caller asked for is still the upper bound.
	historyDays, err := s.store.UsageHistoryDays(ctx)
	if err != nil {
		return nil, err
	}
	gradeWindow := windowDays
	if historyDays > 0 && historyDays < gradeWindow {
		gradeWindow = historyDays
	}

	now := time.Now()
	inv := &swInventory{byKey: map[string]*swProduct{}, builtAt: now}
	endpoints := map[string]bool{}
	for _, r := range presence {
		endpoints[r.AgentID] = true
		prod := inv.byKey[r.ProductKey]
		if prod == nil {
			prod = &swProduct{Key: r.ProductKey, Name: r.Name, Vendor: r.Vendor, Levels: map[string]int{}, Component: swinventory.IsComponent(r.Name, r.OS)}
			if t, ok := trackedByKey[r.ProductKey]; ok {
				prod.Tracked, prod.TrackedID, prod.CostCents, prod.Currency, prod.PackageID = true, t.ID, t.CostPerSeatCents, t.Currency, t.PackageID
				if t.Name != "" {
					prod.Name = t.Name
				}
				if t.Vendor != "" {
					prod.Vendor = t.Vendor
				}
			}
			if prod.PackageID == "" {
				prod.PackageID = catalog[r.ProductKey]
			}
			prod.InCatalog = prod.PackageID != ""
			inv.byKey[r.ProductKey] = prod
			inv.products = append(inv.products, prod)
		}
		if prod.Vendor == "" {
			prod.Vendor = r.Vendor
		}
		// A Windows/macOS display name beats a dpkg package name for the
		// same product ("Google Chrome" over "google-chrome-stable").
		if r.OS != "linux" && !prod.Tracked && prod.Name != r.Name && strings.Contains(r.Name, " ") {
			prod.Name = r.Name
		}
		addUnique(&prod.Platforms, r.OS)
		if r.Version != "" && len(prod.Versions) < 12 {
			addUnique(&prod.Versions, r.Version)
		}

		var extra []string
		if t, ok := trackedByKey[r.ProductKey]; ok {
			extra = t.Executables
		}
		p := swinventory.Product{Name: r.Name, Vendor: r.Vendor, Key: r.ProductKey}
		exes := swinventory.Executables(p, r.Executable, extra)
		for _, e := range exes {
			if len(prod.Executables) < 8 {
				addUnique(&prod.Executables, e)
			}
		}
		trackable := !prod.Component && (r.Executable != "" || len(extra) > 0 || swinventory.HasKnownExecutables(r.ProductKey))
		if !trackable && !prod.Component {
			for _, e := range exes {
				if seen[e] {
					trackable = true
					break
				}
			}
		}

		d := swDevice{AgentID: r.AgentID, Hostname: r.Hostname, OS: r.OS, Online: r.Online, Version: r.Version, Executable: r.Executable, InstallDate: r.InstallDate, FirstSeen: r.FirstSeen.UTC().Format(time.RFC3339), firstSeenAt: r.FirstSeen, lastUsedAt: r.LastUsedReported}
		if m := use[r.AgentID]; m != nil {
			for _, e := range exes {
				u, ok := m[e]
				if !ok {
					continue
				}
				if u.DaysUsed > d.DaysUsed {
					d.DaysUsed = u.DaysUsed
				}
				d.Launches += u.Launches
				if u.LastDay.After(d.lastUsedAt) {
					d.lastUsedAt = u.LastDay
				}
			}
		}
		d.Level = swinventory.UsageLevel(d.DaysUsed, gradeWindow, d.lastUsedAt, now, trackable)
		d.Used = d.Level == swinventory.UsageHeavy || d.Level == swinventory.UsageModerate || d.Level == swinventory.UsageLight
		if !d.lastUsedAt.IsZero() {
			d.LastUsed = d.lastUsedAt.UTC().Format(time.RFC3339)
		}
		prod.devices = append(prod.devices, d)
		prod.Installed++
		prod.Levels[d.Level]++
		switch d.Level {
		case swinventory.UsageUnused:
			prod.Unused++
		case swinventory.UsageUnknown:
			prod.Unknown++
		default:
			prod.Used++
		}
		if prod.FirstSeen == "" || d.FirstSeen < prod.FirstSeen {
			prod.FirstSeen = d.FirstSeen
		}
		if d.LastUsed > prod.LastUsed {
			prod.LastUsed = d.LastUsed
		}
	}
	for _, p := range inv.products {
		if p.Tracked {
			p.AnnualCents = p.CostCents * int64(p.Installed)
			p.WasteCents = p.CostCents * int64(p.Unused)
			inv.summary.AnnualCents += p.AnnualCents
			inv.summary.WasteCents += p.WasteCents
			inv.summary.Tracked++
		}
		if !p.Component {
			inv.summary.Applications++
			inv.summary.UnusedSeats += p.Unused
		}
		sort.Strings(p.Platforms)
		if p.Platforms == nil {
			p.Platforms = []string{}
		}
		if p.Versions == nil {
			p.Versions = []string{}
		}
		if p.Executables == nil {
			p.Executables = []string{}
		}
	}
	sort.Slice(inv.products, func(i, j int) bool {
		a, b := inv.products[i], inv.products[j]
		if a.Installed != b.Installed {
			return a.Installed > b.Installed
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	inv.summary.Products = len(inv.products)
	inv.summary.Endpoints = len(endpoints)
	inv.summary.WindowDays = windowDays
	inv.summary.HistoryDays = historyDays
	s.swinvMu.Lock()
	if !s.swinvRolledAt.IsZero() {
		at := s.swinvRolledAt
		inv.summary.RolledUpAt = &at
	}
	s.swinvMu.Unlock()
	return inv, nil
}

func addUnique(list *[]string, v string) {
	if v == "" {
		return
	}
	for _, x := range *list {
		if x == v {
			return
		}
	}
	*list = append(*list, v)
}

// --- HTTP ----------------------------------------------------------------

func windowDaysParam(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if n <= 0 {
		return swinventoryDefaultWin
	}
	return n
}

// softwareInventoryResponse is what GET /api/software-inventory answers.
type softwareInventoryResponse struct {
	Products []*swProduct `json:"products"`
	Summary  swSummary    `json:"summary"`
}

// GET /api/software-inventory?days=30&q=&filter=all|apps|tracked|unused&format=csv
func (s *Server) handleSoftwareInventory(w http.ResponseWriter, r *http.Request) {
	inv, err := s.swinventory(r.Context(), windowDaysParam(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filter := r.URL.Query().Get("filter")
	out := make([]*swProduct, 0, len(inv.products))
	for _, p := range inv.products {
		switch filter {
		case "apps":
			if p.Component {
				continue
			}
		case "tracked":
			if !p.Tracked {
				continue
			}
		case "unused":
			if p.Unused == 0 {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(p.Name), q) && !strings.Contains(strings.ToLower(p.Vendor), q) && !strings.Contains(p.Key, q) {
			continue
		}
		out = append(out, p)
	}
	if r.URL.Query().Get("format") == "csv" {
		var buf bytes.Buffer
		cw := newSafeCSVWriter(&buf)
		_ = cw.Write([]string{"product", "vendor", "component", "platforms", "versions", "installed", "used", "unused", "unknown", "heavy", "moderate", "light", "first_seen", "last_used", "tracked", "cost_per_seat", "est_annual_cost", "est_waste"})
		for _, p := range out {
			_ = cw.Write([]string{p.Name, p.Vendor, strconv.FormatBool(p.Component), strings.Join(p.Platforms, " "), strings.Join(p.Versions, " "),
				strconv.Itoa(p.Installed), strconv.Itoa(p.Used), strconv.Itoa(p.Unused), strconv.Itoa(p.Unknown),
				strconv.Itoa(p.Levels[swinventory.UsageHeavy]), strconv.Itoa(p.Levels[swinventory.UsageModerate]), strconv.Itoa(p.Levels[swinventory.UsageLight]),
				p.FirstSeen, p.LastUsed, strconv.FormatBool(p.Tracked), cents(p.CostCents), cents(p.AnnualCents), cents(p.WasteCents)})
		}
		cw.Flush()
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="software-inventory.csv"`)
		_, _ = w.Write(buf.Bytes())
		return
	}
	writeJSONResponse(w, softwareInventoryResponse{Products: out, Summary: inv.summary})
}

func cents(c int64) string {
	if c == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%02d", c/100, c%100)
}

// softwareInventoryProductResponse is what GET
// /api/software-inventory/product/{key} answers.
type softwareInventoryProductResponse struct {
	Devices    []swDevice            `json:"devices"`
	History    []store.UsageDayCount `json:"history"`
	Product    *swProduct            `json:"product"`
	Tracked    *store.TrackedProduct `json:"tracked"`
	WindowDays int                   `json:"window_days"`
}

// GET /api/software-inventory/product/{key}?days=30
func (s *Server) handleSoftwareInventoryProduct(w http.ResponseWriter, r *http.Request) {
	days := windowDaysParam(r)
	inv, err := s.swinventory(r.Context(), days)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p := inv.byKey[r.PathValue("key")]
	if p == nil {
		http.Error(w, "no such product", http.StatusNotFound)
		return
	}
	history, err := s.store.UsageHistory(r.Context(), p.Executables, r.URL.Query().Get("agent"), days)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	devices := append([]swDevice(nil), p.devices...)
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].LastUsed != devices[j].LastUsed {
			return devices[i].LastUsed > devices[j].LastUsed
		}
		return devices[i].Hostname < devices[j].Hostname
	})
	var tracked *store.TrackedProduct
	if p.Tracked {
		tracked, _ = s.store.GetTrackedProduct(r.Context(), p.TrackedID)
	}
	writeJSONResponse(w, softwareInventoryProductResponse{Product: p, Devices: devices, History: history, Tracked: tracked, WindowDays: days})
}

// softwareInventoryRefreshResponse is what POST
// /api/software-inventory/refresh answers.
type softwareInventoryRefreshResponse struct {
	Summary swSummary `json:"summary"`
}

// POST /api/software-inventory/refresh
func (s *Server) handleSoftwareInventoryRefresh(w http.ResponseWriter, r *http.Request) {
	s.swinventoryRollup(r.Context())
	inv, err := s.swinventory(r.Context(), swinventoryDefaultWin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, softwareInventoryRefreshResponse{Summary: inv.summary})
}

// --- tracked products -----------------------------------------------------

// listTrackedProductsResponse is what GET /api/tracked-products answers.
type listTrackedProductsResponse struct {
	Tracked []store.TrackedProduct `json:"tracked"`
}

func (s *Server) handleListTrackedProducts(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListTrackedProducts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listTrackedProductsResponse{Tracked: list})
}

func (s *Server) handleUpsertTrackedProduct(w http.ResponseWriter, r *http.Request) {
	var in store.TrackedProduct
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.ProductKey = strings.TrimSpace(in.ProductKey)
	if in.ProductKey == "" && in.Name != "" {
		in.ProductKey = swinventory.Key(in.Name)
	}
	if in.Name == "" && in.ProductKey != "" {
		in.Name = in.ProductKey
	}
	if in.ProductKey == "" {
		http.Error(w, "product_key or name is required", http.StatusBadRequest)
		return
	}
	if in.CostPerSeatCents < 0 {
		http.Error(w, "cost_per_seat_cents cannot be negative", http.StatusBadRequest)
		return
	}
	if in.Currency == "" {
		in.Currency = "USD"
	}
	exes := make([]string, 0, len(in.Executables))
	for _, e := range in.Executables {
		if k := swinventory.ExeKey(e); k != "" {
			exes = append(exes, k)
		}
	}
	in.Executables = exes
	if in.PackageID != "" {
		pkg, err := s.store.GetSoftwarePackage(r.Context(), in.PackageID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if pkg == nil {
			http.Error(w, "no such package", http.StatusBadRequest)
			return
		}
	}
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetTrackedProduct(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such tracked product", http.StatusNotFound)
			return
		}
		in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		// Tracking the same product twice edits the existing row.
		if existing, _ := s.store.GetTrackedProduct(r.Context(), in.ProductKey); existing != nil {
			in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
		} else {
			in.ID = idgen.New("trk-")
			in.CreatedBy = auth.CurrentUser(r.Context()).Username
		}
	}
	if err := s.store.UpsertTrackedProduct(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateSwinventory()
	s.audit(r.Context(), auditEvent{Action: "software.track", Actor: auth.CurrentUser(r.Context()).Username, Target: in.Name, Severity: "info",
		Detail: map[string]any{"id": in.ID, "cost_per_seat_cents": in.CostPerSeatCents, "package_id": in.PackageID}})
	// The save has happened: say so if the answer cannot show it, rather
	// than answer 200 with null.
	out, err := s.store.GetTrackedProduct(r.Context(), in.ID)
	if err == nil && out == nil {
		err = fmt.Errorf("it was deleted meanwhile")
	}
	if err != nil {
		http.Error(w, "saved, but could not read it back: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteTrackedProduct(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetTrackedProduct(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such tracked product", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteTrackedProduct(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateSwinventory()
	s.audit(r.Context(), auditEvent{Action: "software.untrack", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "info"})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) invalidateSwinventory() {
	s.swinvMu.Lock()
	s.swinvCache = map[int]*swInventory{}
	s.swinvMu.Unlock()
}

// --- remove unused ---------------------------------------------------------

// removeUnusedSoftwareRequest is the body of POST
// /api/software-inventory/product/{key}/remove-unused.
type removeUnusedSoftwareRequest struct {
	UnusedDays      int    `json:"unused_days"`
	PackageID       string `json:"package_id"`
	OverrideWindows bool   `json:"override_windows"`
	DryRun          bool   `json:"dry_run"`
}

// removeUnusedSoftwareResponse is what POST
// /api/software-inventory/product/{key}/remove-unused answers with
// dry_run: the endpoints it would remove the package from.
type removeUnusedSoftwareResponse struct {
	Devices    []swDevice `json:"devices"`
	Package    string     `json:"package"`
	PackageID  string     `json:"package_id"`
	UnusedDays int        `json:"unused_days"`
}

// POST /api/software-inventory/product/{key}/remove-unused
//
// Picks the endpoints where the product is installed and has not run for
// unused_days, then hands them to the ordinary software deployment as an
// explicit target list for the package's remove command. Everything a
// deployment enforces — applicability, maintenance windows, the override
// permission, audit, per-device results — applies unchanged, because it is
// the same handler.
func (s *Server) handleRemoveUnusedSoftware(w http.ResponseWriter, r *http.Request) {
	var req removeUnusedSoftwareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.UnusedDays <= 0 {
		req.UnusedDays = swinventoryDefaultWin
	}
	if req.UnusedDays > swinventoryMaxWindow {
		req.UnusedDays = swinventoryMaxWindow
	}
	inv, err := s.swinventory(r.Context(), req.UnusedDays)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p := inv.byKey[r.PathValue("key")]
	if p == nil {
		http.Error(w, "no such product", http.StatusNotFound)
		return
	}
	if p.Component {
		http.Error(w, p.Name+" is a library or runtime, not a program; its usage cannot be judged", http.StatusBadRequest)
		return
	}
	pkgID := req.PackageID
	if pkgID == "" {
		pkgID = p.PackageID
	}
	if pkgID == "" {
		http.Error(w, "no catalog package removes "+p.Name+" — adopt it under Installed Software (or link a package on the tracked product) first", http.StatusBadRequest)
		return
	}
	pkg, err := s.store.GetSoftwarePackage(r.Context(), pkgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pkg == nil {
		http.Error(w, "no such package", http.StatusNotFound)
		return
	}
	cutoff := time.Now().Add(-time.Duration(req.UnusedDays) * 24 * time.Hour)
	var ids []string
	var picked []swDevice
	for _, d := range p.devices {
		if d.Level != swinventory.UsageUnused {
			continue
		}
		// Never used at all: only counts once mustra has watched the
		// endpoint long enough to have seen a launch.
		if d.lastUsedAt.IsZero() && d.firstSeenAt.After(cutoff) {
			continue
		}
		if !d.lastUsedAt.IsZero() && d.lastUsedAt.After(cutoff) {
			continue
		}
		if !hasCommandFor(*pkg, d.OS, "remove") {
			continue
		}
		ids = append(ids, d.AgentID)
		picked = append(picked, d)
	}
	if picked == nil {
		picked = []swDevice{}
	}
	if req.DryRun {
		writeJSONResponse(w, removeUnusedSoftwareResponse{PackageID: pkg.ID, Package: pkg.Name, Devices: picked, UnusedDays: req.UnusedDays})
		return
	}
	if len(ids) == 0 {
		http.Error(w, "no endpoint has "+p.Name+" installed and unused for "+strconv.Itoa(req.UnusedDays)+" days", http.StatusBadRequest)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "software.remove_unused", Actor: auth.CurrentUser(r.Context()).Username, Target: p.Name, Severity: "notice",
		Detail: map[string]any{"package_id": pkg.ID, "unused_days": req.UnusedDays, "endpoints": len(ids)}})
	raw, _ := json.Marshal(softwareDeployRequest{PackageID: pkg.ID, Operation: "remove", AgentIDs: ids, OverrideWindows: req.OverrideWindows})
	r.Body = io.NopCloser(bytes.NewReader(raw))
	s.handleDeploySoftware(w, r)
}
