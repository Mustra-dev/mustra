package server

// Asset lifecycle: each endpoint's make, model and serial (the hardware
// sensor), with what the operator records about it as asset attributes —
// purchase date, warranty end, owner, state, location, cost — and its age
// and warranty days left. A warranty about to end notifies once per end
// date.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const warrantyWarnDays = 30

var virtualMachineVendor = regexp.MustCompile(`(?i)qemu|vmware|virtualbox|innotek|xen|bochs|parallels|virtual machine`)

// lifecycleAttributes is the preset the Lifecycle view reads.
var lifecycleAttributes = []store.AssetAttribute{
	{Name: "purchase_date", Label: "Purchase date", Kind: "date", Description: "When the machine was bought; its age is counted from here (else from its firmware date)."},
	{Name: "warranty_end", Label: "Warranty ends", Kind: "date", Description: "The last day of the manufacturer's (or extended) warranty. Mustra warns 30 days before."},
	{Name: "owner", Label: "Owner", Kind: "text", Description: "Who the machine belongs to or is assigned to."},
	{Name: "lifecycle_state", Label: "Lifecycle state", Kind: "select", Options: []string{"in use", "spare", "in repair", "retired"}, Description: "Where the machine is in its life."},
	{Name: "location", Label: "Location", Kind: "text", Description: "Where it is: site, room, rack."},
	{Name: "cost", Label: "Cost", Kind: "number", Description: "What it cost, for replacement planning."},
}

// lifecyclePresetResponse is what POST
// /api/asset-attributes/lifecycle-preset answers.
type lifecyclePresetResponse struct {
	Created []string `json:"created"`
}

// POST /api/asset-attributes/lifecycle-preset: create whichever of the
// lifecycle attributes do not exist yet.
func (s *Server) handleLifecyclePreset(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.ListAssetAttributes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	have := map[string]bool{}
	for _, a := range existing {
		have[a.Name] = true
	}
	who := auth.CurrentUser(r.Context()).Username
	created := []string{}
	for _, a := range lifecycleAttributes {
		if have[a.Name] {
			continue
		}
		a.ID, a.CreatedBy = idgen.New("attr-"), who
		if err := s.store.UpsertAssetAttribute(r.Context(), a); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		created = append(created, a.Name)
	}
	s.audit(r.Context(), auditEvent{Action: "assets.lifecycle_preset", Actor: who, Target: "asset attributes", Severity: "notice",
		Detail: map[string]any{"created": created}})
	writeJSONResponse(w, lifecyclePresetResponse{Created: created})
}

type lifecycleRow struct {
	AgentID      string   `json:"agent_id"`
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Manufacturer string   `json:"manufacturer,omitempty"`
	Model        string   `json:"model,omitempty"`
	Serial       string   `json:"serial,omitempty"`
	Chassis      string   `json:"chassis,omitempty"`
	Physical     bool     `json:"physical"`
	BIOSDate     string   `json:"bios_date,omitempty"`
	PurchaseDate string   `json:"purchase_date,omitempty"`
	AgeYears     *float64 `json:"age_years,omitempty"`
	AgeFrom      string   `json:"age_from,omitempty"` // purchase, firmware
	WarrantyEnd  string   `json:"warranty_end,omitempty"`
	WarrantyDays *int     `json:"warranty_days,omitempty"`
	Owner        string   `json:"owner,omitempty"`
	State        string   `json:"state,omitempty"`
	Location     string   `json:"location,omitempty"`
	Cost         string   `json:"cost,omitempty"`
	Managed      bool     `json:"managed"`
}

func (s *Server) lifecycleRows(ctx context.Context, now time.Time) ([]lifecycleRow, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	attrs, err := s.store.AttributeValuesByAgent(ctx)
	if err != nil {
		return nil, err
	}
	hw := map[string]proto.HardwareInfo{}
	if rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorHardware)); err == nil {
		for _, row := range rows {
			var h []proto.HardwareInfo
			if json.Unmarshal(row.Data, &h) == nil && len(h) > 0 {
				hw[row.AgentID] = h[0]
			}
		}
	}
	day := func(v string) (time.Time, bool) {
		t, err := time.Parse("2006-01-02", strings.TrimSpace(v))
		return t, err == nil
	}
	out := make([]lifecycleRow, 0, len(agents))
	for _, a := range agents {
		h, v := hw[a.AgentID], attrs[a.AgentID]
		r := lifecycleRow{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Manufacturer: h.Manufacturer, Model: h.Model, Serial: h.Serial,
			Chassis: h.Chassis, BIOSDate: h.BIOSDate, PurchaseDate: v["purchase_date"], WarrantyEnd: v["warranty_end"], Owner: v["owner"],
			State: v["lifecycle_state"], Location: v["location"], Cost: v["cost"], Managed: a.Managed}
		// The vendor check covers agents older than 0.57.31, which left a
		// Windows VM's chassis blank.
		if h.Chassis == "" && virtualMachineVendor.MatchString(h.Manufacturer+" "+h.Model) {
			r.Chassis = "virtual"
		}
		r.Physical = r.Chassis != "" && r.Chassis != "virtual" && r.Chassis != "container"
		if t, ok := day(r.PurchaseDate); ok {
			age := math.Round(now.Sub(t).Hours()/24/365.25*10) / 10
			r.AgeYears, r.AgeFrom = &age, "purchase"
		} else if t, ok := day(r.BIOSDate); ok && r.Physical {
			age := math.Round(now.Sub(t).Hours()/24/365.25*10) / 10
			r.AgeYears, r.AgeFrom = &age, "firmware"
		}
		if t, ok := day(r.WarrantyEnd); ok {
			d := int(math.Floor(t.Sub(now.Truncate(24*time.Hour)).Hours() / 24))
			r.WarrantyDays = &d
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Physical != out[j].Physical {
			return out[i].Physical
		}
		return strings.ToLower(out[i].Hostname) < strings.ToLower(out[j].Hostname)
	})
	return out, nil
}

// lifecycleResponse is what GET /api/lifecycle answers.
type lifecycleResponse struct {
	Endpoints     []lifecycleRow `json:"endpoints"`
	PresetMissing int            `json:"preset_missing"`
	WarnDays      int            `json:"warn_days"`
}

// GET /api/lifecycle
func (s *Server) handleLifecycle(w http.ResponseWriter, r *http.Request) {
	rows, err := s.lifecycleRows(r.Context(), time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	attrs, _ := s.store.ListAssetAttributes(r.Context())
	have := map[string]bool{}
	for _, a := range attrs {
		have[a.Name] = true
	}
	missing := 0
	for _, a := range lifecycleAttributes {
		if !have[a.Name] {
			missing++
		}
	}
	writeJSONResponse(w, lifecycleResponse{Endpoints: rows, PresetMissing: missing, WarnDays: warrantyWarnDays})
}

// GET /api/lifecycle.csv
func (s *Server) handleLifecycleCSV(w http.ResponseWriter, r *http.Request) {
	rows, err := s.lifecycleRows(r.Context(), time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="lifecycle-`+time.Now().UTC().Format("2006-01-02")+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"endpoint", "os", "manufacturer", "model", "serial", "chassis", "firmware_date", "purchase_date", "age_years", "warranty_end", "warranty_days_left", "owner", "state", "location", "cost"})
	f := func(p *float64) string {
		if p == nil {
			return ""
		}
		return strconv.FormatFloat(*p, 'f', 1, 64)
	}
	for _, x := range rows {
		days := ""
		if x.WarrantyDays != nil {
			days = strconv.Itoa(*x.WarrantyDays)
		}
		_ = cw.Write([]string{x.Hostname, x.OS, csvSafe(x.Manufacturer), csvSafe(x.Model), csvSafe(x.Serial), x.Chassis, x.BIOSDate, x.PurchaseDate,
			f(x.AgeYears), x.WarrantyEnd, days, csvSafe(x.Owner), x.State, csvSafe(x.Location), x.Cost})
	}
	cw.Flush()
}

func (s *Server) warrantyLoop(ctx context.Context) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		s.checkWarranties(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) checkWarranties(ctx context.Context) {
	rows, err := s.lifecycleRows(ctx, time.Now())
	if err != nil {
		return
	}
	warned, err := s.store.WarrantyAlerted(ctx)
	if err != nil {
		return
	}
	for _, r := range rows {
		if r.WarrantyDays == nil || *r.WarrantyDays > warrantyWarnDays || *r.WarrantyDays < -1 || r.State == "retired" || warned[r.AgentID] == r.WarrantyEnd {
			continue
		}
		what := "ends in " + strconv.Itoa(*r.WarrantyDays) + " day(s)"
		if *r.WarrantyDays < 0 {
			what = "ended"
		}
		s.notify(ctx, "warning", "Lifecycle", "Warranty "+what+": "+r.Hostname,
			strings.Join(nonEmpty(r.Manufacturer+" "+r.Model, "serial "+r.Serial, "warranty ends "+r.WarrantyEnd), " · "), "/agents#lifecycle")
		_ = s.store.SetWarrantyAlerted(ctx, r.AgentID, r.WarrantyEnd)
	}
}
