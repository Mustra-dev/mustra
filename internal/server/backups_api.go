package server

// Backup status: the backups sensor from Proxmox VE nodes, joined to the
// Mustra endpoints running inside the guests (by MAC, then by name), with
// each guest rated ok, overdue, never backed up, or not in a backup job.
// A covered guest that goes overdue notifies once, and again when it
// recovers.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/backupsrc"
)

const (
	settingBackupStaleHours = "backups.stale_hours"
	defaultBackupStaleHours = 36
)

type backupStatus struct {
	proto.BackupGuest
	HostAgentID string   `json:"host_agent_id"` // the Proxmox node's agent
	AgentID     string   `json:"agent_id,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	AgeHours    *float64 `json:"age_hours,omitempty"`
	State       string   `json:"state"` // ok, overdue, never, not_covered
	CollectedAt string   `json:"collected_at"`
}

func (b backupStatus) key() string { return b.Node + "/" + strconv.Itoa(b.VMID) }

func (s *Server) backupStaleHours(ctx context.Context) float64 {
	settings, _ := s.store.GetAllSettings(ctx)
	if h, err := strconv.ParseFloat(settings[settingBackupStaleHours], 64); err == nil && h > 0 {
		return h
	}
	return defaultBackupStaleHours
}

func (s *Server) backupStatuses(ctx context.Context) ([]backupStatus, error) {
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorBackups))
	if err != nil {
		return nil, err
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	// Endpoints by MAC (from the network sensor) and by short hostname.
	byMAC, byName := map[string]int{}, map[string]int{}
	if nets, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorNetwork)); err == nil {
		idx := map[string]int{}
		for i, a := range agents {
			idx[a.AgentID] = i
		}
		for _, n := range nets {
			var ifs []proto.NetworkInterfaceInfo
			if json.Unmarshal(n.Data, &ifs) != nil {
				continue
			}
			for _, nic := range ifs {
				if i, ok := idx[n.AgentID]; ok && nic.MAC != "" {
					byMAC[strings.ToLower(nic.MAC)] = i
				}
			}
		}
	}
	for i, a := range agents {
		short, _, _ := strings.Cut(strings.ToLower(a.Hostname), ".")
		byName[short] = i
	}
	stale := s.backupStaleHours(ctx)
	out := []backupStatus{}
	for _, row := range rows {
		var guests []proto.BackupGuest
		if json.Unmarshal(row.Data, &guests) != nil {
			continue
		}
		for _, g := range guests {
			b := backupStatus{BackupGuest: g, HostAgentID: row.AgentID, CollectedAt: row.CollectedAt.UTC().Format(time.RFC3339)}
			idx, found := -1, false
			for _, m := range g.MACs {
				if i, ok := byMAC[m]; ok {
					idx, found = i, true
					break
				}
			}
			if !found {
				if i, ok := byName[strings.ToLower(g.Name)]; ok {
					idx, found = i, true
				}
			}
			if found {
				b.AgentID, b.Hostname = agents[idx].AgentID, agents[idx].Hostname
			}
			b.State = rateBackup(g, stale, time.Now(), &b.AgeHours)
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		rank := map[string]int{"overdue": 0, "never": 1, "not_covered": 2, "ok": 3}
		if rank[out[i].State] != rank[out[j].State] {
			return rank[out[i].State] < rank[out[j].State]
		}
		return out[i].VMID < out[j].VMID
	})
	return out, nil
}

// rateBackup: a guest no job covers is "not_covered" whatever it holds
// (an old manual backup is not protection); a covered guest with nothing
// is "never"; otherwise its newest backup's age decides.
func rateBackup(g proto.BackupGuest, staleHours float64, now time.Time, age **float64) string {
	if g.LastBackup != "" {
		if t, err := time.Parse(time.RFC3339, g.LastBackup); err == nil {
			h := now.Sub(t).Hours()
			*age = &h
		}
	}
	switch {
	case !g.Covered:
		return "not_covered"
	case *age == nil:
		return "never"
	case **age > staleHours:
		return "overdue"
	}
	return "ok"
}

// backupsResponse is what GET /api/backup-status answers.
type backupsResponse struct {
	Counts     map[string]int `json:"counts"`
	Guests     []backupStatus `json:"guests"`
	StaleHours float64        `json:"stale_hours"`
	// Systems are the connected backup systems (Proxmox Backup Server,
	// Rubrik), each with what it protects.
	Systems []backupSystemStatus `json:"systems"`
}

// backupSystemStatus is one connected backup system as the Backup status
// page shows it.
type backupSystemStatus struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	PolledAt *time.Time        `json:"polled_at,omitempty"`
	OKAt     *time.Time        `json:"ok_at,omitempty"`
	Error    string            `json:"error,omitempty"`
	Stores   []backupsrc.Store `json:"stores"`
	// Jobs are the system's maintenance jobs (PBS verify, prune, garbage
	// collection, sync) and how each last ended.
	Jobs   []backupsrc.Job   `json:"jobs"`
	Items  []backupItemState `json:"items"`
	Counts map[string]int    `json:"counts"`
}

// backupItemState is one thing a backup system protects, rated like a
// guest and put to the endpoint it is.
type backupItemState struct {
	backupsrc.Item
	// GuestName is the Proxmox guest a PBS vm/ct group belongs to.
	GuestName string   `json:"guest_name,omitempty"`
	AgentID   string   `json:"agent_id,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	AgeHours  *float64 `json:"age_hours,omitempty"`
	// State is ok, overdue, never, not_covered (the system knows it but
	// nothing protects it), verify_failed, or orphaned (a PBS group for a
	// guest no Proxmox node has any more; never alerts).
	State string `json:"state"`
	// InProxmox is set when the same guest is already listed from the
	// Proxmox VE nodes, which alert for it.
	InProxmox bool `json:"in_proxmox,omitempty"`
}

// rateBackupItem rates one item the way rateBackup rates a guest, plus a
// failed verification, and the system's own compliance verdict.
func rateBackupItem(it backupsrc.Item, staleHours float64, now time.Time, age **float64) string {
	if it.LastBackup != nil {
		h := now.Sub(*it.LastBackup).Hours()
		*age = &h
	}
	comp := strings.ToLower(strings.ReplaceAll(it.Compliance, "_", ""))
	switch {
	case !it.Protected:
		return "not_covered"
	case *age == nil:
		return "never"
	case **age > staleHours, strings.Contains(comp, "outof"), strings.Contains(comp, "noncompliant"):
		return "overdue"
	case it.Verified == "failed":
		return "verify_failed"
	}
	return "ok"
}

// backupSystems reads every enabled source's newest result and puts each
// item to an endpoint: a PBS vm/ct group by its guest ID (through the
// Proxmox guests), anything else by host name.
func (s *Server) backupSystems(ctx context.Context, guests []backupStatus) ([]backupSystemStatus, error) {
	sources, err := s.store.ListBackupSources(ctx)
	if err != nil {
		return nil, err
	}
	out := []backupSystemStatus{}
	if len(sources) == 0 {
		return out, nil
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	byName := map[string]int{}
	for i, a := range agents {
		short, _, _ := strings.Cut(strings.ToLower(a.Hostname), ".")
		byName[short] = i
	}
	byVMID := map[int]backupStatus{}
	for _, g := range guests {
		byVMID[g.VMID] = g
	}
	stale, now := s.backupStaleHours(ctx), time.Now()
	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		sys := backupSystemStatus{ID: src.ID, Name: src.Name, Kind: src.Kind, PolledAt: src.LastPolled, OKAt: src.LastOK, Error: src.LastError,
			Stores: []backupsrc.Store{}, Jobs: []backupsrc.Job{}, Items: []backupItemState{}, Counts: map[string]int{}}
		var r backupsrc.Result
		if len(src.LastResult) > 0 && json.Unmarshal(src.LastResult, &r) == nil {
			if r.Stores != nil {
				sys.Stores = r.Stores
			}
			if r.Jobs != nil {
				sys.Jobs = r.Jobs
			}
			for _, it := range r.Items {
				st := backupItemState{Item: it}
				g, known := byVMID[it.VMID]
				switch {
				case it.VMID != 0 && known && pveType(g.Type) == it.Type:
					st.GuestName, st.AgentID, st.Hostname, st.InProxmox = g.Name, g.AgentID, g.Hostname, true
				case it.VMID == 0:
					if i, ok := byName[strings.ToLower(it.Name)]; ok {
						st.AgentID, st.Hostname = agents[i].AgentID, agents[i].Hostname
					}
				}
				st.State = rateBackupItem(it, stale, now, &st.AgeHours)
				// A vm/ct group whose guest no Proxmox node has any more
				// (deleted, or the ID reused by a guest of the other
				// type) is a leftover: shown, never overdue.
				if it.VMID != 0 && len(guests) > 0 && !st.InProxmox {
					st.State = "orphaned"
				}
				sys.Counts[st.State]++
				sys.Items = append(sys.Items, st)
			}
		}
		sort.SliceStable(sys.Items, func(i, j int) bool {
			rank := map[string]int{"overdue": 0, "verify_failed": 1, "never": 2, "not_covered": 3, "ok": 4, "orphaned": 5}
			return rank[sys.Items[i].State] < rank[sys.Items[j].State]
		})
		out = append(out, sys)
	}
	return out, nil
}

// backupGuestsResponse is what GET /api/backup-status?agent_id= answers:
// that endpoint's guests alone.
type backupGuestsResponse struct {
	Guests []backupStatus `json:"guests"`
}

// GET /api/backup-status[?agent_id=]
func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	list, err := s.backupStatuses(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if id := r.URL.Query().Get("agent_id"); id != "" {
		var mine []backupStatus
		for _, b := range list {
			if b.AgentID == id {
				mine = append(mine, b)
			}
		}
		writeJSONResponse(w, backupGuestsResponse{Guests: mine})
		return
	}
	counts := map[string]int{}
	for _, b := range list {
		counts[b.State]++
	}
	systems, err := s.backupSystems(r.Context(), list)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, backupsResponse{Guests: list, Counts: counts, StaleHours: s.backupStaleHours(r.Context()), Systems: systems})
}

// backupSettingsRequest is the body of POST /api/backup-status/settings.
type backupSettingsRequest struct {
	StaleHours float64 `json:"stale_hours" api:"required"`
}

// POST /api/backup-status/settings {"stale_hours": 36}
func (s *Server) handleBackupSettings(w http.ResponseWriter, r *http.Request) {
	var body backupSettingsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body); err != nil || body.StaleHours < 1 || body.StaleHours > 24*90 {
		http.Error(w, "stale_hours must be between 1 and 2160", http.StatusBadRequest)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	if err := s.store.SetSetting(r.Context(), settingBackupStaleHours, strconv.FormatFloat(body.StaleHours, 'f', -1, 64), who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "settings.backups", Actor: who, Target: "backup status", Severity: "notice",
		Detail: map[string]any{"stale_hours": body.StaleHours}})
	// Apply the new threshold now rather than at the next sweep.
	go s.checkBackups(context.WithoutCancel(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) backupAlertLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.checkBackups(ctx)
	}
}

// backupCheckMu keeps a settings-triggered check from racing the sweep
// into notifying the same guest twice.
var backupCheckMu sync.Mutex

func (s *Server) checkBackups(ctx context.Context) {
	backupCheckMu.Lock()
	defer backupCheckMu.Unlock()
	list, err := s.backupStatuses(ctx)
	if err != nil {
		return
	}
	open, err := s.store.BackupAlerts(ctx)
	if err != nil {
		return
	}
	stale := s.backupStaleHours(ctx)
	present := map[string]bool{}
	for _, b := range list {
		present[b.key()] = true
	}
	// Backup systems' items alert too, except a PBS group for a Proxmox
	// guest, which the guest's own row already covers.
	systems, _ := s.backupSystems(ctx, list)
	for _, sys := range systems {
		if sys.Error != "" && sys.OKAt == nil {
			continue // never read: nothing to judge
		}
		for _, it := range sys.Items {
			// A listed guest alerts from its own row; a leftover group
			// never does, and an alert it raised earlier is cleared
			// quietly below (it is not "present").
			if it.InProxmox || it.State == "orphaned" {
				continue
			}
			key := "src/" + sys.ID + "/" + it.Key
			present[key] = true
			bad := it.State == "overdue" || it.State == "never" || it.State == "verify_failed"
			_, alerted := open[key]
			name := firstNonEmpty(it.Hostname, it.Name)
			switch {
			case bad && !alerted:
				why := map[string]string{"never": "no backup at all", "verify_failed": "the newest backup failed verification"}[it.State]
				if why == "" {
					why = "newest backup more than " + strconv.FormatFloat(stale, 'f', -1, 64) + " hours old"
					if it.Compliance != "" {
						why += " or out of compliance (" + it.Compliance + ")"
					}
				}
				s.notify(ctx, "warning", "Backups", "Backup overdue: "+name, why+" ("+sys.Name+")", "/backup-status")
				s.audit(ctx, auditEvent{Action: "backups.overdue", Actor: "system", Target: name, AgentID: it.AgentID, Severity: "warning",
					Detail: map[string]any{"source": sys.Name, "item": it.Key, "state": it.State}})
				_ = s.store.SetBackupAlert(ctx, key, true)
			case !bad && alerted:
				s.notify(ctx, "info", "Backups", "Backup recovered: "+name, "backed up again ("+sys.Name+")", "/backup-status")
				_ = s.store.SetBackupAlert(ctx, key, false)
			}
		}
	}
	// A guest that was deleted or moved takes its alert with it.
	for k := range open {
		if !present[k] {
			_ = s.store.SetBackupAlert(ctx, k, false)
		}
	}
	for _, b := range list {
		bad := b.State == "overdue" || b.State == "never"
		_, alerted := open[b.key()]
		name := firstNonEmpty(b.Hostname, b.Name, "guest "+strconv.Itoa(b.VMID))
		switch {
		case bad && !alerted:
			why := "no backup at all"
			if b.State == "overdue" {
				why = "last backup " + b.LastBackup + ", more than " + strconv.FormatFloat(stale, 'f', -1, 64) + " hours ago"
			}
			s.notify(ctx, "warning", "Backups", "Backup overdue: "+name, why+" (Proxmox "+b.Node+", VM "+strconv.Itoa(b.VMID)+")", "/backup-status")
			s.audit(ctx, auditEvent{Action: "backups.overdue", Actor: "system", Target: name, AgentID: b.AgentID, Severity: "warning",
				Detail: map[string]any{"vmid": b.VMID, "node": b.Node, "last_backup": b.LastBackup}})
			_ = s.store.SetBackupAlert(ctx, b.key(), true)
		case !bad && alerted:
			s.notify(ctx, "info", "Backups", "Backup recovered: "+name, "newest backup "+b.LastBackup, "/backup-status")
			_ = s.store.SetBackupAlert(ctx, b.key(), false)
		}
	}
}

// pveType is a Proxmox guest type as PBS names its backup groups.
func pveType(t string) string {
	switch t {
	case "qemu":
		return "vm"
	case "lxc":
		return "ct"
	}
	return t
}
