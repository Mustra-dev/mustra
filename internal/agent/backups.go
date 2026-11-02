package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Backups: on a Proxmox VE node, what the backup storages hold for each
// guest on this node, read with pvesh as root (no API token involved).
// Shared storages list every node's backups; only this node's guests are
// reported, so a cluster's nodes do not double count. Any other endpoint
// reports nothing.

const pveshPath = "/usr/bin/pvesh"

func collectBackups(ctx context.Context) ([]proto.BackupGuest, error) {
	if _, err := os.Stat(pveshPath); err != nil {
		return []proto.BackupGuest{}, nil
	}
	node, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	node, _, _ = strings.Cut(node, ".")

	var guests []proto.BackupGuest
	for _, typ := range []string{"qemu", "lxc"} {
		var list []struct {
			VMID   json.Number `json:"vmid"`
			Name   string      `json:"name"`
			Status string      `json:"status"`
			Tmpl   int         `json:"template"`
		}
		if err := pvesh(ctx, &list, "get", "/nodes/"+node+"/"+typ); err != nil {
			return nil, err
		}
		for _, g := range list {
			if g.Tmpl == 1 {
				continue
			}
			id, _ := g.VMID.Int64()
			guests = append(guests, proto.BackupGuest{VMID: int(id), Name: g.Name, Type: typ, Status: g.Status, Node: node})
		}
	}
	byID := map[int]*proto.BackupGuest{}
	for i := range guests {
		byID[guests[i].VMID] = &guests[i]
		guests[i].MACs = guestMACs(ctx, node, guests[i].Type, guests[i].VMID)
	}

	jobs, _ := os.ReadFile("/etc/pve/jobs.cfg")
	legacy, _ := os.ReadFile("/etc/pve/vzdump.cron")
	users, _ := os.ReadFile("/etc/pve/user.cfg")
	pools := parsePoolMembers(string(users))
	for _, j := range parseVzdumpJobs(string(jobs) + "\n" + string(legacy)) {
		j.expandPool(pools)
		for _, g := range guests {
			if j.covers(g.VMID, node) {
				byID[g.VMID].Covered = true
				byID[g.VMID].Jobs = append(byID[g.VMID].Jobs, j.id)
			}
		}
	}

	var storages []struct {
		Storage string `json:"storage"`
		Active  int    `json:"active"`
	}
	if err := pvesh(ctx, &storages, "get", "/nodes/"+node+"/storage", "--content", "backup"); err != nil {
		return nil, err
	}
	for _, st := range storages {
		if st.Active != 1 {
			continue
		}
		var content []struct {
			VMID         json.Number `json:"vmid"`
			Ctime        int64       `json:"ctime"`
			Size         int64       `json:"size"`
			Verification *struct {
				State string `json:"state"`
			} `json:"verification"`
		}
		if err := pvesh(ctx, &content, "get", "/nodes/"+node+"/storage/"+st.Storage+"/content", "--content", "backup"); err != nil {
			continue // one unreachable remote storage must not hide the rest
		}
		for _, c := range content {
			id, _ := c.VMID.Int64()
			g := byID[int(id)]
			if g == nil {
				continue
			}
			g.Backups++
			if !containsStr(g.Storages, st.Storage) {
				g.Storages = append(g.Storages, st.Storage)
			}
			at := time.Unix(c.Ctime, 0).UTC().Format(time.RFC3339)
			if at > g.LastBackup {
				g.LastBackup, g.LastStorage, g.LastSizeBytes, g.LastVerified = at, st.Storage, c.Size, ""
				if c.Verification != nil {
					g.LastVerified = c.Verification.State
				}
			}
		}
	}

	var tasks []struct {
		Status  string `json:"status"`
		EndTime int64  `json:"endtime"`
	}
	if pvesh(ctx, &tasks, "get", "/nodes/"+node+"/tasks", "--typefilter", "vzdump", "--limit", "1") == nil && len(tasks) > 0 {
		for i := range guests {
			guests[i].LastJobStatus = tasks[0].Status
			if tasks[0].EndTime > 0 {
				guests[i].LastJobEnd = time.Unix(tasks[0].EndTime, 0).UTC().Format(time.RFC3339)
			}
		}
	}
	sort.Slice(guests, func(i, j int) bool { return guests[i].VMID < guests[j].VMID })
	if guests == nil {
		guests = []proto.BackupGuest{}
	}
	return guests, nil
}

func pvesh(ctx context.Context, out any, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(cctx, pveshPath, append(args, "--output-format", "json")...).Output()
	if err != nil {
		return fmt.Errorf("pvesh %s: %w", strings.Join(args[:2], " "), err)
	}
	return json.Unmarshal(raw, out)
}

var guestMACRe = regexp.MustCompile(`(?i)(?:^|[,=])((?:[0-9a-f]{2}:){5}[0-9a-f]{2})`)

// guestMACs reads the guest's network cards from its configuration, the
// link between a guest and the Mustra agent running inside it.
func guestMACs(ctx context.Context, node, typ string, vmid int) []string {
	var cfg map[string]any
	if pvesh(ctx, &cfg, "get", fmt.Sprintf("/nodes/%s/%s/%d/config", node, typ, vmid)) != nil {
		return nil
	}
	var out []string
	for k, v := range cfg {
		s, ok := v.(string)
		if !ok || !strings.HasPrefix(k, "net") {
			continue
		}
		if m := guestMACRe.FindStringSubmatch(s); m != nil {
			out = append(out, strings.ToLower(m[1]))
		}
	}
	sort.Strings(out)
	return out
}

type vzdumpJob struct {
	id      string
	enabled bool
	all     bool
	node    string
	pool    string
	vmids   map[int]bool
	exclude map[int]bool
}

// expandPool turns a pool-based job into the guests the pool holds now,
// which is what vzdump itself backs up when the job runs.
func (j *vzdumpJob) expandPool(pools map[string][]int) {
	if j.pool == "" {
		return
	}
	for _, id := range pools[j.pool] {
		j.vmids[id] = true
	}
}

// parsePoolMembers reads the pool lines of /etc/pve/user.cfg,
// "pool:<name>:<comment>:<vmids>:<storages>", into pool → guest IDs.
func parsePoolMembers(cfg string) map[string][]int {
	out := map[string][]int{}
	for _, line := range strings.Split(cfg, "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 4 || f[0] != "pool" || f[1] == "" {
			continue
		}
		for _, v := range strings.Split(f[3], ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				out[f[1]] = append(out[f[1]], n)
			}
		}
	}
	return out
}

func (j vzdumpJob) covers(vmid int, node string) bool {
	if !j.enabled || (j.node != "" && j.node != node) || j.exclude[vmid] {
		return false
	}
	return j.all || j.vmids[vmid]
}

// parseVzdumpJobs reads the vzdump sections of /etc/pve/jobs.cfg:
//
//	vzdump: backup-f4f5
//		schedule 2,19:30
//		all 1
//		exclude 117
//		enabled 1
//
// A job is enabled unless it says "enabled 0". A pool-based job ("pool
// <name>") covers the pool's members, which expandPool fills in from
// /etc/pve/user.cfg.
func parseVzdumpJobs(cfg string) []vzdumpJob {
	var jobs []vzdumpJob
	var cur *vzdumpJob
	ids := func(v string) map[int]bool {
		m := map[int]bool{}
		for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
				m[n] = true
			}
		}
		return m
	}
	for _, line := range strings.Split(cfg, "\n") {
		if strings.HasPrefix(line, "vzdump:") {
			jobs = append(jobs, vzdumpJob{id: strings.TrimSpace(strings.TrimPrefix(line, "vzdump:")), enabled: true, vmids: map[int]bool{}, exclude: map[int]bool{}})
			cur = &jobs[len(jobs)-1]
			continue
		}
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			cur = nil // another section type
			continue
		}
		if cur == nil {
			continue
		}
		key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
		val = strings.TrimSpace(val)
		switch key {
		case "enabled":
			cur.enabled = val != "0"
		case "all":
			cur.all = val == "1"
		case "vmid":
			cur.vmids = ids(val)
		case "exclude":
			cur.exclude = ids(val)
		case "node":
			cur.node = val
		case "pool":
			cur.pool = val
		}
	}
	return jobs
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
