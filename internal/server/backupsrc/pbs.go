package backupsrc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Proxmox Backup Server: /api2/json with an API token
// (Authorization: PBSAPIToken=<user@realm!name>:<secret>). The token
// needs Datastore.Audit on /datastore (the DatastoreAudit role), for the
// token itself as well as its user: a token's rights are the
// intersection of both.
//
//   GET /admin/datastore                    the datastores
//   GET /status/datastore-usage             used, total, estimated-full-date
//   GET /admin/datastore/{store}/groups     per group: type, id, last-backup, backup-count
//   GET /admin/datastore/{store}/snapshots  per snapshot: verification state, size
//   GET /admin/{verify,prune,gc,sync}       job status: last-run-state, last-run-endtime,
//                                           next-run (best effort: a token without
//                                           the right to list one kind skips it)
//
// A group with no snapshot has last-backup 0 (PBS 4 lists empty groups).

func fetchPBS(ctx context.Context, client *http.Client, cfg Config) (Result, error) {
	base := strings.TrimRight(cfg.URL, "/") + "/api2/json"
	get := func(path string, out any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "PBSAPIToken="+cfg.TokenID+":"+cfg.Secret)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			msg := strings.TrimSpace(string(body))
			if len(msg) > 200 {
				msg = msg[:200]
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return fmt.Errorf("%s: %s (check the token and that it has DatastoreAudit on /datastore)", path, resp.Status)
			}
			return fmt.Errorf("%s: %s %s", path, resp.Status, msg)
		}
		return json.Unmarshal(body, &struct {
			Data any `json:"data"`
		}{Data: out})
	}

	var stores []struct {
		Store string `json:"store"`
	}
	if err := get("/admin/datastore", &stores); err != nil {
		return Result{}, err
	}
	var usage []struct {
		Store    string `json:"store"`
		Used     int64  `json:"used"`
		Total    int64  `json:"total"`
		FullDate int64  `json:"estimated-full-date"`
	}
	if err := get("/status/datastore-usage", &usage); err != nil {
		return Result{}, err
	}
	var r Result
	now := time.Now()
	for _, u := range usage {
		if cfg.Datastore != "" && u.Store != cfg.Datastore {
			continue
		}
		st := Store{Name: u.Store, UsedBytes: u.Used, TotalBytes: u.Total}
		// The estimate extrapolates recent growth; one in the past, or
		// years away, says nothing useful.
		if full := time.Unix(u.FullDate, 0); u.FullDate > 0 && full.After(now) && full.Before(now.AddDate(5, 0, 0)) {
			st.FullAt = &full
		}
		r.Stores = append(r.Stores, st)
	}
	seen := false
	for _, ds := range stores {
		if cfg.Datastore != "" && ds.Store != cfg.Datastore {
			continue
		}
		seen = true
		var groups []struct {
			Type  string      `json:"backup-type"`
			ID    string      `json:"backup-id"`
			Last  int64       `json:"last-backup"`
			Count json.Number `json:"backup-count"`
		}
		if err := get("/admin/datastore/"+url.PathEscape(ds.Store)+"/groups", &groups); err != nil {
			return Result{}, err
		}
		var snaps []struct {
			Type         string `json:"backup-type"`
			ID           string `json:"backup-id"`
			Time         int64  `json:"backup-time"`
			Size         int64  `json:"size"`
			Verification *struct {
				State string `json:"state"`
			} `json:"verification"`
		}
		if err := get("/admin/datastore/"+url.PathEscape(ds.Store)+"/snapshots", &snaps); err != nil {
			return Result{}, err
		}
		type newest struct {
			time     int64
			size     int64
			verified string
		}
		latest := map[string]newest{}
		for _, sn := range snaps {
			k := sn.Type + "/" + sn.ID
			if cur, ok := latest[k]; ok && cur.time >= sn.Time {
				continue
			}
			v := "none"
			if sn.Verification != nil && sn.Verification.State != "" {
				v = sn.Verification.State
			}
			latest[k] = newest{time: sn.Time, size: sn.Size, verified: v}
		}
		for _, g := range groups {
			it := Item{Key: ds.Store + ":" + g.Type + "/" + g.ID, Type: g.Type, Name: g.ID, Location: ds.Store, Protected: true}
			if n, err := g.Count.Int64(); err == nil {
				it.Count = int(n)
			}
			if g.Type == "vm" || g.Type == "ct" {
				it.VMID, _ = strconv.Atoi(g.ID)
			}
			if g.Last > 0 {
				t := time.Unix(g.Last, 0).UTC()
				it.LastBackup = &t
			}
			if n, ok := latest[g.Type+"/"+g.ID]; ok {
				it.SizeBytes, it.Verified = n.size, n.verified
			}
			r.Items = append(r.Items, it)
		}
	}
	if cfg.Datastore != "" && !seen {
		return Result{}, fmt.Errorf("no datastore named %q on this server", cfg.Datastore)
	}
	for _, kind := range []string{"verify", "prune", "gc", "sync"} {
		var raw []pbsJob
		if get("/admin/"+kind, &raw) != nil {
			continue
		}
		for _, j := range raw {
			if store := firstNonEmpty(j.Store, j.Store2); cfg.Datastore == "" || store == cfg.Datastore {
				r.Jobs = append(r.Jobs, j.job(kind))
			}
		}
	}
	return r, nil
}

// pbsJob is one entry of /admin/{verify,prune,gc,sync}.
type pbsJob struct {
	ID       string `json:"id"`
	Store    string `json:"store"`
	Store2   string `json:"remote-store"`
	Schedule string `json:"schedule"`
	State    string `json:"last-run-state"`
	EndTime  int64  `json:"last-run-endtime"`
	UPID     string `json:"last-run-upid"`
	// Garbage collection reports its last run as well as its schedule.
	GCUPID       string `json:"upid"`
	NextRun      int64  `json:"next-run"`
	RemovedBytes *int64 `json:"removed-bytes"`
	PendingBytes *int64 `json:"pending-bytes"`
}

func (p pbsJob) job(kind string) Job {
	j := Job{Kind: kind, ID: firstNonEmpty(p.ID, p.Store), Store: p.Store, Schedule: p.Schedule, State: p.State}
	if p.EndTime > 0 {
		t := time.Unix(p.EndTime, 0).UTC()
		j.LastEnd = &t
	}
	if p.NextRun > 0 {
		t := time.Unix(p.NextRun, 0).UTC()
		j.NextRun = &t
	}
	switch {
	case j.State != "":
	case p.UPID != "" || p.GCUPID != "":
		// Started, and no end recorded yet.
		j.State = "running"
	default:
		j.State = "never"
	}
	if p.RemovedBytes != nil && p.PendingBytes != nil {
		j.Detail = fmt.Sprintf("freed %s, %s pending removal", humanBytes(*p.RemovedBytes), humanBytes(*p.PendingBytes))
	}
	return j
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
