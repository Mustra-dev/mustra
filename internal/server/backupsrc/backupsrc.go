// Package backupsrc reads backup status from backup systems themselves
// (Proxmox Backup Server, Rubrik Security Cloud), for the Backup status
// page. The backups sensor already reports what Proxmox VE's jobs hold for
// each guest; a backup system also knows what nothing in Proxmox made (a
// host backed up with the PBS client, a Rubrik-protected server), how full
// its storage is, and whether a backup was verified.
//
// A provider only reads. Credentials are the caller's to keep sealed; the
// HTTP client is the caller's too, so it can refuse addresses an
// administrator has not allowed.
package backupsrc

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// Config is one connected backup system.
type Config struct {
	Kind string // pbs | rubrik
	// URL is the system's base address: https://pbs.example:8007 for PBS,
	// https://<account>.my.rubrik.com for Rubrik Security Cloud.
	URL string
	// TokenID and Secret authenticate: a PBS API token
	// (user@realm!name and its secret), or a Rubrik service account's
	// client ID and client secret.
	TokenID string
	Secret  string
	// Datastore limits PBS to one datastore; empty reads them all.
	Datastore string
}

// Item is one protected thing and its newest backup.
type Item struct {
	// Key identifies the item within its system: "vm/120", "host/pihole2",
	// a Rubrik object ID.
	Key string `json:"key"`
	// Type is vm, ct or host for PBS; the object type for Rubrik
	// (VmwareVirtualMachine, LinuxFileset…).
	Type string `json:"type"`
	// Name is what the system calls it: a guest ID for PBS vm/ct groups
	// (the Backup status page puts the guest's name to it), the host name
	// for PBS host groups, the object name for Rubrik.
	Name string `json:"name"`
	// VMID is set for PBS vm and ct groups.
	VMID       int        `json:"vmid,omitempty"`
	LastBackup *time.Time `json:"last_backup,omitempty"`
	// Count is how many backups are kept, when the system says.
	Count     int   `json:"count,omitempty"`
	SizeBytes int64 `json:"size_bytes,omitempty"`
	// Verified is ok, failed or none for the newest backup, empty when
	// the system does not verify.
	Verified string `json:"verified,omitempty"`
	// Compliance is the system's own judgement, when it has one
	// (Rubrik's SLA compliance), as the system words it.
	Compliance string `json:"compliance,omitempty"`
	// Protected is false when the system knows the object but nothing
	// protects it (Rubrik: no SLA).
	Protected bool `json:"protected"`
	// Location is where the backup lives: a datastore, a cluster.
	Location string `json:"location,omitempty"`
}

// Store is one storage location's usage.
type Store struct {
	Name       string `json:"name"`
	UsedBytes  int64  `json:"used_bytes"`
	TotalBytes int64  `json:"total_bytes"`
	// FullAt is the system's own estimate of when the store fills up,
	// only when it is in the future.
	FullAt *time.Time `json:"full_at,omitempty"`
}

// Job is a maintenance job on the backup system (PBS verify, prune,
// garbage collection, sync) and how its last run ended.
type Job struct {
	Kind  string `json:"kind"` // verify, prune, gc, sync
	ID    string `json:"id"`
	Store string `json:"store"`
	// State is "OK", "running", "never" or the failure as the system
	// reports it.
	State    string     `json:"state"`
	LastEnd  *time.Time `json:"last_end,omitempty"`
	NextRun  *time.Time `json:"next_run,omitempty"`
	Schedule string     `json:"schedule,omitempty"`
	// Detail is what the run did, where the system says (garbage
	// collection: what it freed and what is still pending).
	Detail string `json:"detail,omitempty"`
}

// Failed reports a job whose last run ended badly.
func (j Job) Failed() bool {
	return j.State != "" && j.State != "OK" && j.State != "running" && j.State != "never"
}

// Result is one read of a system.
type Result struct {
	Items  []Item  `json:"items"`
	Stores []Store `json:"stores"`
	// Jobs is omitted by systems that do not report them.
	Jobs []Job `json:"jobs,omitempty"`
}

// Fetch reads cfg's system with client.
func Fetch(ctx context.Context, client *http.Client, cfg Config) (Result, error) {
	var (
		r   Result
		err error
	)
	switch cfg.Kind {
	case "pbs":
		r, err = fetchPBS(ctx, client, cfg)
	case "rubrik":
		r, err = fetchRubrik(ctx, client, cfg)
	default:
		return Result{}, fmt.Errorf("unknown backup system %q", cfg.Kind)
	}
	if err != nil {
		return Result{}, err
	}
	if r.Items == nil {
		r.Items = []Item{}
	}
	if r.Stores == nil {
		r.Stores = []Store{}
	}
	sort.Slice(r.Items, func(i, j int) bool { return r.Items[i].Key < r.Items[j].Key })
	return r, nil
}

// Kinds are the systems a backup source can be, with their display names.
var Kinds = map[string]string{
	"pbs":    "Proxmox Backup Server",
	"rubrik": "Rubrik Security Cloud",
}
