package agent

import (
	"encoding/json"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"path/filepath"
	"time"
)

var deployHistoryBucket = []byte("deploy_sensor_history")

type deployHistoryBatch struct {
	Paths    []string         `json:"paths,omitempty"`
	Since    time.Time        `json:"since"`
	Until    time.Time        `json:"until"`
	Complete bool             `json:"complete"`
	Rows     []map[string]any `json:"rows"`
}

// A bounded local history preserves coverage, including empty observation
// windows. Missing windows and suppression invalidate negative assertions.
func (a *Agent) saveDeployHistory(kind string, since, until time.Time, data any, complete bool, paths ...[]string) {
	if a.store == nil {
		return
	}
	raw, e := json.Marshal(data)
	if e != nil {
		return
	}
	var rows []map[string]any
	if string(raw) != "null" {
		if json.Unmarshal(raw, &rows) != nil {
			return
		}
	}
	batch := deployHistoryBatch{Since: since, Until: until, Rows: rows, Complete: complete}
	if len(paths) > 0 {
		batch.Paths = paths[0]
	}
	raw, e = json.Marshal(batch)
	if e != nil {
		return
	}
	e = a.store.db.Update(func(tx *bolt.Tx) error {
		root, e := tx.CreateBucketIfNotExists(deployHistoryBucket)
		if e != nil {
			return e
		}
		b, e := root.CreateBucketIfNotExists([]byte(kind))
		if e != nil {
			return e
		}
		if e = b.Put([]byte(until.UTC().Format(time.RFC3339Nano)), raw); e != nil {
			return e
		}
		// Keep at most 24 hours and 16 MB per history source.
		var used int64
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			used += int64(len(v))
			var entry deployHistoryBatch
			if json.Unmarshal(v, &entry) != nil || used > 16<<20 || time.Since(entry.Until) > 24*time.Hour {
				if e = c.Delete(); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if e != nil {
		a.logger.Warn("persist deployment sensor history", "sensor", kind, "error", e)
	}
}
func (a *Agent) deployHistoryRows(kind string, lookback int, path string) ([]map[string]any, error) {
	if a.store == nil || lookback <= 0 || lookback > 86400 {
		return nil, fmt.Errorf("historical checks require a lookback from 1 to 86400 seconds")
	}
	until := time.Now()
	since := until.Add(-time.Duration(lookback) * time.Second)
	covered := since
	rows := []map[string]any{}
	e := a.store.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(deployHistoryBucket)
		if root == nil {
			return fmt.Errorf("historical collection has no coverage")
		}
		b := root.Bucket([]byte(kind))
		if b == nil {
			return fmt.Errorf("historical sensor has no coverage")
		}
		return b.ForEach(func(k, v []byte) error {
			var entry deployHistoryBatch
			if e := json.Unmarshal(v, &entry); e != nil {
				return e
			}
			if entry.Until.Before(since) {
				return nil
			}
			if kind == "file_events" {
				if path == "" {
					return fmt.Errorf("file history requires an exact path filter to verify monitoring coverage")
				}
				dir := filepath.Dir(path)
				if canonical, e := filepath.EvalSymlinks(dir); e == nil {
					dir = canonical
				}
				coveredPath := false
				for _, p := range entry.Paths {
					canonical, e := filepath.EvalSymlinks(p)
					if e == nil && canonical == dir {
						coveredPath = true
					}
					if p == dir {
						coveredPath = true
					}
				}
				if !coveredPath {
					return fmt.Errorf("requested file was outside monitored directories during the window")
				}
			}
			if !entry.Complete {
				return fmt.Errorf("historical window contains suppression or incomplete monitoring")
			}
			if entry.Since.After(covered.Add(time.Second)) {
				return fmt.Errorf("historical window contains a collection gap")
			}
			covered = entry.Until
			for _, row := range entry.Rows {
				at, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(row["at"]))
				if !at.IsZero() && (at.Before(since) || at.After(until)) {
					continue
				}
				rows = append(rows, row)
			}
			if len(rows) > 10000 {
				return fmt.Errorf("historical check exceeds 10000 rows")
			}
			return nil
		})
	})
	if e != nil {
		return nil, e
	}
	if covered.Before(until.Add(-15 * time.Second)) {
		return nil, fmt.Errorf("historical collection is not current")
	}
	return rows, nil
}
