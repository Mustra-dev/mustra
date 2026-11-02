package deploylog

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mustra-dev/mustra/internal/proto"
	"strings"
	"testing"
	"time"
)

func TestReadRunLogsAcrossArchives(t *testing.T) {
	dir := t.TempDir()
	settings := proto.DefaultDeploySettings().ServerLogs
	settings.RotateMB = 1
	settings.CompressFiles = 1
	log, e := Open(dir, settings)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	for i := 0; i < 60; i++ {
		ev := proto.DeployEvent{ID: fmt.Sprint(i), JobID: "wanted", Timestamp: now.Add(time.Duration(i) * time.Second), Message: strings.Repeat("output ", 6000)}
		if i%2 == 1 {
			ev.JobID = "unrelated"
		}
		raw, _ := json.Marshal(ev)
		if _, e = log.Write(append(raw, '\n')); e != nil {
			t.Fatal(e)
		}
	}
	result, e := Read(context.Background(), dir, ReadOptions{JobID: "wanted", Limit: 5, Bytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Events) != 5 || !result.Truncated || result.Events[4].ID != "58" {
		t.Fatalf("wrong bounded history: %d %v", len(result.Events), result.Truncated)
	}
	count := 0
	e = Walk(context.Background(), dir, "wanted", func(ev proto.DeployEvent) error {
		count++
		if ev.JobID != "wanted" {
			t.Fatal("unrelated run leaked")
		}
		return nil
	})
	if e != nil || count != 30 {
		t.Fatalf("per-run export: %d %v", count, e)
	}
	older, e := Read(context.Background(), dir, ReadOptions{JobID: "wanted", Before: result.Events[0].Timestamp, Limit: 5})
	if e != nil || len(older.Events) != 5 || !older.Events[4].Timestamp.Before(result.Events[0].Timestamp) {
		t.Fatal("older history missing", e)
	}
}
