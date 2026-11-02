package deploylog

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

type ReadOptions struct {
	JobID  string
	Search string
	Before time.Time
	Limit  int
	Bytes  int
}
type Result struct {
	Events    []proto.DeployEvent `json:"events"`
	Truncated bool                `json:"truncated"`
}

// Walk reads retained events without exposing unrelated jobs or filenames to
// callers. A context and decompression budget bound reads of compressed logs.
func Walk(ctx context.Context, dir, job string, visit func(proto.DeployEvent) error) error {
	lock, _ := directoryLocks.LoadOrStore(dir, &sync.Mutex{})
	mu := lock.(*sync.Mutex)
	for !mu.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer mu.Unlock()
	entries, e := os.ReadDir(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	remaining := int64(512 << 20)
	scan := func(in io.Reader) error {
		reader := bufio.NewScanner(io.LimitReader(in, remaining+1))
		reader.Buffer(make([]byte, 8192), 2<<20)
		for reader.Scan() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			remaining -= int64(len(reader.Bytes()) + 1)
			if remaining < 0 {
				return errors.New("log scan exceeded 512 MB; narrow retention before retrying")
			}
			var ev proto.DeployEvent
			if e := json.Unmarshal(reader.Bytes(), &ev); e != nil {
				return e
			}
			if ev.JobID == job {
				if e := visit(ev); e != nil {
					return e
				}
			}
		}
		return reader.Err()
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		path := filepath.Join(dir, entry.Name())
		if strings.HasSuffix(entry.Name(), ".zip") {
			z, e := zip.OpenReader(path)
			if e != nil {
				return e
			}
			for _, f := range z.File {
				in, err := f.Open()
				if err == nil {
					err = scan(in)
					in.Close()
				}
				if err != nil {
					z.Close()
					return err
				}
			}
			z.Close()
		} else if strings.HasSuffix(entry.Name(), ".log") {
			f, e := os.Open(path)
			if e != nil {
				return e
			}
			e = scan(f)
			f.Close()
			if e != nil {
				return e
			}
		}
	}
	return nil
}

func Read(ctx context.Context, dir string, o ReadOptions) (Result, error) {
	out := Result{Events: []proto.DeployEvent{}}
	if o.JobID == "" {
		return out, errors.New("an endpoint action run ID is required")
	}
	if o.Limit <= 0 {
		o.Limit = 2000
	}
	if o.Bytes <= 0 {
		o.Bytes = 4 << 20
	}
	seen := map[string]bool{}
	used := 0
	e := Walk(ctx, dir, o.JobID, func(ev proto.DeployEvent) error {
		if !o.Before.IsZero() && !ev.Timestamp.Before(o.Before) || !strings.Contains(strings.ToLower(ev.Message), strings.ToLower(o.Search)) || seen[ev.ID] {
			return nil
		}
		seen[ev.ID] = true
		out.Events = append(out.Events, ev)
		used += len(ev.Message) + 512
		for len(out.Events) > o.Limit || used > o.Bytes {
			used -= len(out.Events[0].Message) + 512
			delete(seen, out.Events[0].ID)
			out.Events = out.Events[1:]
			out.Truncated = true
		}
		return nil
	})
	sort.SliceStable(out.Events, func(i, j int) bool { return out.Events[i].Timestamp.Before(out.Events[j].Timestamp) })
	return out, e
}
