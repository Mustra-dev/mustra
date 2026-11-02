// Package deploylog stores bounded deployment transcripts independently of the
// service log. Archives are verified before their source segments are removed.
package deploylog

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

var directoryLocks sync.Map

type Log struct {
	mu       *sync.Mutex
	dir      string
	settings proto.DeployLogSettings
}

func Validate(s proto.DeployLogSettings) error {
	if s.RetentionDays < 0 || s.RetentionDays > 36500 || s.ArchiveMB < 1 || s.ArchiveMB > 1048576 || s.RotateMB < 1 || s.RotateMB > 1024 || s.CompressFiles < 1 || s.CompressFiles > 100 {
		return fmt.Errorf("invalid log settings: age 0–36500 days, archive 1–1048576 MB, rotation 1–1024 MB, batch 1–100 files")
	}
	return nil
}
func Open(dir string, s proto.DeployLogSettings) (*Log, error) {
	if e := Validate(s); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	lock, _ := directoryLocks.LoadOrStore(dir, &sync.Mutex{})
	l := &Log{dir: dir, settings: s, mu: lock.(*sync.Mutex)}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.maintain(); e != nil {
		return nil, e
	}
	return l, nil
}
func (l *Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	path := filepath.Join(l.dir, "active.log")
	limit := int64(l.settings.RotateMB) * 1000000
	if st, e := os.Stat(path); e == nil && st.Size() > 0 && st.Size()+int64(len(p)) > limit {
		if e = l.rotate(); e != nil {
			return 0, e
		}
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return 0, e
	}
	// Preserve complete records across rotation; readers parse one JSON event per line.
	n, e := f.Write(p)
	if e == nil {
		e = f.Sync()
	}
	st, se := f.Stat()
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = se
	}
	if e == nil && st.Size() >= limit {
		e = l.rotate()
	}
	return n, e
}

func (l *Log) rotate() error {
	name := fmt.Sprintf("%020d.log", time.Now().UnixNano())
	if e := os.Rename(filepath.Join(l.dir, "active.log"), filepath.Join(l.dir, name)); e != nil {
		return e
	}
	return l.maintain()
}
func (l *Log) maintain() error {
	entries, e := os.ReadDir(l.dir)
	if e != nil {
		return e
	}
	var pending []string
	for _, entry := range entries {
		if l.settings.RetentionDays > 0 && strings.HasSuffix(entry.Name(), ".log") {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if time.Since(info.ModTime()) > time.Duration(l.settings.RetentionDays)*24*time.Hour {
				if err = os.Remove(filepath.Join(l.dir, entry.Name())); err != nil {
					return err
				}
				continue
			}
		}
		if strings.HasSuffix(entry.Name(), ".log") && entry.Name() != "active.log" {
			pending = append(pending, entry.Name())
		}
	}
	sort.Strings(pending)
	for len(pending) >= l.settings.CompressFiles {
		batch := pending[:l.settings.CompressFiles]
		name := strings.TrimSuffix(batch[0], ".log") + ".zip"
		dst := filepath.Join(l.dir, name)
		if _, e := os.Stat(dst); e != nil {
			f, e := os.CreateTemp(l.dir, ".archive-")
			if e != nil {
				return e
			}
			temp := f.Name()
			zw := zip.NewWriter(f)
			for _, seg := range batch {
				w, err := zw.Create(seg)
				if err != nil {
					e = err
					break
				}
				src, err := os.Open(filepath.Join(l.dir, seg))
				if err != nil {
					e = err
					break
				}
				_, e = io.Copy(w, src)
				src.Close()
				if e != nil {
					break
				}
			}
			ze := zw.Close()
			se := f.Sync()
			ce := f.Close()
			if e == nil {
				e = ze
			}
			if e == nil {
				e = se
			}
			if e == nil {
				e = ce
			}
			if e == nil {
				e = verify(temp)
			}
			if e == nil {
				e = os.Rename(temp, dst)
			}
			_ = os.Remove(temp)
			if e != nil {
				return e
			}
		} else if e = verify(dst); e != nil {
			return e
		}
		for _, seg := range batch {
			if e = os.Remove(filepath.Join(l.dir, seg)); e != nil {
				return e
			}
		}
		pending = pending[l.settings.CompressFiles:]
	}
	entries, e = os.ReadDir(l.dir)
	if e != nil {
		return e
	}
	type archive struct {
		name  string
		size  int64
		mtime time.Time
	}
	var archives []archive
	var used int64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".zip") {
			continue
		}
		st, e := entry.Info()
		if e != nil {
			return e
		}
		archives = append(archives, archive{entry.Name(), st.Size(), st.ModTime()})
		used += st.Size()
	}
	sort.Slice(archives, func(i, j int) bool { return archives[i].name < archives[j].name })
	for _, a := range archives {
		expired := l.settings.RetentionDays > 0 && time.Since(a.mtime) > time.Duration(l.settings.RetentionDays)*24*time.Hour
		if used <= int64(l.settings.ArchiveMB)*1000000 && !expired {
			continue
		}
		if e = os.Remove(filepath.Join(l.dir, a.name)); e != nil {
			return e
		}
		used -= a.size
	}
	return nil
}
func verify(path string) error {
	r, e := zip.OpenReader(path)
	if e != nil {
		return e
	}
	defer r.Close()
	for _, f := range r.File {
		in, e := f.Open()
		if e != nil {
			return e
		}
		_, e = io.Copy(io.Discard, in)
		in.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func (l *Log) Snapshot(w io.Writer) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	zw := zip.NewWriter(w)
	entries, e := os.ReadDir(l.dir)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".zip") && !strings.HasSuffix(entry.Name(), ".log")) {
			continue
		}
		f, e := os.Open(filepath.Join(l.dir, entry.Name()))
		if e != nil {
			return e
		}
		out, e := zw.Create(entry.Name())
		if e == nil {
			_, e = io.Copy(out, f)
		}
		f.Close()
		if e != nil {
			return e
		}
	}
	return zw.Close()
}

func (l *Log) SetSettings(settings proto.DeployLogSettings) error {
	if e := Validate(settings); e != nil {
		return e
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.settings == settings {
		return nil
	}
	l.settings = settings
	return l.maintain()
}
