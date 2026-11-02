package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

var sensorCacheMu sync.Mutex

// Copy verified bytes into the private execution directory, so cache eviction
// cannot race a running executable (including Windows file locking).
func stageGoSensor(ctx context.Context, a *proto.SensorArtifact, dst string) error {
	if a == nil || a.OS != runtime.GOOS || a.Arch != runtime.GOARCH {
		return fmt.Errorf("missing or incompatible Go sensor artifact")
	}
	hash, err := hex.DecodeString(a.File.SHA256)
	if err != nil || len(hash) != sha256.Size || a.File.Size <= 0 || a.File.Size > proto.MaxSensorArtifactBytes {
		return fmt.Errorf("invalid Go sensor artifact metadata")
	}
	sensorCacheMu.Lock()
	defer sensorCacheMu.Unlock()
	root, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	root = filepath.Join(root, "mustra", "go-sensors")
	if err = os.MkdirAll(root, 0700); err != nil {
		return err
	}
	path := filepath.Join(root, strings.ToLower(a.File.SHA256))
	data, err := readSensorCache(path, a.File.Size)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != strings.ToLower(a.File.SHA256) {
		req, err := http.NewRequestWithContext(ctx, "GET", a.File.URL, nil)
		if err != nil {
			return err
		}
		client := http.Client{Timeout: 60 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, a.File.Size+1))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 || int64(len(data)) != a.File.Size || fmt.Sprintf("%x", sha256.Sum256(data)) != strings.ToLower(a.File.SHA256) {
			return fmt.Errorf("Go sensor download failed checksum or size verification")
		}
		f, err := os.CreateTemp(root, ".download-")
		if err != nil {
			return err
		}
		name := f.Name()
		_, err = f.Write(data)
		ce := f.Close()
		if err == nil {
			err = ce
		}
		if err == nil {
			_ = os.Remove(path)
			err = os.Rename(name, path)
		}
		os.Remove(name)
		if err != nil {
			return err
		}
	}
	now := time.Now()
	_ = os.Chtimes(path, now, now)
	// Keep recent revisions for rollback, with a fixed disk budget.
	entries, _ := os.ReadDir(root)
	infos := []os.FileInfo{}
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if i, err := e.Info(); err == nil {
			infos = append(infos, i)
			total += i.Size()
		}
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ModTime().Before(infos[j].ModTime()) })
	for _, i := range infos {
		if total <= 128<<20 {
			break
		}
		if filepath.Join(root, i.Name()) != path {
			if os.Remove(filepath.Join(root, i.Name())) == nil {
				total -= i.Size()
			}
		}
	}
	return os.WriteFile(dst, data, 0700)
}
func readSensorCache(path string, size int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, size+1))
	if err == nil && int64(len(b)) != size {
		err = fmt.Errorf("cache size mismatch")
	}
	return b, err
}
