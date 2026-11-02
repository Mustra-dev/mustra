package agent

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func verifyCachedFile(path, want string) bool {
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	return e == nil && strings.EqualFold(fmt.Sprintf("%x", h.Sum(nil)), want)
}
func pruneDeployCache(dir string, limit int64) {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return
	}
	var files []os.FileInfo
	var used int64
	for _, entry := range entries {
		if len(entry.Name()) != 64 {
			continue
		}
		st, e := entry.Info()
		if e != nil {
			continue
		}
		files = append(files, st)
		used += st.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].ModTime().Before(files[j].ModTime()) })
	for _, f := range files {
		if used <= limit {
			break
		}
		if os.Remove(filepath.Join(dir, f.Name())) == nil {
			used -= f.Size()
		}
	}
}
