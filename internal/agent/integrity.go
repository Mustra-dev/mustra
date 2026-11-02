package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// File integrity monitoring, hash-baseline half.
//
// FIM splits into real-time event monitoring (inotify /
// ReadDirectoryChangesW) and periodic hash baselining. This is the second
// half, and deliberately so: the baseline is what actually answers "has
// anything changed since last time", it needs no kernel interface, no
// watch descriptors, and no per-OS event plumbing, and it cannot miss a
// change that happened while the agent was down — which is exactly when
// interesting changes happen.
//
// The agent reports the current state of the watched set. The server
// diffs consecutive snapshots, which is where change detection belongs:
// the endpoint would otherwise need durable state to compare against, and
// an attacker who can write the file can write the baseline beside it.

const (
	maxIntegrityFiles = 3000
	maxIntegrityBytes = 32 << 20 // hashing a 4 GB log every interval helps nobody
	maxIntegrityDepth = 8
)

// integrityPaths are the files whose contents changing is worth knowing
// about — authentication, authorization, scheduled execution, and service
// definitions. Anything an attacker touches to keep access, and anything
// an operator touches by mistake at 2am.
func integrityPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			`C:\Windows\System32\drivers\etc`,
			`C:\Windows\System32\Tasks`,
		}
	case "darwin":
		return []string{
			"/etc/sudoers", "/etc/sudoers.d", "/etc/hosts", "/etc/ssh",
			"/Library/LaunchDaemons", "/Library/LaunchAgents",
		}
	default:
		return []string{
			"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
			"/etc/sudoers", "/etc/sudoers.d",
			"/etc/ssh", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
			"/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
			"/etc/systemd/system", "/etc/pam.d", "/etc/security",
			"/etc/apt/sources.list", "/etc/apt/sources.list.d",
			"/etc/yum.repos.d", "/root/.ssh",
		}
	}
}

func collectIntegrity(ctx context.Context) ([]proto.IntegrityFile, error) {
	out := []proto.IntegrityFile{}
	seen := map[string]bool{}
	count := 0
	cfg := currentWatch()

	for _, root := range append(integrityPaths(), extraWatchPaths()...) {
		if ctx.Err() != nil {
			break
		}
		info, err := os.Lstat(root)
		if err != nil {
			continue // a path this OS doesn't have is not an error
		}
		if !info.IsDir() {
			if f, ok := describeIntegrityFileOpt(root, cfg.FollowSymlinks); ok && !seen[root] {
				seen[root] = true
				out = append(out, f)
				count++
			}
			continue
		}
		rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil || count >= maxIntegrityFiles {
				return filepath.SkipAll
			}
			if d.IsDir() {
				if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth > maxIntegrityDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if seen[path] {
				return nil
			}
			if f, ok := describeIntegrityFileOpt(path, cfg.FollowSymlinks); ok {
				seen[path] = true
				out = append(out, f)
				count++
			}
			return nil
		})
	}
	// Registry keys ride along as pseudo-files: one entry per key whose
	// hash covers its values and subkey names, so the server's diff
	// reports a changed key the way it reports a changed file.
	for _, f := range collectRegistryIntegrity(cfg.RegistryKeys) {
		if !seen[f.Path] {
			seen[f.Path] = true
			out = append(out, f)
		}
	}

	// Stable order so the server's diff compares like with like rather
	// than reporting filesystem iteration order as change.
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func describeIntegrityFile(path string) (proto.IntegrityFile, bool) {
	return describeIntegrityFileOpt(path, false)
}

// describeIntegrityFileOpt is describeIntegrityFile with the watchlist's
// follow-symlinks choice: when set, a symlink is described by what it
// points at (contents hashed), while the target it names is still kept so
// a repointed link remains a visible change.
func describeIntegrityFileOpt(path string, followSymlinks bool) (proto.IntegrityFile, bool) {
	// Lstat, not Stat: a symlink repointed at something else is itself a
	// change worth seeing, and following it would hide the swap.
	info, err := os.Lstat(path)
	if err != nil {
		return proto.IntegrityFile{}, false
	}
	if followSymlinks && info.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(path)
		if tinfo, err := os.Stat(path); err == nil && tinfo.Mode().IsRegular() {
			f := proto.IntegrityFile{Path: path, Size: tinfo.Size(), Mode: tinfo.Mode().String(),
				Modified: tinfo.ModTime().UTC().Format(time.RFC3339), SymlinkTarget: target}
			f.Owner, f.Group = fileOwner(tinfo)
			if tinfo.Size() <= maxIntegrityBytes {
				if sum, err := hashFile(path); err == nil {
					f.Hash = sum
				}
			}
			return f, true
		}
	}
	f := proto.IntegrityFile{
		Path:     path,
		Size:     info.Size(),
		Mode:     info.Mode().String(),
		Modified: info.ModTime().UTC().Format(time.RFC3339),
	}
	f.Owner, f.Group = fileOwner(info)

	if info.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			f.SymlinkTarget = target
		}
		return f, true
	}
	if !info.Mode().IsRegular() {
		return f, true
	}
	if info.Size() > maxIntegrityBytes {
		f.Hash = "" // too big to hash; size and mtime still catch a change
		return f, true
	}
	if sum, err := hashFile(path); err == nil {
		f.Hash = sum
	}
	return f, true
}

func hashFile(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
