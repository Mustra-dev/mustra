package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensorbuild"
	"github.com/mustra-dev/mustra/internal/store"
)

// Serialize cache publication so concurrent saves cannot compile the same revision twice.
var goBuildMu sync.Mutex
var goArtifactID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func goArtifactPath(key string) string { return filepath.Join(packageFileDir(), "go-sensors", key) }
func goRequest(c store.CustomSensor, platform, arch string) sensorbuild.Request {
	return sensorbuild.Request{Source: c.Commands[platform], OS: platform, Arch: arch}
}
func readGoArtifact(key string) ([]byte, error) {
	p := goArtifactPath(key)
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.Size() <= 0 || st.Size() > sensorbuild.MaxArtifact {
		return nil, fmt.Errorf("oversized Go artifact")
	}
	return os.ReadFile(p)
}
func (s *Server) buildGoSensors(ctx context.Context, c store.CustomSensor) error {
	hasGo := false
	for platform, source := range c.Commands {
		hasGo = hasGo || (c.Platform(platform).Language == "go" && strings.TrimSpace(source) != "")
	}
	if !hasGo {
		return nil
	}
	if !goBuildMu.TryLock() {
		return fmt.Errorf("Go builder busy; retry shortly (previous sensor retained)")
	}
	defer goBuildMu.Unlock()
	for _, platform := range []string{"linux", "darwin", "windows"} {
		if c.Platform(platform).Language != "go" || strings.TrimSpace(c.Commands[platform]) == "" {
			continue
		}
		for _, arch := range []string{"amd64", "arm64"} {
			r := goRequest(c, platform, arch)
			key := sensorbuild.Key(r)
			if _, err := readGoArtifact(key); err == nil {
				continue
			}
			var result sensorbuild.Result
			if err := s.callScriptTools(ctx, "build", r, &result); err != nil {
				return fmt.Errorf("Go build %s/%s unavailable; previous sensor retained: %w", platform, arch, err)
			}
			if result.Error != "" {
				return fmt.Errorf("Go build: %s", result.Error)
			}
			if len(result.Data) == 0 || len(result.Data) > sensorbuild.MaxArtifact {
				return fmt.Errorf("invalid Go build artifact")
			}
			entries, _ := os.ReadDir(filepath.Dir(goArtifactPath(key)))
			var used int64
			for _, entry := range entries {
				if info, e := entry.Info(); e == nil {
					used += info.Size()
				}
			}
			if used+int64(len(result.Data)) > 1<<30 {
				return fmt.Errorf("Go artifact cache exceeds 1 GiB; remove expired revisions before retrying")
			}
			if err := os.MkdirAll(filepath.Dir(goArtifactPath(key)), 0700); err != nil {
				return err
			}
			f, err := os.CreateTemp(filepath.Dir(goArtifactPath(key)), ".build-")
			if err != nil {
				return err
			}
			name := f.Name()
			_, err = f.Write(result.Data)
			closeErr := f.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil {
				err = os.Rename(name, goArtifactPath(key))
			}
			os.Remove(name)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Server) goSensorArtifact(ctx context.Context, c store.CustomSensor, platform, arch string) (*proto.SensorArtifact, error) {
	if arch != "amd64" && arch != "arm64" {
		return nil, fmt.Errorf("unsupported architecture")
	}
	key := sensorbuild.Key(goRequest(c, platform, arch))
	now := time.Now()
	_ = os.Chtimes(goArtifactPath(key), now, now)
	data, err := readGoArtifact(key)
	if err != nil {
		return nil, err
	}
	base, err := s.agentPublicURLOrEmpty(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(base) == "" {
		return nil, fmt.Errorf("agent console URL is not configured")
	}
	tok := s.dlTokens.mint("go:" + key)
	if tok == "" {
		return nil, fmt.Errorf("download token unavailable")
	}
	return &proto.SensorArtifact{OS: platform, Arch: arch, File: proto.PackageFileRef{Name: "sensor.bin", Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), URL: strings.TrimRight(base, "/") + "/sensor-artifacts/" + key + "?t=" + tok}}, nil
}
func (s *Server) handleGoSensorArtifact(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !goArtifactID.MatchString(key) || !s.dlTokens.valid(r.URL.Query().Get("t"), "go:"+key) {
		http.Error(w, "invalid download token", http.StatusForbidden)
		return
	}
	serveAsDownload(w, r, goArtifactPath(key), "sensor.bin")
}

// Retain active revisions indefinitely and superseded/test artifacts for 30 days.
// Cleanup runs only after a successful save, so failed edits never evict rollout artifacts.
func (s *Server) cleanupGoArtifacts(ctx context.Context) {
	if !goBuildMu.TryLock() {
		return
	}
	defer goBuildMu.Unlock()
	defs, err := s.store.ListCustomSensors(ctx)
	if err != nil {
		return
	}
	active := map[string]bool{}
	for _, c := range defs {
		for _, platform := range []string{"linux", "darwin", "windows"} {
			if c.Platform(platform).Language != "go" {
				continue
			}
			for _, arch := range []string{"amd64", "arm64"} {
				active[sensorbuild.Key(goRequest(c, platform, arch))] = true
			}
		}
	}
	revisions, err := s.store.ListDeployRevisions(ctx, "")
	if err != nil {
		return
	}
	for _, revision := range revisions {
		_ = walkDeployChecks(&revision.Definition, func(check *proto.DeployCheck, os string) error {
			if check.Sensor != nil {
				for platform, definition := range check.Sensor.Definitions {
					if definition.Platform.Language == "go" {
						c := store.CustomSensor{Commands: map[string]string{platform: definition.Command}}
						for _, arch := range []string{"amd64", "arm64"} {
							active[sensorbuild.Key(goRequest(c, platform, arch))] = true
						}
					}
				}
			}
			return nil
		}, func(script *proto.DeployScript, os string) error {
			if script.Language == "go" {
				c := store.CustomSensor{Commands: map[string]string{os: script.Source}}
				for _, arch := range []string{"amd64", "arm64"} {
					active[sensorbuild.Key(goRequest(c, os, arch))] = true
				}
			}
			return nil
		})
	}
	entries, _ := os.ReadDir(filepath.Dir(goArtifactPath("unused")))
	for _, e := range entries {
		if active[e.Name()] || !goArtifactID.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err == nil && time.Since(info.ModTime()) > 30*24*time.Hour {
			_ = os.Remove(goArtifactPath(e.Name()))
		}
	}
}

func retainGoRevision(c store.CustomSensor) {
	now := time.Now()
	for _, platform := range []string{"linux", "darwin", "windows"} {
		if c.Platform(platform).Language != "go" {
			continue
		}
		for _, arch := range []string{"amd64", "arm64"} {
			path := goArtifactPath(sensorbuild.Key(goRequest(c, platform, arch)))
			_ = os.Chtimes(path, now, now)
		}
	}
}
