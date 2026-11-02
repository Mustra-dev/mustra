package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Integrity watchlists, endpoint half.
//
// The built-in watched set (integrityPaths) is what every endpoint gets.
// A monitor on the server adds to it: the "watch" command carries the
// union of the watchlists covering this endpoint, the agent persists it,
// extends both the hash sweep and the real-time watcher with it, and
// reports the set's revision in every facts message so the server can see
// which endpoints have taken their monitors.
//
// Kept in an atomic pointer rather than on the Agent because the
// collectors that need it (collectIntegrity, watchDirs) are package
// functions called from several loops and from deploy checks.
var watchConfig atomic.Pointer[proto.WatchConfig]

// currentWatch returns the pushed set, or an empty one.
func currentWatch() proto.WatchConfig {
	if c := watchConfig.Load(); c != nil {
		return *c
	}
	return proto.WatchConfig{}
}

// extraWatchPaths are the pushed paths, cleaned and absolute; anything
// relative or empty is dropped rather than watched somewhere surprising.
func extraWatchPaths() []string {
	var out []string
	for _, p := range currentWatch().Paths {
		p = strings.TrimSpace(p)
		if p == "" || !filepath.IsAbs(p) {
			continue
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// loadWatchConfig restores a persisted set before the watchers start.
func (a *Agent) loadWatchConfig() {
	raw, err := a.store.LoadWatchConfig()
	if err != nil || len(raw) == 0 {
		return
	}
	var c proto.WatchConfig
	if json.Unmarshal(raw, &c) != nil {
		return
	}
	watchConfig.Store(&c)
	a.logger.Info("integrity watch set restored", "revision", c.Revision, "paths", len(c.Paths), "registry_keys", len(c.RegistryKeys))
}

// applyWatchConfig is the "watch" command: persist, swap in, and make
// both halves of integrity monitoring pick it up now — the watcher adds
// the new directories and the hash sweep runs so the server gets a
// baseline for the new paths at once rather than at the next interval.
func (a *Agent) applyWatchConfig(ctx context.Context, c proto.WatchConfig) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := a.store.SaveWatchConfig(raw); err != nil {
		return err
	}
	watchConfig.Store(&c)
	a.logger.Info("integrity watch set applied", "revision", c.Revision, "paths", len(c.Paths), "registry_keys", len(c.RegistryKeys), "follow_symlinks", c.FollowSymlinks)
	select {
	case a.watchRefresh <- struct{}{}:
	default:
	}
	go a.collectAndPublishSensor(context.WithoutCancel(ctx), proto.SensorIntegrity,
		func(ctx context.Context) (any, error) { return collectIntegrity(ctx) })
	go a.sendFacts(context.WithoutCancel(ctx))
	return nil
}
