package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/updatesig"
	"github.com/mustra-dev/mustra/internal/version"

	"github.com/mustra-dev/mustra/internal/server/vault"
)

// The deployment's agent update signing key.
//
// Where it comes from, first match wins:
//
//  1. MUSTRA_AGENT_SIGNING_KEY (base64 32-byte ed25519 seed; init.sh
//     writes one into .env, which is 0600) or MUSTRA_AGENT_SIGNING_KEY_FILE.
//  2. MUSTRA_AGENT_SIGNING_PUBKEY alone: a release-signed setup. The key
//     never reaches this server; it serves the `<binary>.sig` manifests
//     shipped beside the binaries and refuses to sign anything itself.
//  3. Generated on first start and stored in the settings table, encrypted
//     with the credential vault key when one is configured.
//
// Agents pin the public half at enrollment, so rotating it means
// re-enrolling: deliberate, because a key that could be swapped over the
// same channel it protects would protect nothing.

func (s *Server) loadSigningKey(ctx context.Context, t *agentTrust) error {
	seed := trustEnv("MUSTRA_AGENT_SIGNING_KEY")
	if path := trustEnv("MUSTRA_AGENT_SIGNING_KEY_FILE"); seed == "" && path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read MUSTRA_AGENT_SIGNING_KEY_FILE: %w", err)
		}
		seed = strings.TrimSpace(string(raw))
	}
	if seed != "" {
		key, err := updatesig.ParsePrivateKey(seed)
		if err != nil {
			return fmt.Errorf("MUSTRA_AGENT_SIGNING_KEY: %w", err)
		}
		t.signKey, t.signPub = key, key.Public().(ed25519.PublicKey)
		return nil
	}
	if pub := trustEnv("MUSTRA_AGENT_SIGNING_PUBKEY"); pub != "" {
		key, err := updatesig.ParsePublicKey(pub)
		if err != nil {
			return fmt.Errorf("MUSTRA_AGENT_SIGNING_PUBKEY: %w", err)
		}
		t.signPub = key
		s.logger.Info("agent updates are release-signed; serving pre-signed manifests only", "key_id", updatesig.KeyID(key))
		return nil
	}
	stored, err := s.store.GetSetting(ctx, settingUpdateSigningKey)
	if err != nil {
		return err
	}
	if stored == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		enc := base64.StdEncoding.EncodeToString(priv.Seed())
		stored = "plain:" + enc
		if s.vault != nil {
			ct, err := s.vault.Seal(enc, vault.SettingAAD(settingUpdateSigningKey))
			if err != nil {
				return err
			}
			stored = "vault:" + base64.StdEncoding.EncodeToString(ct)
		} else {
			s.logger.Warn("no credential encryption key: the generated agent update signing key is stored unencrypted in the database. " +
				"Set MUSTRA_AGENT_SIGNING_KEY (deploy/init.sh does) to keep it out of the database and its backups.")
		}
		if err := s.store.SetSettingIfAbsent(ctx, settingUpdateSigningKey, stored, "system"); err != nil {
			return err
		}
		// Another instance may have won the race; use whatever is stored.
		if stored, err = s.store.GetSetting(ctx, settingUpdateSigningKey); err != nil {
			return err
		}
		s.logger.Info("generated this deployment's agent update signing key")
	}
	var seedText string
	switch {
	case strings.HasPrefix(stored, "plain:"):
		seedText = strings.TrimPrefix(stored, "plain:")
	case strings.HasPrefix(stored, "vault:"):
		if s.vault == nil {
			return errors.New("the agent update signing key is vault-encrypted but no credential encryption key is configured")
		}
		ct, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, "vault:"))
		if err != nil {
			return fmt.Errorf("stored signing key: %w", err)
		}
		var legacy bool
		if seedText, legacy, err = s.vault.Open(ct, vault.SettingAAD(settingUpdateSigningKey)); err != nil {
			return fmt.Errorf("decrypt stored signing key: %w", err)
		}
		if legacy {
			// Written before vault values were bound to their record:
			// re-seal it in place so it is bound from now on.
			if sealed, serr := s.vault.Seal(seedText, vault.SettingAAD(settingUpdateSigningKey)); serr == nil {
				if serr = s.store.SetSetting(ctx, settingUpdateSigningKey, "vault:"+base64.StdEncoding.EncodeToString(sealed), "system"); serr != nil {
					s.logger.Warn("could not re-seal the stored agent update signing key", "error", serr)
				}
			}
		}
	default:
		return errors.New("stored agent update signing key has an unknown format")
	}
	key, err := updatesig.ParsePrivateKey(seedText)
	if err != nil {
		return err
	}
	t.signKey, t.signPub = key, key.Public().(ed25519.PublicKey)
	return nil
}

// agentBuildPlatform maps a build filename to its platform.
func agentBuildPlatform(name string) (goos, goarch string, ok bool) {
	base := strings.TrimSuffix(name, ".exe")
	rest, found := strings.CutPrefix(base, "mustra-agent-")
	if !found {
		if rest, found = strings.CutPrefix(base, "mustra-tray-"); !found {
			return "", "", false
		}
	}
	parts := strings.Split(rest, "-")
	if len(parts) != 2 {
		return "", "", false
	}
	switch parts[0] {
	case "linux", "darwin", "windows":
	default:
		return "", "", false
	}
	switch parts[1] {
	case "amd64", "arm64":
	default:
		return "", "", false
	}
	if (parts[0] == "windows") != strings.HasSuffix(name, ".exe") {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// manifestCache keeps the digest of each build against its modification
// time, so hashing a 15 MB binary happens once per deploy.
var manifestCache sync.Map // path -> cachedManifest

type cachedManifest struct {
	modTime time.Time
	m       updatesig.Manifest
}

// buildManifest returns the signed manifest of one agent build: the
// release's pre-signed `<name>.sig` when present (and valid under the
// pinned key), otherwise one signed here. The manifest is general — no
// agent, no downgrade.
func (s *Server) buildManifest(name string) (updatesig.Manifest, error) {
	if s.trust == nil || s.trust.signPub == nil {
		return updatesig.Manifest{}, errors.New("no agent update signing key is configured")
	}
	goos, goarch, ok := agentBuildPlatform(name)
	if !ok {
		return updatesig.Manifest{}, fmt.Errorf("%s is not an agent build", name)
	}
	path := filepath.Join(s.agentBuildsDir(), name)
	fi, err := os.Stat(path)
	if err != nil {
		return updatesig.Manifest{}, fmt.Errorf("no such build: %s", name)
	}
	if raw, err := os.ReadFile(path + ".sig"); err == nil {
		m, err := updatesig.Unmarshal(raw)
		if err != nil {
			return updatesig.Manifest{}, err
		}
		if err := m.Verify(s.trust.signPub); err != nil {
			return updatesig.Manifest{}, fmt.Errorf("the shipped %s.sig: %w", name, err)
		}
		if m.File != name || m.OS != goos || m.Arch != goarch || m.AllowDowngrade {
			return updatesig.Manifest{}, fmt.Errorf("the shipped %s.sig describes a different build", name)
		}
		return m, nil
	}
	if s.trust.signKey == nil {
		return updatesig.Manifest{}, fmt.Errorf("%s has no pre-signed manifest and this server holds no signing key", name)
	}
	if hit, ok := manifestCache.Load(path); ok {
		if c := hit.(cachedManifest); c.modTime.Equal(fi.ModTime()) {
			return c.m, nil
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return updatesig.Manifest{}, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return updatesig.Manifest{}, err
	}
	m, err := updatesig.Sign(updatesig.Manifest{
		File: name, OS: goos, Arch: goarch, Version: version.Agent(),
		SHA256: hex.EncodeToString(h.Sum(nil)), Size: size,
	}, s.trust.signKey)
	if err != nil {
		return updatesig.Manifest{}, err
	}
	manifestCache.Store(path, cachedManifest{modTime: fi.ModTime(), m: m})
	return m, nil
}

func agentBuildName(goos, goarch string) string {
	name := "mustra-agent-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// updateOfferFor builds the signed update an endpoint may apply. When
// downgradeFor names an agent, the manifest additionally authorizes that
// one agent — and only it, for an hour — to move to an older build.
func (s *Server) updateOfferFor(ctx context.Context, goos, goarch, downgradeFor string) (*proto.UpdateOffer, error) {
	name := agentBuildName(goos, goarch)
	m, err := s.buildManifest(name)
	if err != nil {
		return nil, err
	}
	if downgradeFor != "" {
		if s.trust.signKey == nil {
			return nil, errors.New("a downgrade must be signed, and this server holds no signing key")
		}
		m.AllowDowngrade, m.AgentID, m.Expires = true, downgradeFor, time.Now().Add(time.Hour).Unix()
		if m, err = updatesig.Sign(m, s.trust.signKey); err != nil {
			return nil, err
		}
	}
	base, err := s.agentPublicURL(ctx)
	if err != nil {
		return nil, err
	}
	return &proto.UpdateOffer{BinaryURL: base + "/downloads/" + name + "?v=" + m.Version, Manifest: m}, nil
}
