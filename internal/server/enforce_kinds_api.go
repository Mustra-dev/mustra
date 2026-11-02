package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/enforcekinds"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"

	"github.com/mustra-dev/mustra/internal/server/vault"
)

// Typed Enforce policies and what surrounds them: the kind catalogue and
// compile preview the editor uses, BitLocker recovery-key escrow fed by
// the security posture sensor, and fleet coverage computed from the same
// sensor.

// enforceKindsResponse is what GET /api/enforce/kinds answers.
type enforceKindsResponse struct {
	Kinds []enforcekinds.Info `json:"kinds"`
}

func (s *Server) handleEnforceKinds(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, enforceKindsResponse{Kinds: enforcekinds.Kinds()})
}

// enforceCompileRequest is the body of POST /api/enforce/compile.
type enforceCompileRequest struct {
	Kind   string          `json:"kind" api:"required"`
	Config json.RawMessage `json:"config" api:"required"`
}

// enforceCompileResponse is what POST /api/enforce/compile answers.
type enforceCompileResponse struct {
	Settings []proto.EnforceSetting `json:"settings"`
}

// handleEnforceCompile shows an author what a typed policy turns into
// before it is saved: the exact rules and fixes the endpoint will run.
func (s *Server) handleEnforceCompile(w http.ResponseWriter, r *http.Request) {
	var req enforceCompileRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	settings, err := enforcekinds.Compile(enforcekinds.Kind(req.Kind), req.Config)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSONResponse(w, enforceCompileResponse{Settings: settings})
}

// --- recovery key escrow -------------------------------------------

// escrowRecoveryKeys stores the recovery passwords a posture snapshot
// carries and returns the snapshot with them removed, so the sensor cache
// never holds a password. With no vault configured the passwords are
// dropped, loudly: storing them in the clear is not an option.
func (s *Server) escrowRecoveryKeys(ctx context.Context, snap proto.SensorSnapshot) json.RawMessage {
	var rows []proto.SecurityPosture
	if json.Unmarshal(snap.Data, &rows) != nil || len(rows) == 0 || len(rows[0].RecoveryKeys) == 0 {
		return snap.Data
	}
	keys := rows[0].RecoveryKeys
	rows[0].RecoveryKeys = nil
	if s.vault == nil {
		s.logger.Warn("bitlocker recovery keys received but no credential encryption key is configured; not stored",
			"agent_id", snap.AgentID, "keys", len(keys))
	} else {
		for _, k := range keys {
			enc, err := s.vault.Seal(k.Password, vault.BitLockerAAD(snap.AgentID, k.KeyID))
			if err != nil {
				s.logger.Warn("encrypt recovery key", "agent_id", snap.AgentID, "error", err)
				continue
			}
			if err := s.store.UpsertBitLockerKey(ctx, store.BitLockerKey{AgentID: snap.AgentID, Mount: k.Mount, KeyID: k.KeyID, PasswordEnc: enc}); err != nil {
				s.logger.Warn("escrow recovery key", "agent_id", snap.AgentID, "error", err)
			}
		}
	}
	stripped, err := json.Marshal(rows)
	if err != nil {
		return snap.Data
	}
	return stripped
}

// recoveryKeyView is an entry of what GET /api/enforce/recovery-keys
// answers.
type recoveryKeyView struct {
	store.BitLockerKey
	Hostname string `json:"hostname"`
}

// listRecoveryKeysResponse is what GET /api/enforce/recovery-keys answers.
type listRecoveryKeysResponse struct {
	CanReveal       bool              `json:"can_reveal"`
	EscrowAvailable bool              `json:"escrow_available"`
	Keys            []recoveryKeyView `json:"keys"`
}

func (s *Server) handleListRecoveryKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListBitLockerKeys(r.Context(), r.URL.Query().Get("agent"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	u := auth.CurrentUser(r.Context())
	canReveal := false
	if u != nil {
		ok, err := s.auth.HasPermission(r.Context(), u, auth.PermRecoveryKeys)
		canReveal = err == nil && ok
	}
	hostnames := map[string]string{}
	if agents, err := s.store.ListAgents(r.Context(), s.staleAfter()); err == nil {
		for _, a := range agents {
			hostnames[a.AgentID] = a.Hostname
		}
	}
	out := make([]recoveryKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, recoveryKeyView{BitLockerKey: k, Hostname: hostnames[k.AgentID]})
	}
	writeJSONResponse(w, listRecoveryKeysResponse{Keys: out, CanReveal: canReveal, EscrowAvailable: s.vault != nil})
}

// revealRecoveryKeyResponse is what POST
// /api/enforce/recovery-keys/{agent}/{key}/reveal answers.
type revealRecoveryKeyResponse struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	KeyID    string `json:"key_id"`
	Mount    string `json:"mount"`
	Password string `json:"password"`
}

// handleRevealRecoveryKey returns one recovery password to a user holding
// enforce.recovery_keys, and records who read which key for which machine
// -- a recovery password unlocks a disk, and the record of who saw it is
// the whole reason it may be stored here at all.
func (s *Server) handleRevealRecoveryKey(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		http.Error(w, "no credential encryption key is configured, so no recovery keys are escrowed", 503)
		return
	}
	agentID, keyID := r.PathValue("agent"), r.PathValue("key")
	key, err := s.store.GetBitLockerKey(r.Context(), agentID, keyID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if key == nil {
		http.NotFound(w, r)
		return
	}
	password, _, err := s.vault.Open(key.PasswordEnc, vault.BitLockerAAD(key.AgentID, key.KeyID))
	if err != nil {
		http.Error(w, "the escrowed key could not be decrypted with the current credential encryption key", 500)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	hostname := agentID
	if agents, err := s.store.ListAgents(r.Context(), s.staleAfter()); err == nil {
		for _, a := range agents {
			if a.AgentID == agentID {
				hostname = a.Hostname
			}
		}
	}
	s.audit(r.Context(), auditEvent{Action: "bitlocker.key_view", Actor: who, Target: hostname, AgentID: agentID, Severity: "warning",
		Detail: map[string]any{"key_id": keyID, "mount": key.Mount}})
	writeJSONResponse(w, revealRecoveryKeyResponse{AgentID: agentID, Hostname: hostname, Mount: key.Mount, KeyID: keyID, Password: password})
}

// --- coverage --------------------------------------------------------

type coverageCounts struct {
	Reporting int `json:"reporting"`
	Firewall  int `json:"firewall"`
	Encrypted int `json:"encrypted"`
	Antivirus int `json:"antivirus"`
	AppCtrl   int `json:"app_control"`
	Escrowed  int `json:"escrowed"`
}

// enforceCoverageEndpoint is an entry of what GET /api/enforce/coverage
// answers.
type enforceCoverageEndpoint struct {
	AgentID     string    `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	CollectedAt time.Time `json:"collected_at"`
	proto.SecurityPosture
	Escrowed bool `json:"escrowed"`
}

// enforceCoverageResponse is what GET /api/enforce/coverage answers.
type enforceCoverageResponse struct {
	All       coverageCounts            `json:"all"`
	Endpoints []enforceCoverageEndpoint `json:"endpoints"`
	Windows   coverageCounts            `json:"windows"`
}

// handleEnforceCoverage is the "coverage" view: of the endpoints
// that report a posture, how many have a firewall on, an encrypted OS
// volume, real-time antimalware, application control enforcing, and a
// recovery key escrowed. Windows is broken out because three of the five
// only exist there.
func (s *Server) handleEnforceCoverage(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListSensorDataForSensor(r.Context(), string(proto.SensorSecurityPosture))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	escrowed := map[string]bool{}
	if keys, err := s.store.ListBitLockerKeys(r.Context(), ""); err == nil {
		for _, k := range keys {
			escrowed[k.AgentID] = true
		}
	}
	all, windows := coverageCounts{}, coverageCounts{}
	var endpoints []enforceCoverageEndpoint
	for _, row := range rows {
		var ps []proto.SecurityPosture
		if json.Unmarshal(row.Data, &ps) != nil || len(ps) == 0 {
			continue
		}
		p := ps[0]
		p.RecoveryKeys = nil
		e := enforceCoverageEndpoint{AgentID: row.AgentID, Hostname: row.Hostname, OS: row.OS, CollectedAt: row.CollectedAt, SecurityPosture: p, Escrowed: escrowed[row.AgentID]}
		endpoints = append(endpoints, e)
		for _, c := range []*coverageCounts{&all, ifWindows(row.OS, &windows)} {
			if c == nil {
				continue
			}
			c.Reporting++
			if p.FirewallEnabled {
				c.Firewall++
			}
			if p.OSVolumeEncrypted {
				c.Encrypted++
			}
			if p.AntivirusRealtime {
				c.Antivirus++
			}
			if p.AppControlMode == "enforce" {
				c.AppCtrl++
			}
			if escrowed[row.AgentID] {
				c.Escrowed++
			}
		}
	}
	if endpoints == nil {
		endpoints = []enforceCoverageEndpoint{}
	}
	writeJSONResponse(w, enforceCoverageResponse{All: all, Windows: windows, Endpoints: endpoints})
}

func ifWindows(os string, c *coverageCounts) *coverageCounts {
	if strings.EqualFold(os, "windows") {
		return c
	}
	return nil
}
