package agent

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/proto"
	bolt "go.etcd.io/bbolt"
)

var deployBucket = []byte("deploy_jobs")

type deployState struct {
	ExecutionUser        string          `json:"execution_user,omitempty"`
	DownloadDeadline     time.Time       `json:"download_deadline,omitempty"`
	VerificationDeadline time.Time       `json:"verification_deadline,omitempty"`
	Workspace            string          `json:"workspace,omitempty"`
	Job                  proto.DeployJob `json:"job"`
	Status               string          `json:"status"`
	Done                 map[string]bool `json:"done"`
	Branches             map[string]bool `json:"branches"`
	ActiveStep           string          `json:"active_step,omitempty"`
	Cancel               bool            `json:"cancel"`
	RebootAt             uint64          `json:"reboot_at,omitempty"`
	Updated              time.Time       `json:"updated"`
}

func (s *Store) acceptDeploy(j proto.DeployJob) error {
	if j.ID == "" || len(j.Packages) == 0 {
		return fmt.Errorf("empty deployment")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(deployBucket)
		if e != nil {
			return e
		}
		if b.Get([]byte(j.ID)) != nil {
			return nil
		}
		st := deployState{Job: j, Status: "queued", Done: map[string]bool{}, Branches: map[string]bool{}, Updated: time.Now()}
		raw, e := json.Marshal(st)
		if e != nil {
			return e
		}
		return b.Put([]byte(j.ID), raw)
	})
}
func (s *Store) saveDeploy(st *deployState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(deployBucket)
		if e != nil {
			return e
		}
		var old deployState
		if raw := b.Get([]byte(st.Job.ID)); raw != nil {
			if e = json.Unmarshal(raw, &old); e != nil {
				return e
			}
			st.Cancel = st.Cancel || old.Cancel
		}
		st.Updated = time.Now()
		raw, e := json.Marshal(st)
		if e != nil {
			return e
		}
		return b.Put([]byte(st.Job.ID), raw)
	})
}
func (s *Store) cancelDeploy(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(deployBucket)
		if b == nil {
			return fmt.Errorf("unknown deployment")
		}
		var st deployState
		if e := json.Unmarshal(b.Get([]byte(id)), &st); e != nil {
			return e
		}
		st.Cancel = true
		raw, e := json.Marshal(st)
		if e != nil {
			return e
		}
		return b.Put([]byte(id), raw)
	})
}
func (s *Store) deployStates() ([]deployState, error) {
	out := []deployState{}
	e := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(deployBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var st deployState
			if e := json.Unmarshal(v, &st); e != nil {
				return e
			}
			if !deploy.Terminal(st.Status) {
				out = append(out, st)
			}
			return nil
		})
	})
	return out, e
}

func (s *Store) saveDeploySettings(settings proto.DeploySettings) error {
	raw, e := json.Marshal(settings)
	if e != nil {
		return e
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(metaBucket).Put([]byte("deploy_settings"), raw) })
}
func (s *Store) loadDeploySettings() (settings *proto.DeploySettings, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(metaBucket).Get([]byte("deploy_settings"))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &settings)
	})
	return
}
