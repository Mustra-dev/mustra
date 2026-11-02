package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

type DeployReference struct {
	Key          string            `json:"key"`
	Kind         string            `json:"kind"`
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	URL          string            `json:"url"`
	Operation    string            `json:"operation"`
	OS           string            `json:"os"`
	FollowLatest bool              `json:"follow_latest"`
	Fingerprint  string            `json:"fingerprint"`
	Compatible   bool              `json:"compatible"`
	Reason       string            `json:"reason,omitempty"`
	Parameters   map[string]string `json:"-"`
	Original     json.RawMessage   `json:"-"`
	Step         int               `json:"-"`
}

func (s *Store) DeployReferences(ctx context.Context, revision string) ([]DeployReference, error) {
	out := []DeployReference{}
	rev, e := s.GetDeployRevision(ctx, revision)
	if e != nil {
		return nil, e
	}
	if rev == nil {
		return nil, fmt.Errorf("version not found")
	}
	pkg, e := s.GetSoftwarePackage(ctx, rev.PackageID)
	if e != nil {
		return nil, e
	}
	if pkg == nil {
		return nil, fmt.Errorf("package not found")
	}
	rows, e := s.pool.Query(ctx, `SELECT to_jsonb(a) FROM scheduled_actions a WHERE package_id=$1 AND (revision_id=$2 AND NOT follow_latest OR (follow_latest OR revision_id='') AND $3)`, rev.PackageID, revision, pkg.DeployRevision == revision)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return nil, e
		}
		var a ScheduledAction
		if e = json.Unmarshal(raw, &a); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, DeployReference{Key: "schedule:" + a.ID, Kind: "schedule", ID: a.ID, Name: a.Name, URL: "/software?schedule=" + a.ID + "#schedules", Operation: a.Operation, OS: a.TargetOS, FollowLatest: a.FollowLatest, Parameters: a.Parameters, Original: raw})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	rows, e = s.pool.Query(ctx, `SELECT to_jsonb(p) FROM playbooks p WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(p.steps) st WHERE st->>'package_id'=$1)`, rev.PackageID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		var p Playbook
		if e = json.Unmarshal(raw, &p); e != nil {
			return nil, e
		}
		var steps []struct {
			PackageID    string            `json:"package_id"`
			RevisionID   string            `json:"revision_id"`
			FollowLatest bool              `json:"follow_latest"`
			Operation    string            `json:"operation"`
			Params       map[string]string `json:"params"`
			Name         string            `json:"name"`
		}
		if e = json.Unmarshal(p.Steps, &steps); e != nil {
			return nil, e
		}
		for i, st := range steps {
			if st.PackageID != rev.PackageID {
				continue
			}
			latest := st.FollowLatest || st.RevisionID == ""
			if (!latest && st.RevisionID != revision) || (latest && pkg.DeployRevision != revision) {
				continue
			}
			op := st.Operation
			if op == "" {
				op = "install"
				if pkg.Kind == KindAction {
					op = "run"
				}
			}
			out = append(out, DeployReference{Key: fmt.Sprintf("playbook:%s:%d", p.ID, i), Kind: "playbook", ID: p.ID, Step: i, Name: fmt.Sprintf("%s — step %d: %s", p.Name, i+1, st.Name), URL: "/playbooks?edit=" + p.ID + "#library", Operation: op, OS: p.OS, FollowLatest: latest, Parameters: st.Params, Original: raw})
		}
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	for i := range out {
		out[i].Fingerprint = fmt.Sprintf("%x", sha256.Sum256(append([]byte(out[i].Key), out[i].Original...)))
	}
	return out, nil
}

// Compare full owner snapshots, and apply all selected updates atomically. The
// replacement row lock prevents retirement between validation and commit.
func (s *Store) UpdateDeployReferences(ctx context.Context, source, replacement, actor string, refs []DeployReference) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var valid bool
	e = tx.QueryRow(ctx, `SELECT published AND NOT retired AND package_id=(SELECT package_id FROM deploy_revisions WHERE id=$2) FROM deploy_revisions WHERE id=$1 FOR SHARE`, replacement, source).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		return fmt.Errorf("replacement is no longer active")
	}
	groups := map[string][]DeployReference{}
	for _, r := range refs {
		groups[r.Kind+":"+r.ID] = append(groups[r.Kind+":"+r.ID], r)
	}
	for _, group := range groups {
		r := group[0]
		var n int64
		if r.Kind == "schedule" {
			tag, e := tx.Exec(ctx, `UPDATE scheduled_actions a SET revision_id=$2,follow_latest=false WHERE id=$1 AND to_jsonb(a)=$3::jsonb`, r.ID, replacement, r.Original)
			if e != nil {
				return e
			}
			n = tag.RowsAffected()
		} else if r.Kind == "playbook" {
			var owner struct {
				Steps []map[string]any `json:"steps"`
			}
			if e = json.Unmarshal(r.Original, &owner); e != nil {
				return e
			}
			for _, ref := range group {
				owner.Steps[ref.Step]["revision_id"] = replacement
				owner.Steps[ref.Step]["follow_latest"] = false
			}
			raw, e := json.Marshal(owner.Steps)
			if e != nil {
				return e
			}
			tag, e := tx.Exec(ctx, `UPDATE playbooks p SET steps=$2,updated_by=$4,updated_at=now() WHERE id=$1 AND to_jsonb(p)=$3::jsonb`, r.ID, raw, r.Original, actor)
			if e != nil {
				return e
			}
			n = tag.RowsAffected()
		}
		if n != 1 {
			return fmt.Errorf("%s changed since preview; refresh before updating references", r.Name)
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) RetireDeployRevision(ctx context.Context, id string, entirePackage bool, note, by string) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var pkg string
	if e = tx.QueryRow(ctx, `SELECT p.id FROM software_packages p JOIN deploy_revisions r ON r.package_id=p.id WHERE r.id=$1 AND r.published FOR UPDATE OF p`, id).Scan(&pkg); e != nil {
		return e
	}
	// Already-retired versions keep the note and time they were retired with.
	if _, e = tx.Exec(ctx, `UPDATE deploy_revisions SET retired=true, retired_note=$4, retired_by=$5, retired_at=now() WHERE package_id=$2 AND published AND NOT retired AND (id=$1 OR $3)`, id, pkg, entirePackage, note, by); e != nil {
		return e
	}
	// A Self Service pin on a version just retired is cleared, so Self
	// Service falls back to the package's current version rather than
	// offering one that can no longer be installed.
	_, e = tx.Exec(ctx, `UPDATE software_packages SET deploy_revision=coalesce((SELECT id FROM deploy_revisions WHERE package_id=$1 AND published AND NOT retired ORDER BY created_at DESC LIMIT 1),deploy_revision),enabled=CASE WHEN $2 THEN false ELSE enabled END,self_service_revision=CASE WHEN self_service_revision IN (SELECT id FROM deploy_revisions WHERE package_id=$1 AND retired) THEN '' ELSE self_service_revision END,updated_at=now() WHERE id=$1`, pkg, entirePackage)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
