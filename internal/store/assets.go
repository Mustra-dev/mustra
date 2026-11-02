package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// AssetAttribute is a field an operator maintains about an endpoint that
// no sensor can report: who owns it, which cost centre pays for it,
// whether it may be rebooted during the day.
type AssetAttribute struct {
	ID          string    `json:"id"`
	Name        string    `json:"name" api:"required"`
	Label       string    `json:"label"`
	Kind        string    `json:"kind"`
	Options     []string  `json:"options"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by" api:"readonly"`
	CreatedAt   time.Time `json:"created_at" api:"readonly"`
	UpdatedAt   time.Time `json:"updated_at" api:"readonly"`
}

// attrNamePattern keeps an attribute's name usable as a targeting key:
// it becomes "attr.<name>" in a computer-group rule, so it cannot carry a
// dot, a space, or anything a rule parser would have to guess about.
var attrNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,38}$`)

// ValidAttributeName reports whether a name can be a targeting key.
func ValidAttributeName(name string) bool { return attrNamePattern.MatchString(name) }

// ValidAttributeKind reports whether a kind is one this store understands.
func ValidAttributeKind(kind string) bool {
	switch kind {
	case "text", "number", "date", "boolean", "select":
		return true
	}
	return false
}

const assetAttrColumns = `id, name, label, kind, options, description, created_by, created_at, updated_at`

func (s *Store) ListAssetAttributes(ctx context.Context) ([]AssetAttribute, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+assetAttrColumns+` FROM asset_attributes ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list asset attributes: %w", err)
	}
	defer rows.Close()
	out := []AssetAttribute{}
	for rows.Next() {
		var a AssetAttribute
		if err := rows.Scan(&a.ID, &a.Name, &a.Label, &a.Kind, &a.Options, &a.Description, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan asset attribute: %w", err)
		}
		if a.Options == nil {
			a.Options = []string{}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAssetAttribute(ctx context.Context, id string) (*AssetAttribute, error) {
	list, err := s.ListAssetAttributes(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id || list[i].Name == id {
			return &list[i], nil
		}
	}
	return nil, nil
}

func (s *Store) UpsertAssetAttribute(ctx context.Context, a AssetAttribute) error {
	if a.Options == nil {
		a.Options = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO asset_attributes (`+assetAttrColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, label=EXCLUDED.label, kind=EXCLUDED.kind,
		options=EXCLUDED.options, description=EXCLUDED.description, updated_at=now()`,
		a.ID, a.Name, a.Label, a.Kind, a.Options, a.Description, a.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert asset attribute: %w", err)
	}
	return nil
}

func (s *Store) DeleteAssetAttribute(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM asset_attributes WHERE id = $1`, id)
	return err
}

// SetAssetAttributeValue records one endpoint's value; an empty value
// clears it rather than storing a blank, so "not set" and "set to nothing"
// stay the same thing.
func (s *Store) SetAssetAttributeValue(ctx context.Context, agentID, attributeID, value, who string) error {
	if strings.TrimSpace(value) == "" {
		_, err := s.pool.Exec(ctx, `DELETE FROM asset_attribute_values WHERE agent_id = $1 AND attribute_id = $2`, agentID, attributeID)
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO asset_attribute_values (agent_id, attribute_id, value, set_by, set_at)
		VALUES ($1,$2,$3,$4,now())
		ON CONFLICT (agent_id, attribute_id) DO UPDATE SET value = EXCLUDED.value, set_by = EXCLUDED.set_by, set_at = now()`,
		agentID, attributeID, value, who)
	if err != nil {
		return fmt.Errorf("set asset attribute value: %w", err)
	}
	return nil
}

// AttributeValuesByAgent returns attribute name -> value for every
// endpoint, in one query. Targeting and exports both need the whole fleet's
// values at once; asking per endpoint would be a query per row.
func (s *Store) AttributeValuesByAgent(ctx context.Context) (map[string]map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT v.agent_id, a.name, v.value
		FROM asset_attribute_values v JOIN asset_attributes a ON a.id = v.attribute_id`)
	if err != nil {
		return nil, fmt.Errorf("attribute values: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]string{}
	for rows.Next() {
		var agentID, name, value string
		if err := rows.Scan(&agentID, &name, &value); err != nil {
			return nil, fmt.Errorf("scan attribute value: %w", err)
		}
		if out[agentID] == nil {
			out[agentID] = map[string]string{}
		}
		out[agentID][name] = value
	}
	return out, rows.Err()
}

// AttributeValuesFor returns one endpoint's values, keyed by attribute id.
func (s *Store) AttributeValuesFor(ctx context.Context, agentID string) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT attribute_id, value FROM asset_attribute_values WHERE agent_id = $1`, agentID)
	if err != nil {
		return nil, fmt.Errorf("attribute values for agent: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, v string
		if err := rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, rows.Err()
}

// --- retention -------------------------------------------------------------

// RetireOfflineAgents marks endpoints unmanaged once they have been quiet
// for longer than offlineFor. It does not delete: the row, its sensor
// history and everything recorded about it stay, because what a
// decommissioned machine was running is exactly the question somebody asks
// months later. Returns how many were retired.
func (s *Store) RetireOfflineAgents(ctx context.Context, offlineFor time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE agents SET managed = false, retired_at = now(), retired_reason = 'offline'
WHERE managed
  AND coalesce(last_heartbeat, first_seen) < now() - $1::interval`, offlineFor)
	if err != nil {
		return 0, fmt.Errorf("retire offline agents: %w", err)
	}
	return tag.RowsAffected(), nil
}

// UnretireAgent brings an endpoint back into management. Called when a
// retired agent registers or heartbeats again: it is plainly there.
func (s *Store) UnretireAgent(ctx context.Context, agentID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE agents SET managed = true, retired_at = NULL, retired_reason = '' WHERE agent_id = $1 AND NOT managed`, agentID)
	if err != nil {
		return false, fmt.Errorf("unretire agent: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// SetAgentManaged retires or restores one endpoint by hand.
func (s *Store) SetAgentManaged(ctx context.Context, agentID string, managed bool, reason string) error {
	var err error
	if managed {
		_, err = s.pool.Exec(ctx, `UPDATE agents SET managed = true, retired_at = NULL, retired_reason = '' WHERE agent_id = $1`, agentID)
	} else {
		_, err = s.pool.Exec(ctx, `UPDATE agents SET managed = false, retired_at = now(), retired_reason = $2 WHERE agent_id = $1`, agentID, reason)
	}
	if err != nil {
		return fmt.Errorf("set agent managed: %w", err)
	}
	return nil
}

// PurgeRetiredAgents deletes rows retired longer ago than purgeAfter. This
// is the only path that still destroys inventory, and it is deliberately
// separate from retiring: forgetting an endpoint is a different decision
// from noticing it went away.
func (s *Store) PurgeRetiredAgents(ctx context.Context, purgeAfter time.Duration) (int64, error) {
	if purgeAfter <= 0 {
		return 0, nil // never
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM agents WHERE NOT managed AND retired_at IS NOT NULL AND retired_at < now() - $1::interval`, purgeAfter)
	if err != nil {
		return 0, fmt.Errorf("purge retired agents: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RetiredAgentCount is how many endpoints are being kept but not managed.
func (s *Store) RetiredAgentCount(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM agents WHERE NOT managed`).Scan(&n)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("retired agent count: %w", err)
	}
	return n, nil
}
