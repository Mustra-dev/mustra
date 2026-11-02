package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// A custom sensor is operator-authored collection: a command per platform,
// run on a timer, whose output becomes a sensor like any built-in one.
//
// The built-in thirteen answer the questions everybody has. This is for the
// ones only you have -- "which of my machines still has that vendor agent
// installed", "what is in this config file" -- which no shipped sensor can
// anticipate.
type CustomSensor struct {
	Parameters    []proto.DeployParameter         `json:"parameters,omitempty"`
	Platforms     map[string]proto.SensorPlatform `json:"platforms"`
	Fields        []proto.SensorField             `json:"fields"`
	MaxAgeSeconds int                             `json:"max_age_seconds"`
	ID            string                          `json:"id"`
	Name          string                          `json:"name"`
	Description   string                          `json:"description"`
	// Commands is the command to run per runtime.GOOS. An OS with no entry
	// never runs it, which is how a Windows-only sensor stays invisible to
	// Linux hosts rather than failing on every collection.
	Commands map[string]string `json:"commands"`
	// IntervalSeconds and TimeoutSeconds are per-sensor because a custom
	// sensor is exactly where someone writes something far more expensive
	// than any built-in.
	IntervalSeconds int       `json:"interval_seconds"`
	TimeoutSeconds  int       `json:"timeout_seconds"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at" api:"readonly"`
	UpdatedAt       time.Time `json:"updated_at" api:"readonly"`
	CreatedBy       string    `json:"created_by" api:"readonly"`
}

// SensorKind is the sensor name this custom sensor publishes under. The
// prefix keeps operator-named sensors from ever colliding with a built-in
// one, now or after a future release adds a sensor with the same name.
func (c CustomSensor) SensorKind() string { return "custom_" + c.ID }

const customSensorColumns = `id, name, description, commands, interval_seconds,
       timeout_seconds, enabled, created_at, updated_at, created_by, platforms, fields, max_age_seconds, parameters`

func scanCustomSensor(row pgx.Row) (*CustomSensor, error) {
	var c CustomSensor
	var commands, platforms, fields, parameters []byte
	if err := row.Scan(&c.ID, &c.Name, &c.Description, &commands, &c.IntervalSeconds,
		&c.TimeoutSeconds, &c.Enabled, &c.CreatedAt, &c.UpdatedAt, &c.CreatedBy, &platforms, &fields, &c.MaxAgeSeconds, &parameters); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(commands, &c.Commands)
	_ = json.Unmarshal(platforms, &c.Platforms)
	_ = json.Unmarshal(fields, &c.Fields)
	_ = json.Unmarshal(parameters, &c.Parameters)
	if c.Commands == nil {
		c.Commands = map[string]string{}
	}
	return &c, nil
}

func (s *Store) ListCustomSensors(ctx context.Context) ([]CustomSensor, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+customSensorColumns+` FROM custom_sensors ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list custom sensors: %w", err)
	}
	defer rows.Close()
	var out []CustomSensor
	for rows.Next() {
		c, err := scanCustomSensor(rows)
		if err != nil {
			return nil, fmt.Errorf("scan custom sensor: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Store) GetCustomSensor(ctx context.Context, id string) (*CustomSensor, error) {
	c, err := scanCustomSensor(s.pool.QueryRow(ctx,
		`SELECT `+customSensorColumns+` FROM custom_sensors WHERE id = $1`, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get custom sensor: %w", err)
	}
	return c, nil
}

func (s *Store) UpsertCustomSensor(ctx context.Context, c CustomSensor) (*CustomSensor, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Block reference writes while checking the schema and publishing its replacement.
	if _, err = tx.Exec(ctx, `LOCK TABLE custom_sensors, computer_groups, saved_questions IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return nil, err
	}
	old, err := scanCustomSensor(tx.QueryRow(ctx, `SELECT `+customSensorColumns+` FROM custom_sensors WHERE id=$1`, c.ID))
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if old != nil {
		if err := checkSensorReferences(ctx, tx, *old, &c); err != nil {
			return nil, err
		}
	}
	commands, err := json.Marshal(c.Commands)
	if err != nil {
		return nil, fmt.Errorf("encode custom sensor commands: %w", err)
	}
	platforms, _ := json.Marshal(c.Platforms)
	fields, _ := json.Marshal(c.Fields)
	parameters, _ := json.Marshal(c.Parameters)
	const q = `
INSERT INTO custom_sensors (id, name, description, commands, interval_seconds,
                            timeout_seconds, enabled, created_by, platforms, fields, max_age_seconds, parameters)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description,
  commands = EXCLUDED.commands, interval_seconds = EXCLUDED.interval_seconds,
  timeout_seconds = EXCLUDED.timeout_seconds, enabled = EXCLUDED.enabled,
  platforms=EXCLUDED.platforms, fields=EXCLUDED.fields, max_age_seconds=EXCLUDED.max_age_seconds, parameters=EXCLUDED.parameters, updated_at = now()
RETURNING ` + customSensorColumns
	out, err := scanCustomSensor(tx.QueryRow(ctx, q, c.ID, c.Name, c.Description,
		commands, c.IntervalSeconds, c.TimeoutSeconds, c.Enabled, c.CreatedBy, platforms, fields, c.MaxAgeSeconds, parameters))
	if err != nil {
		return nil, fmt.Errorf("upsert custom sensor: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteCustomSensor removes the definition and the cached results it
// produced. Leaving the results behind would strand rows under a sensor
// name nothing can explain any more, which is exactly the opaque state the
// sensor catalog exists to prevent.
func (s *Store) DeleteCustomSensor(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `LOCK TABLE custom_sensors, computer_groups, saved_questions IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	old, err := scanCustomSensor(tx.QueryRow(ctx, `SELECT `+customSensorColumns+` FROM custom_sensors WHERE id=$1 FOR UPDATE`, id))
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if err = checkSensorReferences(ctx, tx, *old, nil); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM agent_sensor_data WHERE sensor=$1`, old.SensorKind()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM custom_sensor_success WHERE sensor=$1`, old.SensorKind()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM custom_sensors WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (c CustomSensor) Platform(os string) proto.SensorPlatform {
	p := c.Platforms[os]
	p.Language = sensoroutput.Language(os, p.Language)
	if p.Language == "wql" {
		p.Output.Format = "json"
		if p.Namespace == "" {
			p.Namespace = `root\cimv2`
		}
	}
	return p
}
func (c CustomSensor) Revision(os string) string {
	b, _ := json.Marshal(struct {
		Command    string
		Platform   proto.SensorPlatform
		Fields     []proto.SensorField
		Parameters []proto.DeployParameter
	}{c.Commands[os], c.Platform(os), sensoroutput.Fields(c.Fields), c.Parameters})
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func (c CustomSensor) MaxAge() time.Duration {
	seconds := c.MaxAgeSeconds
	if seconds <= 0 {
		seconds = 2*c.IntervalSeconds + c.TimeoutSeconds
	}
	return time.Duration(seconds) * time.Second
}

func checkSensorReferences(ctx context.Context, tx pgx.Tx, old CustomSensor, next *CustomSensor) error {
	fields := map[string]string{}
	if next != nil {
		for _, f := range sensoroutput.Fields(next.Fields) {
			fields[f.Name] = f.Type
		}
	}
	removed := map[string]bool{}
	for _, f := range sensoroutput.Fields(old.Fields) {
		if fields[f.Name] != f.Type {
			removed[old.SensorKind()+"."+f.Name] = true
		}
	}
	if len(removed) == 0 && next != nil {
		return nil
	}
	affected := func(field string) bool {
		return removed[field] || next == nil && strings.HasPrefix(field, old.SensorKind()+".")
	}
	rulesAffected := func(raw []byte) (bool, error) {
		var rules []groups.Rule
		if err := json.Unmarshal(raw, &rules); err != nil {
			return false, err
		}
		// A saved query's groups hide their conditions one level down.
		if leaves, err := groups.ExpandGroups(rules); err == nil {
			rules = leaves
		}
		for _, r := range rules {
			if affected(r.Field) {
				return true, nil
			}
			if r.Op == "same_row" {
				var children []groups.Rule
				if err := json.Unmarshal([]byte(r.Value), &children); err != nil {
					return false, err
				}
				for _, child := range children {
					if affected(child.Field) {
						return true, nil
					}
				}
			}
		}
		return false, nil
	}
	refs := []string{}
	rows, err := tx.Query(ctx, `SELECT name,rules FROM computer_groups`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		var raw []byte
		if err = rows.Scan(&name, &raw); err != nil {
			rows.Close()
			return err
		}
		used, e := rulesAffected(raw)
		if e != nil {
			rows.Close()
			return e
		}
		if used {
			refs = append(refs, "group: "+name)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT name,get_fields,where_rules,record_sensor FROM saved_questions`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name, record string
		var get []string
		var raw []byte
		if err = rows.Scan(&name, &get, &raw, &record); err != nil {
			rows.Close()
			return err
		}
		used, e := rulesAffected(raw)
		if e != nil {
			rows.Close()
			return e
		}
		for _, field := range get {
			used = used || affected(field)
		}
		if used || next == nil && record == old.SensorKind() {
			refs = append(refs, "query: "+name)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(refs) > 0 {
		return fmt.Errorf("sensor fields are in use by %v (reports using these queries are affected); update references before removing or retyping fields", refs)
	}
	return nil
}

// Legacy peers can still run definitions whose source and output retain the
// original shell/text contract, even after an editor materializes defaults.
func (c CustomSensor) LegacyCompatible(os string) bool {
	p := c.Platform(os)
	fields := sensoroutput.Fields(c.Fields)
	return p.Language == sensoroutput.Language(os, "") && (p.Output.Format == "" || p.Output.Format == "text") && len(fields) == 1 && fields[0].Name == "value" && fields[0].Type == "string" && len(p.Output.Paths) == 0
}
