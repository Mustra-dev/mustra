package store

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
	"strings"
)

// Reference writers take a shared definition lock until their write commits.
// This closes the check/write race with schema edits and deletions.
func validateCustomReferences(ctx context.Context, tx pgx.Tx, get []string, rules []groups.Rule, record string) error {
	if _, err := tx.Exec(ctx, `LOCK TABLE custom_sensors IN SHARE MODE`); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT `+customSensorColumns+` FROM custom_sensors`)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	sensors := map[string]bool{}
	for rows.Next() {
		c, err := scanCustomSensor(rows)
		if err != nil {
			rows.Close()
			return err
		}
		sensors[c.SensorKind()] = true
		for _, f := range sensoroutput.Fields(c.Fields) {
			known[c.SensorKind()+"."+f.Name] = true
		}
		for _, k := range []string{"count", "_status", "_collected_at", "_last_attempt_at", "_historical", "_error"} {
			known[c.SensorKind()+"."+k] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	check := func(field string) error {
		if strings.HasPrefix(field, "custom_") && !known[field] {
			return fmt.Errorf("unknown custom sensor field %s", field)
		}
		return nil
	}
	for _, field := range get {
		if err = check(field); err != nil {
			return err
		}
	}
	// A saved query's groups are checked through their conditions.
	if rules, err = groups.ExpandGroups(rules); err != nil {
		return err
	}
	for _, rule := range rules {
		if rule.Op == "same_row" {
			var children []groups.Rule
			if err = rule.Validate(); err != nil {
				return err
			}
			_ = json.Unmarshal([]byte(rule.Value), &children)
			for _, r := range children {
				if err = check(r.Field); err != nil {
					return err
				}
			}
		} else {
			if err = check(rule.Field); err != nil {
				return err
			}
		}
	}
	if strings.HasPrefix(record, "custom_") && !sensors[record] {
		return fmt.Errorf("unknown custom record sensor")
	}
	return nil
}
