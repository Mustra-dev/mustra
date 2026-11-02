// Package sensoroutput normalizes custom collector output into the same scalar
// rows used by targeting, questions, and reports. No partial parse is usable.
package sensoroutput

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mustra-dev/mustra/internal/proto"
)

const MaxBytes = 64 << 10
const MaxRows = 500

var fieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Fields(fields []proto.SensorField) []proto.SensorField {
	if len(fields) == 0 {
		return []proto.SensorField{{Name: "value", Type: "string"}}
	}
	return fields
}
func Language(os, language string) string {
	if language != "" {
		return language
	}
	if os == "windows" {
		return "powershell"
	}
	return "shell"
}
func Validate(fields []proto.SensorField, platforms map[string]proto.SensorPlatform) error {
	seen := map[string]bool{}
	if len(fields) > 64 {
		return fmt.Errorf("at most 64 fields are supported")
	}
	for _, f := range Fields(fields) {
		if len(f.Name) > 64 || !fieldName.MatchString(f.Name) || f.Name == "count" || strings.HasPrefix(f.Name, "_") || seen[f.Name] {
			return fmt.Errorf("invalid, reserved, or duplicate field %q", f.Name)
		}
		if f.Type != "string" && f.Type != "number" && f.Type != "bool" {
			return fmt.Errorf("field %s: use string, number, or bool", f.Name)
		}
		seen[f.Name] = true
	}
	for os, p := range platforms {
		l := Language(os, p.Language)
		if os != "linux" && os != "darwin" && os != "windows" {
			return fmt.Errorf("unknown platform %q", os)
		}
		if l != "go" && l != "python" && !(os == "windows" && (l == "powershell" || l == "batch" || l == "wql")) && !(os != "windows" && l == "shell") {
			return fmt.Errorf("unsupported language %q on %s", l, os)
		}
		o := p.Output
		if len(p.Namespace) > 128 || len(o.RowPath) > 1024 {
			return fmt.Errorf("namespace or row path exceeds length limit")
		}
		for _, path := range o.Paths {
			if len(path) > 1024 {
				return fmt.Errorf("field path exceeds 1024 bytes")
			}
		}
		switch o.Format {
		case "", "text", "json", "jsonl", "delimited", "list":
		default:
			return fmt.Errorf("unknown output format %q", o.Format)
		}
		if l == "wql" && o.Format != "json" {
			return fmt.Errorf("WQL requires JSON output mapping")
		}
		if o.Format == "delimited" || o.Format == "list" {
			r, n := utf8.DecodeRuneInString(o.Delimiter)
			if n != len(o.Delimiter) || n == 0 || r == utf8.RuneError || r == '\r' || r == '\n' || r == '"' || r == 0 {
				return fmt.Errorf("delimiter must be one character other than newline or quote")
			}
		}
		if o.Format == "" || o.Format == "text" || o.Format == "list" {
			if len(o.Paths) > 0 {
				return fmt.Errorf("text and list formats have no field paths")
			}
			fs := Fields(fields)
			if len(fs) != 1 || fs[0].Name != "value" {
				return fmt.Errorf("text and list formats require a single value field")
			}
		}
		for name := range o.Paths {
			if !seen[name] {
				return fmt.Errorf("mapping refers to unknown field %q", name)
			}
		}
	}
	return nil
}

// Lookup supports dotted object paths and numeric array indexes. A JSON Pointer
// can address literal dots/slashes in property names without an escaping guess.
func Lookup(v any, path string) (any, bool) {
	if path == "" || path == "$" {
		return v, true
	}
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	if strings.HasPrefix(path, "/") {
		parts = strings.Split(path[1:], "/")
		for i := range parts {
			parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
		}
	}
	for _, key := range parts {
		switch t := v.(type) {
		case map[string]any:
			var ok bool
			v, ok = t[key]
			if !ok {
				return nil, false
			}
		case []any:
			i, e := strconv.Atoi(key)
			if e != nil || i < 0 || i >= len(t) {
				return nil, false
			}
			v = t[i]
		default:
			return nil, false
		}
	}
	return v, true
}
func decode(raw string) (any, error) {
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected exactly one JSON document")
	}
	return v, nil
}
func Parse(raw string, o proto.SensorOutput, fields []proto.SensorField) ([]map[string]any, error) {
	if len(raw) > MaxBytes {
		return nil, fmt.Errorf("output exceeds %d bytes", MaxBytes)
	}
	fields = Fields(fields)
	rows := make([]map[string]any, 0)
	add := func(v any, text bool) error {
		if len(rows) >= MaxRows {
			return fmt.Errorf("output exceeds %d rows", MaxRows)
		}
		if _, ok := v.(map[string]any); !ok {
			if len(fields) != 1 || fields[0].Name != "value" {
				return fmt.Errorf("row %d: expected an object", len(rows)+1)
			}
		}
		row := map[string]any{}
		for _, f := range fields {
			path := f.Name
			if p, ok := o.Paths[f.Name]; ok {
				path = p
			}
			var value any
			if _, ok := v.(map[string]any); !ok && len(fields) == 1 && f.Name == "value" && o.Paths[f.Name] == "" {
				value = v
			} else {
				value, _ = Lookup(v, path)
			}
			converted, err := scalar(value, f.Type, text)
			if err != nil {
				return fmt.Errorf("row %d, field %s: %w", len(rows)+1, f.Name, err)
			}
			row[f.Name] = converted
		}
		rows = append(rows, row)
		return nil
	}
	switch o.Format {
	case "", "text":
		if raw != "" {
			lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
			for _, line := range lines {
				if err := add(strings.TrimSuffix(line, "\r"), true); err != nil {
					return nil, err
				}
			}
		}
	case "json", "jsonl":
		docs := []string{raw}
		if o.Format == "jsonl" {
			docs = strings.Split(raw, "\n")
		}
		for i, doc := range docs {
			if o.Format == "jsonl" && strings.TrimSpace(doc) == "" {
				continue
			}
			v, err := decode(doc)
			if err != nil {
				return nil, fmt.Errorf("JSON document %d: %w", i+1, err)
			}
			v, ok := Lookup(v, o.RowPath)
			if !ok {
				return nil, fmt.Errorf("row path %q not found", o.RowPath)
			}
			if list, ok := v.([]any); ok {
				for _, item := range list {
					if err := add(item, false); err != nil {
						return nil, err
					}
				}
			} else {
				if v == nil {
					return nil, fmt.Errorf("row path must select an object or array")
				}
				if err := add(v, false); err != nil {
					return nil, err
				}
			}
		}
	case "delimited", "list":
		reader := csv.NewReader(strings.NewReader(raw))
		reader.Comma, _ = utf8.DecodeRuneInString(o.Delimiter)
		reader.FieldsPerRecord = -1
		names := make([]string, len(fields))
		for i, f := range fields {
			names[i] = f.Name
		}
		first := true
		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if o.Format == "list" {
				for _, v := range record {
					if err := add(v, true); err != nil {
						return nil, err
					}
				}
				continue
			}
			if first && o.Headers {
				names = record
				seen := map[string]bool{}
				for _, n := range names {
					if n == "" || seen[n] {
						return nil, fmt.Errorf("empty or duplicate header %q", n)
					}
					seen[n] = true
				}
				first = false
				continue
			}
			first = false
			if len(record) != len(names) {
				return nil, fmt.Errorf("row %d: expected %d columns, got %d", len(rows)+1, len(names), len(record))
			}
			v := map[string]any{}
			for i, n := range names {
				v[n] = record[i]
			}
			if err := add(v, true); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unknown output format")
	}
	return rows, nil
}
func scalar(v any, kind string, text bool) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch kind {
	case "string":
		if s, ok := v.(string); ok {
			return s, nil
		}
	case "bool":
		if b, ok := v.(bool); ok {
			return b, nil
		}
		if text {
			if s, ok := v.(string); ok && (s == "true" || s == "false") {
				return s == "true", nil
			}
		}
	case "number":
		var n float64
		var err error
		switch t := v.(type) {
		case json.Number:
			n, err = t.Float64()
		case float64:
			n = t
		case string:
			if !text {
				return nil, fmt.Errorf("expected number")
			}
			n, err = strconv.ParseFloat(t, 64)
		default:
			return nil, fmt.Errorf("expected number")
		}
		if err == nil && !math.IsNaN(n) && !math.IsInf(n, 0) {
			return n, nil
		}
	}
	return nil, fmt.Errorf("expected %s scalar", kind)
}
