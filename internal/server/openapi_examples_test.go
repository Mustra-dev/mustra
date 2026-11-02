package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// bodiesWithoutExample is how many routes that take a JSON body have
// neither a bodyExamples entry nor a noBodyExample one. Like
// undocumentedRoutes, the test fails when the count rises (a new route
// with a body ships with an example) and when it falls (lower the
// constant), so coverage only moves one way.
const bodiesWithoutExample = 0

// noBodyExample are routes left without an example on purpose, since none
// could be harmless when sent as written: each replaces one live,
// server-wide configuration (or upgrades a whole ring), which a tool that
// sends a spec's example as the body would overwrite with sample values.
// The builder starts them from the schema instead, as it did before.
var noBodyExample = map[string]string{
	"PUT /api/agent-trust":             "the public URL every agent downloads from",
	"POST /api/assets/purge-after":     "when retired assets are purged for good",
	"POST /api/backup-status/settings": "when a backup counts as stale",
	"PUT /api/backups/settings":        "the backup schedule, and how many archives are kept",
	"PUT /api/threat-settings":         "whether threat briefings patch vulnerable endpoints automatically",
	"PUT /api/telemetry":               "where every endpoint's metrics go, and how often they are collected",
	"POST /api/admin/branding":         "the console's logo",
	"POST /api/admin/cert-authorities": "the certificate authorities' accounts",
	"POST /api/certificates/alerts":    "when certificate expiry is announced",
	"POST /api/clients/upgrade":        "upgrades every endpoint of a ring; it cannot name fewer",
	"POST /api/compliance/settings":    "the hardening scan schedule",
	"POST /api/directory":              "the directory connection",
	"POST /api/discover/settings":      "network discovery's settings",
	"POST /api/admin/entra":            "the Entra ID connection",
	"POST /api/admin/logging":          "the log level and audit forwarding",
	"POST /api/admin/remote":           "the remote desktop gateway",
	"POST /api/admin/settings":         "the server's settings",
	"PUT /api/deploy/settings":         "the deployment log and cache limits of every agent",
	"PUT /api/preferences":             "the caller's own preferences, replaced whole",
	"PUT /api/selfservice/branding":    "the Self Service window's look",
}

// Every example is one its route takes, and every route with a JSON body
// has one, up to the ratchet, or is in noBodyExample.
func TestOpenAPIBodyExamples(t *testing.T) {
	for _, pattern := range slices.Sorted(maps.Keys(bodyExamples)) {
		doc, ok := routeDocs[pattern]
		if !ok || doc.Body == nil {
			t.Errorf("%s has an example, but routeDocs declares no JSON body for it", pattern)
			continue
		}
		if noBodyExample[pattern] != "" {
			t.Errorf("%s has an example, and noBodyExample says it must not: remove one", pattern)
		}
		for _, p := range exampleProblems(doc, bodyExamples[pattern]) {
			t.Errorf("%s: %s", pattern, p)
		}
	}
	for pattern := range noBodyExample {
		if doc, ok := routeDocs[pattern]; !ok || doc.Body == nil {
			t.Errorf("noBodyExample lists %s, which declares no JSON body; remove it", pattern)
		}
	}
	var missing []string
	for pattern, doc := range routeDocs {
		if doc.Body != nil && bodyExamples[pattern] == "" && noBodyExample[pattern] == "" {
			missing = append(missing, pattern)
		}
	}
	switch n := len(missing); {
	case n > bodiesWithoutExample:
		slices.Sort(missing)
		t.Errorf("%d routes with a JSON body have no example, more than the %d allowed: add one to openapi_examples.go for each new route among\n%s", n, bodiesWithoutExample, strings.Join(missing, "\n"))
	case n < bodiesWithoutExample:
		t.Errorf("only %d routes with a JSON body have no example: lower bodiesWithoutExample to %d", n, n)
	}
}

// A route's example is its JSON body's example in the spec, as written;
// a route without one has none.
func TestOpenAPIBodyExampleInSpec(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	spec := s.openAPISpec()
	body := specOp(t, spec, "post", "/api/shell/sessions")["requestBody"].(map[string]any)
	media := body["content"].(map[string]any)["application/json"].(map[string]any)
	var want any
	if err := json.Unmarshal([]byte(bodyExamples["POST /api/shell/sessions"]), &want); err != nil {
		t.Fatal(err)
	}
	assertJSON(t, "example", media["example"], schemaJSON(t, want))

	docs := map[string]routeDoc{"POST /api/shell/sessions": routeDocs["POST /api/shell/sessions"]}
	bare := specOp(t, s.openAPISpecFrom(docs, nil, nil), "post", "/api/shell/sessions")["requestBody"].(map[string]any)
	if _, ok := bare["content"].(map[string]any)["application/json"].(map[string]any)["example"]; ok {
		t.Error("a route without an example has one in the spec")
	}
}

// placeholderRe is how an example writes a secret: a description of
// what goes there, never a value a reader could paste and use.
var placeholderRe = regexp.MustCompile(`^<[^<>]+>$`)

// exampleProblems lists what is wrong with example as the body of a route
// declared as doc: what keeps the handler's decoder or the spec's schema
// from taking it, a required field it leaves out, a field the server sets
// (which a request does not send), and a secret written as a value.
func exampleProblems(doc routeDoc, example string) []string {
	var value any
	if err := json.Unmarshal([]byte(example), &value); err != nil {
		return []string{"not JSON: " + err.Error()}
	}
	var out []string
	dec := json.NewDecoder(strings.NewReader(example))
	dec.DisallowUnknownFields()
	if err := dec.Decode(reflect.New(reflect.TypeOf(doc.Body)).Interface()); err != nil {
		out = append(out, fmt.Sprintf("does not decode into %T: %v", doc.Body, err))
	}
	// The schemas as a client reads them, through JSON.
	set := newSchemaSet(doc.types()...)
	raw, err := json.Marshal(map[string]any{"body": doc.requestBody(set, ""), "components": set.components()})
	if err != nil {
		return append(out, err.Error())
	}
	var spec struct {
		Body struct {
			Content map[string]struct {
				Schema map[string]any `json:"schema"`
			} `json:"content"`
		} `json:"body"`
		Components map[string]any `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		return append(out, err.Error())
	}
	sch := spec.Body.Content["application/json"].Schema
	out = append(out, admits(spec.Components, sch, value, "body")...)
	return append(out, exampleFieldProblems(spec.Components, sch, value, "body")...)
}

// exampleFieldProblems walks value along its schema for what admits does
// not check: required fields, read-only ones, and secrets.
func exampleFieldProblems(components map[string]any, sch map[string]any, v any, path string) []string {
	if ref, ok := sch["$ref"].(string); ok {
		return exampleFieldProblems(components, components[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any), v, path)
	}
	var out []string
	all, _ := sch["allOf"].([]any)
	for _, s := range all {
		out = append(out, exampleFieldProblems(components, s.(map[string]any), v, path)...)
	}
	alts, _ := sch["anyOf"].([]any)
	for _, s := range alts {
		if len(admits(components, s.(map[string]any), v, path)) == 0 {
			out = append(out, exampleFieldProblems(components, s.(map[string]any), v, path)...)
			break
		}
	}
	switch x := v.(type) {
	case map[string]any:
		required, _ := sch["required"].([]any)
		for _, r := range required {
			if _, ok := x[r.(string)]; !ok {
				out = append(out, fmt.Sprintf("%s.%s is required", path, r))
			}
		}
		props, _ := sch["properties"].(map[string]any)
		extra, _ := sch["additionalProperties"].(map[string]any)
		for _, k := range slices.Sorted(maps.Keys(x)) {
			where := path + "." + k
			p, ok := props[k].(map[string]any)
			if !ok {
				if extra != nil {
					out = append(out, exampleFieldProblems(components, extra, x[k], where)...)
				}
				continue
			}
			if p["readOnly"] == true {
				out = append(out, where+" is read-only: the server sets it, so a request leaves it out")
			}
			if s, ok := x[k].(string); p["writeOnly"] == true && (!ok || !placeholderRe.MatchString(s)) {
				out = append(out, where+" is a secret: write a <placeholder> rather than a value")
			}
			out = append(out, exampleFieldProblems(components, p, x[k], where)...)
		}
	case []any:
		if items, ok := sch["items"].(map[string]any); ok {
			for i, e := range x {
				out = append(out, exampleFieldProblems(components, items, e, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	}
	return out
}
