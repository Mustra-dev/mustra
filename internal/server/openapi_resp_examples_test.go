package server

import (
	"cmp"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// respsWithoutExample is how many routes that answer with JSON have no
// respExamples entry. Like bodiesWithoutExample, the test fails when the
// count rises (a new route ships with an example) and when it falls
// (lower the constant), so coverage only moves one way.
const respsWithoutExample = 0

// Every response example is one its route could answer with, and the
// routes that answer with JSON have one, up to the ratchet.
func TestOpenAPIResponseExamples(t *testing.T) {
	for _, pattern := range slices.Sorted(maps.Keys(respExamples)) {
		doc, ok := routeDocs[pattern]
		if !ok || doc.Resp == nil {
			t.Errorf("%s has a response example, but routeDocs declares no JSON response for it", pattern)
			continue
		}
		for _, p := range respExampleProblems(doc, respExamples[pattern], notSecretsIn[pattern]) {
			t.Errorf("%s: %s", pattern, p)
		}
	}
	// Each property cleared is one the check flags without it.
	for _, pattern := range slices.Sorted(maps.Keys(notSecretsIn)) {
		if respExamples[pattern] == "" {
			t.Errorf("notSecretsIn clears properties of %s, which has no response example: remove it", pattern)
			continue
		}
		flagged := "\n" + listIndexRe.ReplaceAllString(strings.Join(respExampleProblems(routeDocs[pattern], respExamples[pattern], nil), "\n"), "[]")
		for _, path := range slices.Sorted(maps.Keys(notSecretsIn[pattern])) {
			if !strings.Contains(flagged, "\n"+path+" holds a secret") {
				t.Errorf("notSecretsIn clears %s of %s, which is not flagged as a secret: remove it", path, pattern)
			}
		}
	}
	var missing []string
	for pattern, doc := range routeDocs {
		if doc.Resp != nil && respExamples[pattern] == "" {
			missing = append(missing, pattern)
		}
	}
	switch n := len(missing); {
	case n > respsWithoutExample:
		slices.Sort(missing)
		t.Errorf("%d routes with a JSON response have no example, more than the %d allowed: add one to openapi_resp_examples.go for each new route among\n%s", n, respsWithoutExample, strings.Join(missing, "\n"))
	case n < respsWithoutExample:
		t.Errorf("only %d routes with a JSON response have no example: lower respsWithoutExample to %d", n, n)
	}
}

// A route's response example is its success response's example in the
// spec, as written; a route without one has none.
func TestOpenAPIResponseExampleInSpec(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	const pattern = "GET /api/groups"
	media := func(spec map[string]any) map[string]any {
		resp := specOp(t, spec, "get", "/api/groups")["responses"].(map[string]any)["200"].(map[string]any)
		return resp["content"].(map[string]any)["application/json"].(map[string]any)
	}
	var want any
	if err := json.Unmarshal([]byte(respExamples[pattern]), &want); err != nil {
		t.Fatal(err)
	}
	assertJSON(t, "example", media(s.openAPISpec())["example"], schemaJSON(t, want))

	docs := map[string]routeDoc{pattern: routeDocs[pattern]}
	if _, ok := media(s.openAPISpecFrom(docs, nil, nil))["example"]; ok {
		t.Error("a route without a response example has one in the spec")
	}
}

// notSecretsIn are response properties of one route that secretNameRe
// names but that carry no secret, by the route's pattern and the
// property's path ("[]" for any entry of a list), with what they hold.
// They are cleared there only: elsewhere a property of the same name may
// well be a secret, so notSecrets cannot clear the name.
var notSecretsIn = map[string]map[string]string{
	"GET /api/backup-status": {
		"response.systems[].items[].key": "which backup group or object: the datastore and group (backups:vm/101), or the backup system's object ID",
	},
	"GET /api/certificates/alerts": {
		"response.recent[].item_key": "the key of the item an alert was about, as upcoming[].key",
		"response.upcoming[].key":    "which item expires: its kind's prefix, then a fingerprint or an ID",
	},
	"GET /api/certificates/apps": {
		"response.types.client_secret":       "the credential type's label",
		"response.types.service_account_key": "the credential type's label",
	},
	"GET /api/reveal/overview": {
		"response.pattern_names.aws_access_key": "the built-in pattern's name, keyed by its ID",
		"response.pattern_names.github_token":   "the built-in pattern's name, keyed by its ID",
		"response.pattern_names.private_key":    "the built-in pattern's name, keyed by its ID",
	},
	"GET /api/deploy/credentials/{id}/public-key": {
		"response.public_key": "the authorized_keys line of a stored private key, public by design",
	},
	"GET /api/deploy/revisions/{revision}/references": {
		"response.references[].key": "which schedule or playbook step refers to the version: its kind, its ID, and a playbook step's index",
	},
	"GET /api/dashboards/{id}/data": {
		"response.panels[].series[].key": "the grouped value a slice's label was made from",
	},
	"POST /api/dashboards/preview": {
		"response.series[].key": "the grouped value a slice's label was made from",
	},
	"GET /api/software-inventory": {
		"response.products[].key": "the product's name, normalised: what /api/software-inventory/product/{key} takes",
	},
	"GET /api/software-inventory/product/{key}": {
		"response.product.key": "the product's name, normalised, as in the path",
	},
	"GET /api/entra/devices": {
		"response.devices[].key": "which device a row is: its Entra device ID, or intune: and its Intune ID",
	},
	"GET /api/guide": {
		"response.items[].subject_key": "the condition an item is about: its source, then what it names",
	},
	"POST /api/guide/refresh": {
		"response.items[].subject_key": "the condition an item is about: its source, then what it names",
	},
}

// listIndexRe finds a list index in a path, which notSecretsIn writes "[]".
var listIndexRe = regexp.MustCompile(`\[\d+\]`)

// respExampleProblems lists what is wrong with example as the success
// response of a route declared as doc. It is held to the main shape, Resp:
// when the route answers in several (RespAlt), the example shows the one
// a caller gets most often, and the spec's anyOf admits it. Beyond what
// the schema says, the example must be what encoding/json would write:
// every field the server always sends is there, one it leaves out when
// empty is not there empty, and no secret is sent back. cleared holds the
// route's notSecretsIn.
func respExampleProblems(doc routeDoc, example string, cleared map[string]string) []string {
	var value any
	if err := json.Unmarshal([]byte(example), &value); err != nil {
		return []string{"not JSON: " + err.Error()}
	}
	var out []string
	typed := reflect.New(reflect.TypeOf(doc.Resp))
	dec := json.NewDecoder(strings.NewReader(example))
	dec.DisallowUnknownFields()
	if err := dec.Decode(typed.Interface()); err != nil {
		out = append(out, fmt.Sprintf("does not decode into %T: %v", doc.Resp, err))
	} else if raw, err := json.Marshal(typed.Elem().Interface()); err != nil {
		out = append(out, err.Error())
	} else {
		var written any
		_ = json.Unmarshal(raw, &written)
		out = append(out, encodingDiff(value, written, "response")...)
	}
	// The schemas as a client reads them, through JSON.
	set := newSchemaSet(doc.types()...)
	status := strconv.Itoa(cmp.Or(doc.Status, 200))
	raw, err := json.Marshal(map[string]any{"response": doc.responses(set, "")[status], "components": set.components()})
	if err != nil {
		return append(out, err.Error())
	}
	var spec struct {
		Response struct {
			Content map[string]struct {
				Schema map[string]any `json:"schema"`
			} `json:"content"`
		} `json:"response"`
		Components map[string]any `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		return append(out, err.Error())
	}
	sch := spec.Response.Content["application/json"].Schema
	out = append(out, admits(spec.Components, sch, value, "response")...)
	out = append(out, writeOnlyProblems(spec.Components, sch, value, "response")...)
	return append(out, secretValueProblems(value, "response", cleared)...)
}

// shownOnceRe is how a response example writes a secret the server does
// send, once (a new API or enrollment token): the token's real prefix, if
// it has one, then a description in angle brackets.
var shownOnceRe = regexp.MustCompile(`^[A-Za-z0-9_-]*<[^<>]+>$`)

// bearerRe finds a credential inside a command an answer spells out (the
// enrollment one-liners). Its group is "<" when the credential is written
// as shownOnceRe says.
var bearerRe = regexp.MustCompile(`Bearer [A-Za-z0-9_-]*(<?)`)

// secretValueProblems finds a secret written as a value, whatever the
// schema says of its field. A property secretNameRe names (but for
// notSecrets and the paths cleared, as notSecretsIn writes them) holds
// nothing or a shownOnceRe placeholder, and so does a bearer credential
// inside any string.
func secretValueProblems(v any, path string, cleared map[string]string) []string {
	var out []string
	switch x := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(x)) {
			where := path + "." + k
			if str, ok := x[k].(string); ok && secretNameRe.MatchString(k) && notSecrets[k] == "" && cleared[listIndexRe.ReplaceAllString(where, "[]")] == "" && str != "" && !shownOnceRe.MatchString(str) {
				out = append(out, where+" holds a secret: write a <placeholder>, after the token's prefix if it has one")
			}
			out = append(out, secretValueProblems(x[k], where, cleared)...)
		}
	case []any:
		for i, e := range x {
			out = append(out, secretValueProblems(e, fmt.Sprintf("%s[%d]", path, i), cleared)...)
		}
	case string:
		for _, m := range bearerRe.FindAllStringSubmatch(x, -1) {
			if m[1] == "" {
				out = append(out, path+" carries a bearer credential: write a <placeholder>")
			}
		}
	}
	return out
}

// encodingDiff compares an example with what encoding/json writes for the
// value it decodes into, so that the example shows a response as the
// server really sends it.
func encodingDiff(example, written any, path string) []string {
	switch x := example.(type) {
	case map[string]any:
		w, ok := written.(map[string]any)
		if !ok {
			break
		}
		var out []string
		for _, k := range slices.Sorted(maps.Keys(w)) {
			if _, ok := x[k]; !ok {
				b, _ := json.Marshal(w[k])
				out = append(out, fmt.Sprintf("%s.%s is missing: the server always writes it (%s when unset)", path, k, b))
			}
		}
		for _, k := range slices.Sorted(maps.Keys(x)) {
			if _, ok := w[k]; !ok {
				out = append(out, fmt.Sprintf("%s.%s is not written when it is empty, or is not the field's name: leave it out or give it a value", path, k))
				continue
			}
			out = append(out, encodingDiff(x[k], w[k], path+"."+k)...)
		}
		return out
	case []any:
		w, ok := written.([]any)
		if !ok || len(w) != len(x) {
			break
		}
		var out []string
		for i := range x {
			out = append(out, encodingDiff(x[i], w[i], fmt.Sprintf("%s[%d]", path, i))...)
		}
		return out
	}
	if !reflect.DeepEqual(example, written) {
		b, _ := json.Marshal(written)
		return []string{fmt.Sprintf("%s is written as %s", path, b)}
	}
	return nil
}

// writeOnlyProblems names the write-only fields (secrets) value carries
// with something in them. The server never sends one back: a type shared
// with a request writes it empty, if at all.
func writeOnlyProblems(components map[string]any, sch map[string]any, v any, path string) []string {
	if ref, ok := sch["$ref"].(string); ok {
		return writeOnlyProblems(components, components[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any), v, path)
	}
	var out []string
	all, _ := sch["allOf"].([]any)
	for _, s := range all {
		out = append(out, writeOnlyProblems(components, s.(map[string]any), v, path)...)
	}
	alts, _ := sch["anyOf"].([]any)
	for _, s := range alts {
		if len(admits(components, s.(map[string]any), v, path)) == 0 {
			out = append(out, writeOnlyProblems(components, s.(map[string]any), v, path)...)
			break
		}
	}
	switch x := v.(type) {
	case map[string]any:
		props, _ := sch["properties"].(map[string]any)
		extra, _ := sch["additionalProperties"].(map[string]any)
		for _, k := range slices.Sorted(maps.Keys(x)) {
			where := path + "." + k
			p, ok := props[k].(map[string]any)
			if !ok {
				if extra != nil {
					out = append(out, writeOnlyProblems(components, extra, x[k], where)...)
				}
				continue
			}
			if p["writeOnly"] == true && x[k] != nil && x[k] != "" {
				out = append(out, where+" is a secret, which a response never carries: leave it out")
			}
			out = append(out, writeOnlyProblems(components, p, x[k], where)...)
		}
	case []any:
		if items, ok := sch["items"].(map[string]any); ok {
			for i, e := range x {
				out = append(out, writeOnlyProblems(components, items, e, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	}
	return out
}
