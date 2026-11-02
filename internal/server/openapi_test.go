package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// The reference is generated from the route table: every /api route must
// appear, with the permission its guard demands and a readable summary.
func TestOpenAPIFromRouteTable(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	spec := s.openAPISpec()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]map[string]any)
	apiRoutes := 0
	for _, e := range s.routeLog.entries {
		m, p, _ := strings.Cut(e.Pattern, " ")
		if !strings.HasPrefix(p, "/api/") || strings.HasSuffix(p, "/") {
			continue
		}
		apiRoutes++
		op, ok := paths[pathParamRe.ReplaceAllString(p, "{$1}")][strings.ToLower(m)]
		if !ok {
			t.Errorf("%s is missing from the reference", e.Pattern)
		}
		_ = op
	}
	if apiRoutes < 100 {
		t.Fatalf("only %d API routes found; the route table was not read", apiRoutes)
	}
	agents := paths["/api/agents/{id}/update"]["post"].(map[string]any)
	if !strings.Contains(agents["description"].(string), "deploy.manage") || !strings.Contains(agents["description"].(string), "endpoint action") {
		t.Errorf("permissions and the endpoint-action note belong in the description: %v", agents["description"])
	}
	if got := paths["/api/certificates/managed"]["get"].(map[string]any)["summary"]; got != "List managed certs" {
		t.Errorf("summary from the handler name: %q", got)
	}
	// A file's formats share its tag, not one tag per extension.
	for p, tag := range map[string]string{"/api/openapi.json": "openapi", "/api/openapi.yaml": "openapi", "/api/lifecycle.csv": "lifecycle"} {
		if got := paths[p]["get"].(map[string]any)["tags"]; !reflect.DeepEqual(got, []string{tag}) {
			t.Errorf("%s: tags %v, want [%s]", p, got, tag)
		}
	}
	if !strings.Contains(string(raw), `"openapi":"3.2.1"`) {
		t.Error("not an OpenAPI 3.2.1 document")
	}
}

// specOp is one operation of the generated spec, round-tripped through
// JSON so a test reads what a client reads.
func specOp(t *testing.T, spec map[string]any, method, path string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(spec["paths"])
	if err != nil {
		t.Fatal(err)
	}
	var paths map[string]map[string]map[string]any
	if err := json.Unmarshal(raw, &paths); err != nil {
		t.Fatal(err)
	}
	op, ok := paths[path][method]
	if !ok {
		t.Fatalf("%s %s is not in the spec", method, path)
	}
	return op
}

// jsonBodySchema is an operation's JSON request body without its example:
// whether it is required, and its schema.
func jsonBodySchema(t *testing.T, op map[string]any) map[string]any {
	t.Helper()
	body, _ := op["requestBody"].(map[string]any)
	content, _ := body["content"].(map[string]any)
	media, ok := content["application/json"].(map[string]any)
	if !ok {
		t.Fatalf("no JSON request body: %v", op["requestBody"])
	}
	return map[string]any{"required": body["required"], "schema": media["schema"]}
}

// A declared route describes its real request and response; an
// undeclared one keeps the generic description it had before.
func TestOpenAPIDeclaredRoutes(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	spec := s.openAPISpec()

	sensor := specOp(t, spec, "post", "/api/agents/{id}/sensor-interval")
	assertJSON(t, "named body", jsonBodySchema(t, sensor), `{"required":true,"schema":{"$ref":"#/components/schemas/SetSensorIntervalRequest"}}`)
	assertJSON(t, "named response", sensor["responses"].(map[string]any)["200"], `{"description":"OK","content":{"application/json":{"schema":{"$ref":"#/components/schemas/AgentCommandResult"},"example":{"ok":true}}}}`)
	assertJSON(t, "error", sensor["responses"].(map[string]any)["504"], `{"description":"Gateway Timeout","content":{"text/plain":{"schema":{"type":"string"}}}}`)

	if _, ok := specOp(t, spec, "post", "/api/hunt/run")["requestBody"]; ok {
		t.Error("a route that reads no body must not advertise one")
	}

	shell := specOp(t, spec, "delete", "/api/shell/sessions/{id}")
	assertJSON(t, "query flag", shell["parameters"], `[
		{"name":"id","in":"path","required":true,"schema":{"type":"string"}},
		{"name":"takeover","in":"query","required":false,"description":"close another operator's session","schema":{"type":"string","enum":["1"]}}]`)
	responses := shell["responses"].(map[string]any)
	assertJSON(t, "204", responses["204"], `{"description":"No Content"}`)
	if _, ok := responses["200"]; ok {
		t.Error("a 204 route has no 200 response")
	}

	assertJSON(t, "upload", specOp(t, spec, "post", "/api/software/{id}/files")["requestBody"], `{"required":true,"content":{"multipart/form-data":{"schema":{
		"type":"object","required":["file"],"properties":{"file":{"contentMediaType":"application/octet-stream"}}}}}}`)
	assertJSON(t, "binary response", specOp(t, spec, "get", "/api/backups/{id}/download")["responses"].(map[string]any)["200"],
		`{"description":"OK","content":{"application/gzip":{"schema":{"contentMediaType":"application/gzip"}}}}`)
	assertJSON(t, "raw body", specOp(t, spec, "post", "/api/compliance/import")["requestBody"], `{"required":true,"content":{"application/yaml":{"schema":{"type":"string"}}}}`)
	// Bodies a handler can do without: a rescan of the whole fleet sends
	// none, and a restore by ?id= uploads nothing.
	for _, p := range []string{"/api/patches/rescan", "/api/backups/restore"} {
		if body, _ := specOp(t, spec, "post", p)["requestBody"].(map[string]any); body == nil || body["required"] != false {
			t.Errorf("POST %s: the body is optional, the spec says %v", p, body)
		}
	}
	assertJSON(t, "stream", specOp(t, spec, "get", "/api/agents/stream")["responses"].(map[string]any)["200"], `{"description":"OK","content":{"text/event-stream":{"schema":{"type":"string"}}}}`)
	// The response example goes with the JSON half only; past it, the two
	// media types are compared.
	inventory := specOp(t, spec, "get", "/api/software-inventory")["responses"].(map[string]any)["200"].(map[string]any)
	inventoryJSON := inventory["content"].(map[string]any)["application/json"].(map[string]any)
	assertJSON(t, "JSON example", inventoryJSON["example"], respExamples["GET /api/software-inventory"])
	delete(inventoryJSON, "example")
	assertJSON(t, "JSON, or CSV when asked", inventory, `{"description":"OK","content":{
		"application/json":{"schema":{"$ref":"#/components/schemas/SoftwareInventoryResponse"}},
		"text/csv":{"schema":{"type":"string"}}}}`)
	assertJSON(t, "map body", jsonBodySchema(t, specOp(t, spec, "put", "/api/agents/{id}/attributes")), `{"required":true,"schema":{"type":["object","null"],"additionalProperties":{"type":"string"}}}`)
	if _, ok := specOp(t, spec, "get", "/api/agents/{id}/attributes")["requestBody"]; ok {
		t.Error("the GET half of a shared handler has no body")
	}

	// Undeclared: exactly the description every route had before
	// routeDocs. One declaration is left out of a copy for this, so the
	// check does not run out of undeclared routes as coverage grows.
	const undeclared = "POST /api/agents/{id}/update"
	if _, ok := routeDocs[undeclared]; !ok {
		t.Fatalf("%s is not declared any more; set aside another route", undeclared)
	}
	docs := maps.Clone(routeDocs)
	delete(docs, undeclared)
	op := specOp(t, s.openAPISpecFrom(docs, bodyExamples, respExamples), "post", "/api/agents/{id}/update")
	assertJSON(t, "undeclared body", op["requestBody"], `{"required":false,"content":{"application/json":{"schema":{"type":"object"}}}}`)
	assertJSON(t, "undeclared parameters", op["parameters"], `[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]`)
	assertJSON(t, "undeclared responses", op["responses"], `{
		"200":{"description":"OK","content":{"application/json":{"schema":{"type":"object"}}}},
		"401":{"description":"Not signed in"},"403":{"description":"Missing permission"}}`)

	// A body that was an anonymous struct in its handler, now a named type.
	assertJSON(t, "hoisted body", jsonBodySchema(t, specOp(t, spec, "post", "/api/shell/sessions")),
		`{"required":true,"schema":{"$ref":"#/components/schemas/OpenShellRequest"}}`)

	components := spec["components"].(map[string]any)["schemas"].(map[string]any)
	openShell, _ := components["OpenShellRequest"].(map[string]any)
	if req, _ := openShell["required"].([]string); !slices.Equal(req, []string{"agent_id"}) {
		t.Errorf("OpenShellRequest requires %v, want [agent_id] (component: %v)", req, openShell)
	}
	// Required where the handlers reject a request without it, including
	// checks made inside the validators a body is handed to.
	for name, want := range map[string][]string{
		"TestSignalRequest":       {"expression"},
		"EnforceCompileRequest":   {"config", "kind"},
		"DeployRevisionsRequest":  {"definition", "label"},
		"TestCustomSensorRequest": {"agent_id", "sensor"},
	} {
		comp, _ := components[name].(map[string]any)
		got, _ := comp["required"].([]string)
		got = slices.Sorted(slices.Values(got))
		if !slices.Equal(got, want) {
			t.Errorf("%s requires %v, want %v", name, got, want)
		}
	}
	// A sensor's save requires a name and a script; testing an unnamed
	// draft does not need the name, so the requirements are the route's,
	// not the shared CustomSensor's.
	if req, ok := components["CustomSensor"].(map[string]any)["required"]; ok {
		t.Errorf("CustomSensor requires %v; only its save routes should", req)
	}
	assertJSON(t, "save requires a name", jsonBodySchema(t, specOp(t, spec, "post", "/api/sensors/custom")),
		`{"required":true,"schema":{"allOf":[{"$ref":"#/components/schemas/CustomSensor"},{"required":["name","commands"]}]}}`)
	for _, name := range []string{"SetSensorIntervalRequest", "AgentCommandResult", "EUNMessage"} {
		if _, ok := components[name]; !ok {
			t.Errorf("components/schemas has no %s", name)
		}
	}
}

var (
	componentNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	statusKeyRe     = regexp.MustCompile(`^[1-5][0-9][0-9]$`)
	jsonSchemaTypes = map[string]bool{"string": true, "number": true, "integer": true, "boolean": true, "array": true, "object": true, "null": true}
)

// The spec is a structurally valid OpenAPI 3.2 document: every $ref
// resolves, operation IDs are unique, every path template's parameters
// are declared, and every response and body has what the format requires.
// Binary content is described as 3.1 and later do, never by OpenAPI 3.0's
// format: binary or byte, which no longer say how content is encoded.
func TestOpenAPIIsStructurallyValid(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	raw, err := json.Marshal(s.openAPISpec())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Title, Version string
			License        struct{ Name, Identifier string }
		}
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Parameters  []struct {
				Name     string         `json:"name"`
				In       string         `json:"in"`
				Required bool           `json:"required"`
				Schema   map[string]any `json:"schema"`
			} `json:"parameters"`
			RequestBody *struct {
				Content map[string]struct {
					Schema map[string]any `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
			Responses map[string]struct {
				Description *string                   `json:"description"`
				Content     map[string]map[string]any `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.2.1" || doc.Info.Title == "" || doc.Info.Version == "" {
		t.Errorf("header: openapi %q, title %q, version %q", doc.OpenAPI, doc.Info.Title, doc.Info.Version)
	}
	if doc.Info.License.Name == "" || doc.Info.License.Identifier != "AGPL-3.0-only" {
		t.Errorf("license: %+v", doc.Info.License)
	}
	for name := range doc.Components.Schemas {
		if !componentNameRe.MatchString(name) {
			t.Errorf("component name %q is not a valid key", name)
		}
	}
	var checkSchema func(where string, v any)
	checkSchema = func(where string, v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				switch k {
				case "$ref":
					ref, _ := x.(string)
					name, ok := strings.CutPrefix(ref, "#/components/schemas/")
					if _, found := doc.Components.Schemas[name]; !ok || !found {
						t.Errorf("%s: $ref %q does not resolve", where, ref)
					}
				case "type":
					types, _ := x.([]any)
					if s, ok := x.(string); ok {
						types = []any{s}
					}
					if len(types) == 0 {
						t.Errorf("%s: type %v", where, x)
					}
					for _, ty := range types {
						if s, _ := ty.(string); !jsonSchemaTypes[s] {
							t.Errorf("%s: %v is not a JSON Schema type", where, ty)
						}
					}
				case "format":
					if x == "binary" || x == "byte" {
						t.Errorf("%s: format %v is OpenAPI 3.0's; use contentMediaType or contentEncoding", where, x)
					}
				case "contentMediaType":
					if _, typed := v["type"]; typed {
						t.Errorf("%s: raw bytes (contentMediaType %v) have no JSON type", where, x)
					}
				case "additionalProperties", "items", "anyOf", "allOf":
					checkSchema(where, x)
				case "properties":
					props, _ := x.(map[string]any)
					for _, p := range props {
						checkSchema(where, p)
					}
				}
			}
		case []any:
			for _, x := range v {
				checkSchema(where, x)
			}
		}
	}
	for name, sch := range doc.Components.Schemas {
		checkSchema("components/schemas/"+name, sch)
	}
	ids := map[string]string{}
	for path, byMethod := range doc.Paths {
		templated := map[string]bool{}
		for _, m := range pathParamRe.FindAllStringSubmatch(path, -1) {
			templated[m[1]] = true
		}
		for method, op := range byMethod {
			where := method + " " + path
			if prev, dup := ids[op.OperationID]; dup || op.OperationID == "" {
				t.Errorf("%s: operationId %q is empty or also used by %s", where, op.OperationID, prev)
			}
			ids[op.OperationID] = where
			seen := map[string]bool{}
			declared := map[string]bool{}
			for _, p := range op.Parameters {
				if seen[p.In+" "+p.Name] {
					t.Errorf("%s: parameter %s %q twice", where, p.In, p.Name)
				}
				seen[p.In+" "+p.Name] = true
				if p.In == "path" {
					declared[p.Name] = true
					if !p.Required || !templated[p.Name] {
						t.Errorf("%s: path parameter %q must be required and in the path", where, p.Name)
					}
				} else if p.In != "query" {
					t.Errorf("%s: parameter %q in %q", where, p.Name, p.In)
				}
				checkSchema(where, p.Schema)
			}
			for name := range templated {
				if !declared[name] {
					t.Errorf("%s: path parameter %q is not declared", where, name)
				}
			}
			if op.RequestBody != nil {
				if len(op.RequestBody.Content) == 0 {
					t.Errorf("%s: requestBody without content", where)
				}
				for _, c := range op.RequestBody.Content {
					checkSchema(where, c.Schema)
				}
			}
			if len(op.Responses) == 0 {
				t.Errorf("%s: no responses", where)
			}
			for code, resp := range op.Responses {
				if !statusKeyRe.MatchString(code) || resp.Description == nil {
					t.Errorf("%s: response %q needs a status code key and a description", where, code)
				}
				for _, c := range resp.Content {
					checkSchema(where, c["schema"])
				}
			}
		}
	}
}

// Every type a declaration reaches is described by its structure or by
// an override: one written by its own MarshalJSON would otherwise be
// "any value" in the spec.
func TestOpenAPITypesHaveSchemas(t *testing.T) {
	var roots []reflect.Type
	for _, d := range routeDocs {
		roots = append(roots, d.types()...)
	}
	for _, typ := range newSchemaSet(roots...).unknown() {
		t.Errorf("%s has its own MarshalJSON: add its schema to schemaOverrides", typ)
	}
}

// secretNameRe is a property that carries a secret (a PFX holds a private
// key), rather than saying whether one is set (password_set) or naming one
// (credential_id). A boolean of that name is a flag, not the secret.
var secretNameRe = regexp.MustCompile(`(^|_)(password|passphrase|secret|token|pfx|key)$`)

// notSecrets are names secretNameRe matches that carry no secret.
var notSecrets = map[string]string{
	"product_key": "names a tracked product",
	"push_key":    "the entry a rotated credential is written under, not the credential",
}

// A request's secrets are write-only: a client generated from the spec
// must not expect to read them back. One the server mints is read-only.
func TestOpenAPIRequestSecretsAreWriteOnly(t *testing.T) {
	var bodies []reflect.Type
	for _, d := range routeDocs {
		if d.Body != nil {
			bodies = append(bodies, reflect.TypeOf(d.Body))
		}
	}
	set := newSchemaSet(bodies...)
	components := set.components()
	seen, exempted := map[string]bool{}, map[string]bool{}
	var walk func(where string, sch map[string]any)
	walk = func(where string, sch map[string]any) {
		if ref, ok := sch["$ref"].(string); ok {
			name := strings.TrimPrefix(ref, "#/components/schemas/")
			if seen[name] {
				return
			}
			seen[name] = true
			walk(name, components[name].(map[string]any))
			return
		}
		for _, k := range []string{"items", "additionalProperties"} {
			if sub, ok := sch[k].(map[string]any); ok {
				walk(where, sub)
			}
		}
		for _, k := range []string{"anyOf", "allOf"} {
			subs, _ := sch[k].([]any)
			for _, sub := range subs {
				walk(where, sub.(map[string]any))
			}
		}
		props, _ := sch["properties"].(map[string]any)
		for name, p := range props {
			ps := p.(map[string]any)
			if notSecrets[name] != "" {
				exempted[name] = true
			} else if secretNameRe.MatchString(name) && ps["type"] != "boolean" && ps["writeOnly"] != true && ps["readOnly"] != true {
				t.Errorf("%s.%s looks like a secret: tag the field api:\"writeonly\" (or readonly if the server sets it)", where, name)
			}
			walk(where+"."+name, ps)
		}
	}
	for _, b := range bodies {
		walk(b.String(), set.schema(b))
	}
	for name := range notSecrets {
		if !exempted[name] {
			t.Errorf("notSecrets lists %q, which no request body has any more; remove it", name)
		}
	}
}

// A JSON error body on a status the description already lists without
// content (the 401/403 every route has) replaces that entry's content
// rather than failing.
func TestOpenAPIErrorBodyOnAuthStatus(t *testing.T) {
	d := routeDoc{Status: 204, ErrorBody: map[int]any{403: scriptValidation{}}}
	got := d.responses(newSchemaSet(d.types()...), "")
	assertJSON(t, "403", got["403"], `{"description":"Forbidden","content":{"application/json":{"schema":{"$ref":"#/components/schemas/ScriptValidation"}}}}`)
	assertJSON(t, "204", got["204"], `{"description":"No Content"}`)
}

// The endpoint serves the spec built from the route table, the same bytes
// on every request.
func TestOpenAPIEndpointServesTheSpec(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	var bodies []string
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		s.handleOpenAPI(rec, httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
		}
		bodies = append(bodies, rec.Body.String())
	}
	var doc struct {
		OpenAPI string         `json:"openapi"`
		Paths   map[string]any `json:"paths"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &doc); err != nil || doc.OpenAPI != "3.2.1" || len(doc.Paths) < 100 {
		t.Fatalf("not the spec: %v, openapi %q, %d paths", err, doc.OpenAPI, len(doc.Paths))
	}
	if bodies[0] != bodies[1] {
		t.Error("the spec changed between requests")
	}
}

// admits reports where JSON value v breaks schema sch: the types, through
// references, wrappers, items and properties. It checks what the spec's
// schemas say, not all of JSON Schema.
func admits(components map[string]any, sch map[string]any, v any, path string) []string {
	if ref, ok := sch["$ref"].(string); ok {
		return admits(components, components[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any), v, path)
	}
	if all, ok := sch["allOf"].([]any); ok {
		var out []string
		for _, s := range all {
			out = append(out, admits(components, s.(map[string]any), v, path)...)
		}
		return out
	}
	if alts, ok := sch["anyOf"].([]any); ok {
		for _, s := range alts {
			if len(admits(components, s.(map[string]any), v, path)) == 0 {
				return nil
			}
		}
		return []string{path + ": matches none of anyOf"}
	}
	var types []string
	switch ty := sch["type"].(type) {
	case string:
		types = []string{ty}
	case []any:
		for _, x := range ty {
			types = append(types, x.(string))
		}
	}
	if types == nil {
		return nil // {}: any value
	}
	kind := "null"
	switch x := v.(type) {
	case bool:
		kind = "boolean"
	case string:
		kind = "string"
	case float64:
		kind = "number"
		if x == float64(int64(x)) {
			kind = "integer"
		}
	case []any:
		kind = "array"
	case map[string]any:
		kind = "object"
	}
	if !slices.Contains(types, kind) && !(kind == "integer" && slices.Contains(types, "number")) {
		return []string{fmt.Sprintf("%s: %s is not %v", path, kind, types)}
	}
	var out []string
	switch x := v.(type) {
	case []any:
		if items, ok := sch["items"].(map[string]any); ok {
			for i, e := range x {
				out = append(out, admits(components, items, e, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	case map[string]any:
		props, _ := sch["properties"].(map[string]any)
		extra, _ := sch["additionalProperties"].(map[string]any)
		for k, e := range x {
			if p, ok := props[k].(map[string]any); ok {
				out = append(out, admits(components, p, e, path+"."+k)...)
			} else if extra != nil {
				out = append(out, admits(components, extra, e, path+"."+k)...)
			}
		}
	}
	return out
}

// What encoding/json writes for a declared type is what its schema
// admits: the zero value of each (nil slices and maps are null), and a
// default record that really is served with nil lists.
func TestOpenAPISchemasAdmitEncodedValues(t *testing.T) {
	var roots []reflect.Type
	for _, d := range routeDocs {
		roots = append(roots, d.types()...)
	}
	set := newSchemaSet(roots...)
	raw, err := json.Marshal(set.components())
	if err != nil {
		t.Fatal(err)
	}
	var components map[string]any
	if err := json.Unmarshal(raw, &components); err != nil {
		t.Fatal(err)
	}
	check := func(name string, typ reflect.Type, value any) {
		t.Helper()
		var sch map[string]any
		b, _ := json.Marshal(set.schema(typ))
		_ = json.Unmarshal(b, &sch)
		enc, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var decoded any
		_ = json.Unmarshal(enc, &decoded)
		for _, p := range admits(components, sch, decoded, name) {
			t.Error(p)
		}
	}
	for _, typ := range roots {
		check(typ.String(), typ, reflect.Zero(typ).Interface())
	}
	prefs := store.DefaultUserPreferences()
	if prefs.HiddenModules != nil {
		t.Fatal("the default preferences no longer have nil lists; pick another value served with one")
	}
	check("DefaultUserPreferences", reflect.TypeOf(prefs), prefs)
}
