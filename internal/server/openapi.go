package server

// The API reference is generated from the route table itself — every
// /api route as registered, with the permission its guard demands and a
// summary taken from the handler's name — so it cannot drift from what
// the server actually serves. What a route reads and writes comes from
// its routeDocs declaration (openapi_routes.go), reflected from Go
// types; the drift test holds each declaration to its handler's source.
// A route without one is described as taking and returning a JSON object.

import (
	"cmp"
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/version"
)

var (
	handlerNameRe = regexp.MustCompile(`\.(handle[A-Za-z0-9]+)(?:-fm)?$`)
	pathParamRe   = regexp.MustCompile(`\{([a-zA-Z_]+)(\.\.\.)?\}`)
)

// unwrapHandler follows the permission guard and action gate to the
// handler that does the work.
func unwrapHandler(h http.Handler) http.Handler {
	for i := 0; i < 5; i++ {
		switch v := h.(type) {
		case *permGuard:
			h = v.next
		case *actionGate:
			h = v.next
		default:
			return h
		}
	}
	return h
}

// handlerSummary turns handleListManagedCerts into "List managed certs".
func handlerSummary(h http.Handler) string {
	f, ok := unwrapHandler(h).(http.HandlerFunc)
	if !ok {
		return ""
	}
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer())
	if fn == nil {
		return ""
	}
	m := handlerNameRe.FindStringSubmatch(fn.Name())
	if m == nil {
		return ""
	}
	name := strings.TrimPrefix(m[1], "handle")
	var words []string
	start := 0
	runes := []rune(name)
	for i := 1; i < len(runes); i++ {
		if unicode.IsUpper(runes[i]) && (unicode.IsLower(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
			words = append(words, string(runes[start:i]))
			start = i
		}
	}
	words = append(words, string(runes[start:]))
	for i, w := range words {
		if i > 0 && !(len(w) > 1 && strings.ToUpper(w) == w) {
			words[i] = strings.ToLower(w)
		}
	}
	return strings.Join(words, " ")
}

// openAPIVersion is the OpenAPI Specification release the document
// follows. Within a minor version a patch only clarifies the text, so
// tooling for 3.2 reads any 3.2.x document.
const openAPIVersion = "3.2.1"

func (s *Server) openAPISpec() map[string]any {
	return s.openAPISpecFrom(routeDocs, bodyExamples, respExamples)
}

// openAPISpecFrom builds the spec with the given declarations, body
// examples and response examples.
func (s *Server) openAPISpecFrom(docs map[string]routeDoc, examples, resps map[string]string) map[string]any {
	paths := map[string]map[string]any{}
	tags := map[string]bool{}
	actions := s.endpointActionRoutes()
	var roots []reflect.Type
	for _, e := range s.routeLog.entries {
		if d, ok := docs[e.Pattern]; ok {
			roots = append(roots, d.types()...)
		}
	}
	schemas := newSchemaSet(roots...)
	for _, e := range s.routeLog.entries {
		method, path, ok := strings.Cut(e.Pattern, " ")
		if !ok || !strings.HasPrefix(path, "/api/") || strings.HasSuffix(path, "/") {
			continue
		}
		oaPath := pathParamRe.ReplaceAllString(path, "{$1}")
		segs := strings.Split(strings.TrimPrefix(path, "/api/"), "/")
		tag := segs[0]
		if tag == "admin" && len(segs) > 1 {
			tag = segs[1]
		}
		// A file's formats are one group: openapi.json and openapi.yaml.
		tag, _, _ = strings.Cut(tag, ".")
		tags[tag] = true
		var params []map[string]any
		for _, m := range pathParamRe.FindAllStringSubmatch(path, -1) {
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]string{"type": "string"}})
		}
		access := "Any signed-in user or API token."
		if pg, ok := e.Handler.(*permGuard); ok && len(pg.perms) > 0 {
			access = "Requires the `" + strings.Join(pg.perms, "` or `") + "` permission."
		}
		if strings.Contains(path, "/admin/") {
			access += " Some changes also require an administrator."
		}
		if _, ok := actions[e.Pattern]; ok {
			access += " An endpoint action: also limited to endpoints the caller may manage (management rights, action groups, approval policies)."
		}
		summary := handlerSummary(e.Handler)
		if summary == "" {
			summary = method + " " + path
		}
		op := map[string]any{
			"operationId": strings.ToLower(method) + strings.Map(func(r rune) rune {
				if unicode.IsLetter(r) || unicode.IsDigit(r) {
					return r
				}
				return '_'
			}, path),
			"summary": summary, "description": access, "tags": []string{tag},
		}
		if doc, documented := docs[e.Pattern]; documented {
			params = append(params, doc.queryParams()...)
			op["responses"] = doc.responses(schemas, resps[e.Pattern])
			if body := doc.requestBody(schemas, examples[e.Pattern]); body != nil {
				op["requestBody"] = body
			}
		} else {
			responses := authResponses()
			responses["200"] = response(http.StatusOK, jsonContent(anyObject()))
			op["responses"] = responses
			if method == "POST" || method == "PUT" || method == "PATCH" {
				op["requestBody"] = map[string]any{"required": false, "content": jsonContent(anyObject())}
			}
		}
		if params != nil {
			op["parameters"] = params
		}
		if paths[oaPath] == nil {
			paths[oaPath] = map[string]any{}
		}
		paths[oaPath][strings.ToLower(method)] = op
	}
	tagList := make([]map[string]string, 0, len(tags))
	for t := range tags {
		tagList = append(tagList, map[string]string{"name": t})
	}
	sort.Slice(tagList, func(i, j int) bool { return tagList[i]["name"] < tagList[j]["name"] })
	return map[string]any{
		"openapi": openAPIVersion,
		"info": map[string]any{"title": "Mustra API", "version": version.Version,
			"description": "Every route the console uses. Authenticate with an API token (Settings → API tokens) as `Authorization: Bearer <token>`; a token carries only the permissions it was given. Generated from the running server's route table.",
			"license":     map[string]string{"name": "AGPL-3.0-only", "identifier": "AGPL-3.0-only"}},
		"servers":  []map[string]string{{"url": "/"}},
		"security": []map[string][]string{{"bearer": {}}, {"session": {}}},
		"components": map[string]any{
			"securitySchemes": map[string]any{"bearer": map[string]string{"type": "http", "scheme": "bearer"}, "session": map[string]string{"type": "apiKey", "in": "cookie", "name": auth.SessionCookieName(true)}},
			"schemas":         schemas.components(),
		},
		"tags":  tagList,
		"paths": paths,
	}
}

func (d routeDoc) queryParams() []map[string]any {
	var out []map[string]any
	for _, q := range d.Query {
		sch := map[string]any{"type": "string"}
		if q.Type != "" {
			sch["type"] = q.Type
		}
		if q.Enum != nil {
			sch["enum"] = q.Enum
		}
		p := map[string]any{"name": q.Name, "in": "query", "required": q.Required, "schema": sch}
		if q.Desc != "" {
			p["description"] = q.Desc
		}
		out = append(out, p)
	}
	return out
}

// requestBody is nil for a route that reads none. example is the JSON
// body's, as written in bodyExamples.
func (d routeDoc) requestBody(schemas *schemaSet, example string) map[string]any {
	content := map[string]any{}
	switch {
	case d.Body != nil:
		sch := schemas.schema(reflect.TypeOf(d.Body))
		if len(d.Required) > 0 {
			sch = map[string]any{"allOf": []any{sch, map[string]any{"required": d.Required}}}
		}
		media := map[string]any{"schema": sch}
		if example != "" {
			media["example"] = json.RawMessage(example)
		}
		content["application/json"] = media
	case d.Upload != nil:
		props := map[string]any{}
		var required []string
		for _, f := range d.Upload {
			p := map[string]any{"type": "string"}
			if f.File {
				// A file part is raw bytes, which have no JSON type.
				p = map[string]any{"contentMediaType": "application/octet-stream"}
			}
			if f.Desc != "" {
				p["description"] = f.Desc
			}
			props[f.Name] = p
			if f.Required {
				required = append(required, f.Name)
			}
		}
		form := map[string]any{"type": "object", "properties": props}
		if required != nil {
			form["required"] = required
		}
		content["multipart/form-data"] = map[string]any{"schema": form}
	case d.Raw != "":
		content[d.Raw] = map[string]any{"schema": rawSchema(d.Raw)}
	default:
		return nil
	}
	return map[string]any{"required": !d.BodyOptional, "content": content}
}

// responses are the route's answers. example is its JSON success
// response's, as written in respExamples; it shows Resp, the main shape.
func (d routeDoc) responses(schemas *schemaSet, example string) map[string]any {
	status := cmp.Or(d.Status, http.StatusOK)
	// A route with both answers JSON unless the request asks for the
	// other (?format=csv, ?download=1).
	content := map[string]any{}
	if d.Resp != nil {
		sch := schemas.schema(reflect.TypeOf(d.Resp))
		if len(d.RespAlt) > 0 {
			alts := []any{sch}
			for _, v := range d.RespAlt {
				alts = append(alts, schemas.schema(reflect.TypeOf(v)))
			}
			sch = map[string]any{"anyOf": alts}
		}
		media := map[string]any{"schema": sch}
		if example != "" {
			media["example"] = json.RawMessage(example)
		}
		content["application/json"] = media
	}
	if d.Content != "" {
		content[d.Content] = map[string]any{"schema": rawSchema(d.Content)}
	}
	if len(content) == 0 && status != http.StatusNoContent {
		content = jsonContent(anyObject())
	}
	out := authResponses()
	out[strconv.Itoa(status)] = response(status, content)
	for _, code := range d.Also {
		out[strconv.Itoa(code)] = response(code, jsonContent(anyObject()))
	}
	// Errors are http.Error's text/plain message, meant for a person,
	// and JSON where the handler writes that for the status instead or too.
	errors := map[int]map[string]any{}
	for _, code := range d.Errors {
		errors[code] = map[string]any{"text/plain": map[string]any{"schema": map[string]string{"type": "string"}}}
	}
	for code, v := range d.ErrorBody {
		if errors[code] == nil {
			errors[code] = map[string]any{}
		}
		errors[code]["application/json"] = map[string]any{"schema": schemas.schema(reflect.TypeOf(v))}
	}
	for code, c := range errors {
		out[strconv.Itoa(code)] = response(code, c)
	}
	return out
}

// authResponses are what every protected route can answer, described or not.
func authResponses() map[string]any {
	return map[string]any{"401": map[string]any{"description": "Not signed in"}, "403": map[string]any{"description": "Missing permission"}}
}

// response is one status's entry: its text, and its body if it has one.
func response(code int, content map[string]any) map[string]any {
	r := map[string]any{"description": http.StatusText(code)}
	if len(content) > 0 {
		r["content"] = content
	}
	return r
}

func jsonContent(schema any) map[string]any {
	return map[string]any{"application/json": map[string]any{"schema": schema}}
}

// anyObject is a JSON object the spec says nothing more about.
func anyObject() map[string]string { return map[string]string{"type": "object"} }

// types are the Go types the declaration names, for the spec's components.
func (d routeDoc) types() []reflect.Type {
	var out []reflect.Type
	for _, v := range append([]any{d.Body, d.Resp}, d.RespAlt...) {
		if v != nil {
			out = append(out, reflect.TypeOf(v))
		}
	}
	for _, v := range d.ErrorBody {
		out = append(out, reflect.TypeOf(v))
	}
	return out
}

// rawSchema describes a non-JSON body: text, or bytes for anything else.
// Raw bytes have no JSON type: since OpenAPI 3.1 they are described by
// contentMediaType, and format no longer says how content is encoded,
// so OpenAPI 3.0's `type: string, format: binary` would claim a string.
func rawSchema(mediaType string) map[string]any {
	if strings.HasPrefix(mediaType, "text/") || strings.Contains(mediaType, "yaml") || strings.Contains(mediaType, "xml") {
		return map[string]any{"type": "string"}
	}
	return map[string]any{"contentMediaType": mediaType}
}

// openAPIDocument is the spec as JSON and as YAML, built from routeLog on
// first use: neither the route table nor the declarations change while
// the server runs. Both are nil if it could not be built.
func (s *Server) openAPIDocument() (jsonDoc, yamlDoc []byte) {
	s.openAPIOnce.Do(func() {
		b, err := json.Marshal(s.openAPISpec())
		if err != nil {
			s.logger.Error("openapi: building the spec failed", "error", err)
			return
		}
		y, err := jsonToYAML(b)
		if err != nil {
			s.logger.Error("openapi: writing the spec as YAML failed", "error", err)
			return
		}
		s.openAPI, s.openAPIYAML = b, y
	})
	return s.openAPI, s.openAPIYAML
}

// GET /api/openapi.json
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	doc, _ := s.openAPIDocument()
	if doc == nil {
		http.Error(w, "the API description could not be built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(doc)
}

// GET /api/openapi.yaml: the same document, for tools that take YAML.
func (s *Server) handleOpenAPIYAML(w http.ResponseWriter, r *http.Request) {
	_, doc := s.openAPIDocument()
	if doc == nil {
		http.Error(w, "the API description could not be built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(doc)
}
