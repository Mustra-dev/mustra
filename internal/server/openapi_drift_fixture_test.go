package server

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"path"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// driftFixture is handler source for the drift checker's own tests: one
// handler per shape the checker has to tell apart.
const driftFixture = `package server

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/mustra-dev/mustra/internal/fixturecheck"
	"github.com/mustra-dev/mustra/internal/proto"
)

type Server struct{ store fixtureStore }

func (s *Server) handleNamed(w http.ResponseWriter, r *http.Request) {
	var req setSensorIntervalRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.IntervalSeconds < 60 {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if !sensorNamePattern.MatchString(req.Sensor) {
		http.Error(w, "unknown sensor", http.StatusBadRequest)
		return
	}
	var result proto.AgentCommandResult
	writeJSONResponse(w, result)
}

func (s *Server) handleMapReply(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, map[string]any{"ok": true})
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := parseLimit(q)
	_ = limit
	if r.URL.Query().Get("takeover") == "1" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, "nope", 404)
}

func parseLimit(q url.Values) string { return q.Get("limit") }

func (s *Server) handleDecodesViaHelper(w http.ResponseWriter, r *http.Request) {
	s.readBody(w, r)
}

func (s *Server) readBody(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)
	var body map[string]string
	_ = json.Unmarshal(raw, &body)
}

func (s *Server) handleSharedByMethods(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSONResponse(w, map[string]any{"values": nil})
		return
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	setSSEHeaders(w)
}

func setSSEHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
}

func (s *Server) handleParks(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if s.parked() {
		w.WriteHeader(http.StatusAccepted)
		writeJSONResponse(w, map[string]any{"approval_required": true})
		return
	}
	var result proto.AgentCommandResult
	writeJSONResponse(w, result)
}

func (s *Server) handleJSONError(w http.ResponseWriter, r *http.Request) {
	if s.invalid() {
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeJSONResponse(w, scriptValidation{})
		return
	}
	writeJSONResponse(w, proto.AgentCommandResult{})
}

func (s *Server) handleDefaults(w http.ResponseWriter, r *http.Request) {
	var req createAPITokenRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.TrimSpace(req.Name) == "" {
		req.Name = "token"
	}
}

func (s *Server) handleHelperTwice(w http.ResponseWriter, r *http.Request) {
	s.decodeFrom(w, nil)
	s.decodeFrom(w, r.Body)
}

func (s *Server) decodeFrom(w http.ResponseWriter, body io.Reader) {
	var req map[string]string
	_ = json.NewDecoder(body).Decode(&req)
}

func (s *Server) handleGuardedHelper(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 0 {
		s.decodeStrict(w, r.Body)
	}
}

func (s *Server) decodeStrict(w http.ResponseWriter, body io.Reader) {
	var req map[string]string
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
	}
}

func (s *Server) handleThroughLocal(w http.ResponseWriter, r *http.Request) {
	var req shellExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	command := strings.TrimSpace(req.Command)
	if command == "" {
		http.Error(w, "empty command", http.StatusBadRequest)
	}
}

func (s *Server) handleThroughAssignment(w http.ResponseWriter, r *http.Request) {
	var req deployReferencesRequest
	replacement := ""
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	replacement = req.Replacement
	if replacement == "" || len(req.References) == 0 {
		http.Error(w, "select a replacement", http.StatusBadRequest)
	}
}

func (s *Server) handleThroughLookup(w http.ResponseWriter, r *http.Request) {
	var req setTrustRootRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	modes := map[string]string{"all": "all", "off": ""}
	v, ok := modes[req.Mode]
	if !ok {
		http.Error(w, "unknown mode", http.StatusBadRequest)
	}
	_ = v
}

func (s *Server) handleThroughIndex(w http.ResponseWriter, r *http.Request) {
	var req setCriticalityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		http.Error(w, "no endpoint", http.StatusBadRequest)
		return
	}
	if levels[req.Level] == "" {
		http.Error(w, "unknown level", http.StatusBadRequest)
	}
}

func (s *Server) handleDeepStatus(w http.ResponseWriter, r *http.Request) {
	s.deepOne(w, r)
}

func (s *Server) deepOne(w http.ResponseWriter, r *http.Request)   { s.deepTwo(w, r) }
func (s *Server) deepTwo(w http.ResponseWriter, r *http.Request)   { s.deepThree(w, r) }
func (s *Server) deepThree(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }

func (s *Server) handleTokenStrict(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || len(req.Permissions) == 0 {
		http.Error(w, "a name and a permission are required", http.StatusBadRequest)
	}
}

func (s *Server) handleTokenLoose(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
	}
}

func (s *Server) handleHelperRejects(w http.ResponseWriter, r *http.Request) {
	var req userIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		writeFixtureError(w)
	}
}

func writeFixtureError(w http.ResponseWriter) {
	http.Error(w, "a user is required", http.StatusBadRequest)
}

func (s *Server) handleTwoAnswers(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("preview") == "1" {
		writeJSONResponse(w, scriptValidation{})
		return
	}
	writeJSONResponse(w, proto.AgentCommandResult{})
}

func (s *Server) handleRefuses(w http.ResponseWriter, r *http.Request) {
	if s.gone() {
		http.NotFound(w, r)
		return
	}
	if s.denied() {
		writeJSONError(w, http.StatusForbidden, map[string]any{"error": "not allowed"})
		return
	}
	writeJSONResponse(w, proto.AgentCommandResult{})
}

func (s *Server) handleLeftoverMap(w http.ResponseWriter, r *http.Request) {
	if s.parked() {
		writeJSONResponse(w, map[string]any{"already": true})
		return
	}
	writeJSONResponse(w, proto.AgentCommandResult{})
}

func (s *Server) handleRunOrPreview(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/preview") {
		writeJSONResponse(w, scriptValidation{})
		return
	}
	writeJSONResponse(w, proto.AgentCommandResult{})
}

func (s *Server) handleForwards(w http.ResponseWriter, r *http.Request) {
	s.handleRunOrPreview(w, r)
}

func (s *Server) handleUnchecked(w http.ResponseWriter, r *http.Request) {
	var req userIDRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
}

func (s *Server) handleSwitchCase(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	switch {
	case strings.TrimSpace(req.Name) == "":
		http.Error(w, "name it", http.StatusBadRequest)
	case len(req.Permissions) == 0:
		http.Error(w, "grant something", http.StatusBadRequest)
	}
}

func (s *Server) handleSwitchAfterSkip(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	switch {
	case req.Kind == "all":
		return
	case len(req.Permissions) == 0:
		http.Error(w, "grant something", http.StatusBadRequest)
	}
}

func (s *Server) handleSwitchTag(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	switch req.Kind {
	case "allow", "block":
	default:
		http.Error(w, "allow or block", http.StatusBadRequest)
	}
}

func (s *Server) handleSwitchTagZero(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	switch req.Kind {
	case "", "allow":
	default:
		http.Error(w, "allow or nothing", http.StatusBadRequest)
	}
}

func (s *Server) handleValidator(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := validateFixture(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if problem := fixturecheck.Problem(req.Permissions); problem != "" {
		http.Error(w, problem, http.StatusBadRequest)
	}
}

func validateFixture(req *driftFixtureRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New("name it")
	}
	if req.Kind == "" {
		req.Kind = "allow"
	}
	return nil
}

func (s *Server) handleLookupByField(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	thing, err := s.store.GetThing(r.Context(), req.Kind)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if thing == nil {
		http.NotFound(w, r)
	}
}

func (s *Server) handleUnmarshalField(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var v map[string]string
	if err := json.Unmarshal(req.Raw, &v); err != nil {
		http.Error(w, "raw is not JSON", http.StatusBadRequest)
	}
}

func (s *Server) handleFilledLocal(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	perms := []string{}
	for _, p := range req.Permissions {
		if p = strings.TrimSpace(p); p != "" {
			perms = append(perms, p)
		}
	}
	if len(perms) == 0 {
		http.Error(w, "grant something", http.StatusBadRequest)
	}
}

func (s *Server) handleAllowedValues(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if !slices.Contains([]string{"allow", "block"}, req.Kind) {
		http.Error(w, "allow or block", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.URL, "https://") && !strings.HasPrefix(req.URL, "http://") {
		http.Error(w, "a web address", http.StatusBadRequest)
	}
}

func (s *Server) handleConditionalErr(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var v map[string]string
	var err error
	if len(req.Raw) > 0 {
		err = json.Unmarshal(req.Raw, &v)
	}
	if err != nil {
		http.Error(w, "raw is not JSON", http.StatusBadRequest)
	}
}

func (s *Server) handleReassignedErr(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var v map[string]string
	err := json.Unmarshal(req.Raw, &v)
	err = errFixture
	if err != nil {
		http.Error(w, "refused", http.StatusBadRequest)
	}
}

func (s *Server) handleCopiedLocal(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	perms := map[string]bool{}
	maps.Copy(perms, fixtureDefaults)
	for _, p := range req.Permissions {
		perms[p] = true
	}
	if len(perms) == 0 {
		http.Error(w, "grant something", http.StatusBadRequest)
	}
}

func (s *Server) handleAddressedLocal(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var perms []string
	loadFixtureDefaults(&perms)
	for _, p := range req.Permissions {
		perms = append(perms, p)
	}
	if len(perms) == 0 {
		http.Error(w, "grant something", http.StatusBadRequest)
	}
}

func (s *Server) handleValidatorServerError(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := validateFixture(&req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleValidatorPassesOn(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := checkFixtureLoosely(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func checkFixtureLoosely(req *driftFixtureRequest) error {
	if req.Kind == "" {
		return lookupFixtureKind(req)
	}
	if req.URL == "" {
		if strictFixture {
			return errors.New("a web address")
		}
	}
	return nil
}

func (s *Server) handleSwitchNormalized(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	switch normalizeFixtureKind(req.Kind) {
	case "allow", "block":
	default:
		http.Error(w, "allow or block", http.StatusBadRequest)
	}
}

func (s *Server) handleSwitchTrimmed(w http.ResponseWriter, r *http.Request) {
	var req driftFixtureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	switch strings.ToLower(strings.TrimSpace(req.Kind)) {
	case "allow", "block":
	default:
		http.Error(w, "allow or block", http.StatusBadRequest)
	}
}

func (s *Server) handleCSV(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("format") == "csv" {
		ctype := "text/csv; charset=utf-8"
		w.Header().Set("Content-Type", ctype)
		return
	}
	writeJSONResponse(w, map[string]any{"rows": nil})
}
`

// driftFixtureCheck is a validator in another package of the repository,
// which a fixture handler hands a field to.
const driftFixtureCheck = `package fixturecheck

func Problem(items []string) string {
	if len(items) == 0 {
		return "grant something"
	}
	return ""
}
`

// driftFixtureRequest is a body for the checker's own tests, whose tags
// they control: a name tagged required, and fields that are not.
type driftFixtureRequest struct {
	Name        string          `json:"name" api:"required"`
	Kind        string          `json:"kind"`
	URL         string          `json:"url"`
	Permissions []string        `json:"permissions"`
	Raw         json.RawMessage `json:"raw"`
}

func driftFixtureSource(t *testing.T) *driftSource {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", strings.Replace(driftFixture, `"net/http"`, "\"net/http\"\n\t\"net/url\"", 1), 0)
	if err != nil {
		t.Fatal(err)
	}
	check, err := parser.ParseFile(fset, "fixturecheck.go", driftFixtureCheck, 0)
	if err != nil {
		t.Fatal(err)
	}
	src := newDriftSource()
	src.add(serverPkgPath, f)
	src.add(path.Dir(serverPkgPath)+"/fixturecheck", check)
	return src
}

var driftFixtureRoutes = map[string]string{
	"POST /api/named":           "handleNamed",
	"POST /api/map":             "handleMapReply",
	"DELETE /api/query/{id}":    "handleQuery",
	"POST /api/helper":          "handleDecodesViaHelper",
	"GET /api/shared":           "handleSharedByMethods",
	"PUT /api/shared":           "handleSharedByMethods",
	"GET /api/stream":           "handleStream",
	"POST /api/parks":           "handleParks",
	"GET /api/json-error":       "handleJSONError",
	"GET /api/csv":              "handleCSV",
	"POST /api/defaults":        "handleDefaults",
	"POST /api/unchecked":       "handleUnchecked",
	"POST /api/twice":           "handleHelperTwice",
	"POST /api/guarded":         "handleGuardedHelper",
	"POST /api/local":           "handleThroughLocal",
	"POST /api/assigned":        "handleThroughAssignment",
	"POST /api/lookup":          "handleThroughLookup",
	"POST /api/index":           "handleThroughIndex",
	"POST /api/deep":            "handleDeepStatus",
	"POST /api/token-strict":    "handleTokenStrict",
	"POST /api/token-loose":     "handleTokenLoose",
	"POST /api/helper-error":    "handleHelperRejects",
	"GET /api/two-answers":      "handleTwoAnswers",
	"GET /api/refuses":          "handleRefuses",
	"GET /api/leftover":         "handleLeftoverMap",
	"GET /api/forwards":         "handleForwards",
	"POST /api/switch":          "handleSwitchCase",
	"POST /api/switch-skip":     "handleSwitchAfterSkip",
	"POST /api/switch-tag":      "handleSwitchTag",
	"POST /api/switch-zero":     "handleSwitchTagZero",
	"POST /api/validator":       "handleValidator",
	"POST /api/lookup-field":    "handleLookupByField",
	"POST /api/unmarshal":       "handleUnmarshalField",
	"POST /api/filled":          "handleFilledLocal",
	"POST /api/allowed":         "handleAllowedValues",
	"POST /api/err-maybe":       "handleConditionalErr",
	"POST /api/err-again":       "handleReassignedErr",
	"POST /api/copied":          "handleCopiedLocal",
	"POST /api/addressed":       "handleAddressedLocal",
	"POST /api/validator-5xx":   "handleValidatorServerError",
	"POST /api/validator-loose": "handleValidatorPassesOn",
	"POST /api/switch-normal":   "handleSwitchNormalized",
	"POST /api/switch-trim":     "handleSwitchTrimmed",
}

// Declarations that match the fixture handlers pass.
func TestDriftCheckPassesMatchingDeclarations(t *testing.T) {
	docs := map[string]routeDoc{
		"POST /api/named":        {Body: setSensorIntervalRequest{}, Resp: proto.AgentCommandResult{}, Errors: []int{400}},
		"POST /api/map":          {NoBody: true},
		"DELETE /api/query/{id}": {Query: []queryParam{{Name: "limit"}, flag("takeover", "")}, Status: 204, Errors: []int{404}},
		"POST /api/helper":       {Body: map[string]string{}, BodyOptional: true},
		"GET /api/shared":        {},
		"PUT /api/shared":        {Body: map[string]string{}, BodyOptional: true},
		"GET /api/stream":        {Content: "text/event-stream"},
		"POST /api/parks":        {Body: map[string]string{}, Resp: proto.AgentCommandResult{}, Also: []int{202}, Errors: []int{400}},
		"GET /api/json-error":    {Resp: proto.AgentCommandResult{}, ErrorBody: map[int]any{422: scriptValidation{}}},
		"GET /api/csv":           {Query: []queryParam{{Name: "format", Enum: []string{"csv"}}}, Resp: map[string]any{}, Content: "text/csv"},
	}
	// Required fields checked through a local, an assignment, a comma-ok
	// lookup and a map index.
	docs["POST /api/local"] = routeDoc{Body: shellExecRequest{}, Errors: []int{400}}
	docs["POST /api/assigned"] = routeDoc{Body: deployReferencesRequest{}, Errors: []int{400}}
	docs["POST /api/lookup"] = routeDoc{Body: setTrustRootRequest{}, Errors: []int{400}}
	docs["POST /api/index"] = routeDoc{Body: setCriticalityRequest{}, Errors: []int{400}}
	// A field one route requires beyond its shared type, and a rejection
	// written through a helper.
	docs["POST /api/token-strict"] = routeDoc{Body: driftFixtureRequest{}, Required: []string{"permissions"}, Errors: []int{400}}
	docs["POST /api/helper-error"] = routeDoc{Body: userIDRequest{}, Errors: []int{400}}
	// Required fields checked in a switch without a tag, in a switch on
	// the field, in a validator in this package and in another one, by a
	// lookup that finds nothing, and in each of the other shapes the
	// checker reads (each of which would otherwise ask for a tag).
	docs["POST /api/switch"] = routeDoc{Body: driftFixtureRequest{}, Required: []string{"permissions"}, Errors: []int{400}}
	docs["POST /api/switch-skip"] = routeDoc{Body: driftFixtureRequest{}, Required: []string{"permissions"}, Errors: []int{400}}
	docs["POST /api/switch-tag"] = routeDoc{Body: driftFixtureRequest{}, Required: []string{"kind"}, Errors: []int{400}}
	docs["POST /api/validator"] = routeDoc{Body: driftFixtureRequest{}, Required: []string{"permissions"}, Errors: []int{400}}
	docs["POST /api/lookup-field"] = routeDoc{Body: driftFixtureRequest{}, Required: []string{"kind"}, Errors: []int{400, 404, 500}}
	docs["POST /api/unmarshal"] = routeDoc{Body: driftFixtureRequest{}, Required: []string{"raw"}, Errors: []int{400}}
	docs["POST /api/filled"] = routeDoc{Body: driftFixtureRequest{}, Required: []string{"permissions"}, Errors: []int{400}}
	docs["POST /api/allowed"] = routeDoc{Body: driftFixtureRequest{}, Required: []string{"kind", "url"}, Errors: []int{400}}
	// A success answer of one type or another.
	docs["GET /api/two-answers"] = routeDoc{Query: []queryParam{flag("preview", "")}, Resp: proto.AgentCommandResult{}, RespAlt: []any{scriptValidation{}}}
	// A refusal written as JSON through writeJSONError.
	docs["GET /api/refuses"] = routeDoc{Resp: proto.AgentCommandResult{}, Errors: []int{404}, ErrorBody: map[int]any{403: map[string]any{}}}
	// A map answer beside a named one, declared as any object.
	docs["GET /api/leftover"] = routeDoc{Resp: proto.AgentCommandResult{}, RespAlt: []any{map[string]any{}}}
	// A forward into another route's handler, past a branch only that
	// route takes.
	docs["GET /api/forwards"] = routeDoc{Resp: proto.AgentCommandResult{}}
	unreached := driftExceptions{writesUnreached: map[string]string{"handleForwards scriptValidation": "only /preview answers it"}}
	if got := checkDrift(driftFixtureSource(t), driftFixtureRoutes, docs, unreached); len(got) != 0 {
		t.Errorf("matching declarations reported:\n%s", strings.Join(got, "\n"))
	}
}

// DriftOK skips the checks for a handler whose source the checker cannot
// follow, and says why.
func TestDriftCheckSkipsDriftOK(t *testing.T) {
	docs := map[string]routeDoc{"POST /api/named": {NoBody: true, DriftOK: "decodes through a helper the checker cannot follow"}}
	if got := checkDrift(driftFixtureSource(t), map[string]string{"POST /api/named": "handleNamed"}, docs, driftExceptions{}); len(got) != 0 {
		t.Errorf("DriftOK still reported:\n%s", strings.Join(got, "\n"))
	}
}

// Each kind of disagreement between a declaration and its handler is
// reported.
func TestDriftCheckCatchesDisagreements(t *testing.T) {
	good := map[string]routeDoc{
		"POST /api/named":        {Body: setSensorIntervalRequest{}, Resp: proto.AgentCommandResult{}},
		"POST /api/map":          {NoBody: true},
		"DELETE /api/query/{id}": {Query: []queryParam{{Name: "limit"}, flag("takeover", "")}, Status: 204},
		"POST /api/helper":       {Body: map[string]string{}, BodyOptional: true},
		"GET /api/shared":        {},
		"PUT /api/shared":        {Body: map[string]string{}, BodyOptional: true},
		"GET /api/stream":        {Content: "text/event-stream"},
		"POST /api/parks":        {Body: map[string]string{}, Resp: proto.AgentCommandResult{}, Also: []int{202}, Errors: []int{400}},
		"GET /api/json-error":    {Resp: proto.AgentCommandResult{}, ErrorBody: map[int]any{422: scriptValidation{}}},
		"GET /api/csv":           {Query: []queryParam{{Name: "format", Enum: []string{"csv"}}}, Resp: map[string]any{}, Content: "text/csv"},
		"POST /api/token-strict": {Body: driftFixtureRequest{}, Required: []string{"permissions"}, Errors: []int{400}},
		"GET /api/two-answers":   {Query: []queryParam{flag("preview", "")}, Resp: proto.AgentCommandResult{}, RespAlt: []any{scriptValidation{}}},
		"GET /api/refuses":       {Resp: proto.AgentCommandResult{}, Errors: []int{404}, ErrorBody: map[int]any{403: map[string]any{}}},
		"GET /api/leftover":      {Resp: proto.AgentCommandResult{}, RespAlt: []any{map[string]any{}}},
	}
	for _, c := range []struct {
		name    string
		pattern string
		doc     *routeDoc // nil removes the route's declaration
		want    string
	}{
		{"a body type the handler does not decode", "POST /api/named", &routeDoc{Body: store.EUNMessage{}, Resp: proto.AgentCommandResult{}},
			"declares Body store.EUNMessage, but the handler decodes setSensorIntervalRequest"},
		{"a body decoded in a helper, declared as none", "POST /api/helper", &routeDoc{NoBody: true},
			"declares NoBody, but the handler reads one"},
		{"a mutating route that says nothing about its body", "POST /api/map", &routeDoc{},
			"declare what the body is"},
		{"an undeclared query key", "DELETE /api/query/{id}", &routeDoc{Query: []queryParam{flag("takeover", "")}, Status: 204},
			`the handler reads query parameter "limit"; declare it`},
		{"a declared query key nobody reads", "DELETE /api/query/{id}", &routeDoc{Query: []queryParam{{Name: "limit"}, flag("takeover", ""), {Name: "page"}}, Status: 204},
			`declares query parameter "page", which the handler never reads`},
		{"a response written as a map literal", "POST /api/map", &routeDoc{NoBody: true, Resp: proto.AgentCommandResult{}},
			"declares Resp proto.AgentCommandResult, but the handler writes a map or anonymous struct; convert this response to a named struct"},
		{"a named response left undeclared", "POST /api/named", &routeDoc{Body: setSensorIntervalRequest{}},
			"the handler writes proto.AgentCommandResult; declare it as Resp"},
		{"a 204 left undeclared", "DELETE /api/query/{id}", &routeDoc{Query: []queryParam{{Name: "limit"}, flag("takeover", "")}},
			"the handler responds 204; declare Status: 204"},
		{"an error the handler never returns", "DELETE /api/query/{id}", &routeDoc{Query: []queryParam{{Name: "limit"}, flag("takeover", "")}, Status: 204, Errors: []int{409}},
			"declares error 409, which the handler never returns"},
		{"a stream left undeclared", "GET /api/stream", &routeDoc{},
			"the handler sends text/event-stream; declare it as Content"},
		{"half of a shared handler declared", "GET /api/shared", nil,
			"handleSharedByMethods also serves GET /api/shared; declare all of its routes"},
		{"a second success status left undeclared", "POST /api/parks", &routeDoc{Body: map[string]string{}, Resp: proto.AgentCommandResult{}, Errors: []int{400}},
			"the handler responds 202; declare Status: 202, or Also: []int{202} beside a 200"},
		{"a JSON error body left undeclared", "GET /api/json-error", &routeDoc{Resp: proto.AgentCommandResult{}, Errors: []int{422}},
			"the handler answers 422 with scriptValidation; declare ErrorBody: map[int]any{422: …}"},
		{"a JSON error body declared wrong", "GET /api/json-error", &routeDoc{Resp: proto.AgentCommandResult{}, ErrorBody: map[int]any{422: proto.AgentCommandResult{}}},
			"declares ErrorBody 422 proto.AgentCommandResult, but the handler writes scriptValidation"},
		{"a route that is a download and JSON otherwise", "GET /api/csv", &routeDoc{Query: []queryParam{{Name: "format", Enum: []string{"csv"}}}, Content: "text/csv"},
			"the handler also writes JSON; declare Resp"},
		{"a required field the handler fills in", "POST /api/defaults", &routeDoc{Body: createAPITokenRequest{}},
			"createAPITokenRequest.name is tagged required, but a handler fills it in when it is missing"},
		{"a required field no handler rejects", "POST /api/unchecked", &routeDoc{Body: userIDRequest{}},
			"POST /api/unchecked: server.userIDRequest.user_id is tagged required, but this handler does not reject a request without it"},
		{"a shared type's required field one handler does not check", "POST /api/token-loose", &routeDoc{Body: driftFixtureRequest{}, Errors: []int{400}},
			"POST /api/token-loose: server.driftFixtureRequest.name is tagged required, but this handler does not reject a request without it"},
		{"a route requirement the handler does not check", "POST /api/token-loose", &routeDoc{Body: driftFixtureRequest{}, Required: []string{"permissions"}, Errors: []int{400}},
			"POST /api/token-loose: declares permissions required, but this handler does not reject a request without it"},
		{"a route requirement naming no field", "POST /api/token-strict", &routeDoc{Body: driftFixtureRequest{}, Required: []string{"permissions", "nope"}, Errors: []int{400}},
			`POST /api/token-strict: declares Required "nope", which server.driftFixtureRequest has no field for`},
		{"a field the handler rejects, left optional", "POST /api/token-strict", &routeDoc{Body: driftFixtureRequest{}, Errors: []int{400}},
			`POST /api/token-strict: the handler rejects a request without permissions; tag it api:"required", or list it in Required`},
		{"a body handed to a helper seen before without one", "POST /api/twice", &routeDoc{NoBody: true},
			"declares NoBody, but the handler reads one (decodes map[string]string)"},
		{"a body the handler can do without, declared required", "PUT /api/shared", &routeDoc{Body: map[string]string{}},
			"the handler accepts a request without a body; declare BodyOptional"},
		{"a body read by a helper only when there is one", "POST /api/guarded", &routeDoc{Body: map[string]string{}, Errors: []int{400}},
			"POST /api/guarded: the handler accepts a request without a body; declare BodyOptional"},
		{"an optional body the handler insists on", "POST /api/named", &routeDoc{Body: setSensorIntervalRequest{}, Resp: proto.AgentCommandResult{}, BodyOptional: true},
			"declares BodyOptional, but the handler rejects a request without a body"},
		{"a status set three calls down", "POST /api/deep", &routeDoc{NoBody: true},
			"POST /api/deep: the handler responds 202; declare Status: 202, or Also: []int{202} beside a 200"},
		{"a second success answer left undeclared", "GET /api/two-answers", &routeDoc{Query: []queryParam{flag("preview", "")}, Resp: proto.AgentCommandResult{}},
			"GET /api/two-answers: the handler writes scriptValidation; declare it as Resp"},
		{"an alternative answer the handler never writes", "GET /api/two-answers", &routeDoc{Query: []queryParam{flag("preview", "")}, Resp: proto.AgentCommandResult{}, RespAlt: []any{scriptValidation{}, store.EUNMessage{}}},
			"GET /api/two-answers: declares RespAlt store.EUNMessage, but the handler writes "},
		{"a JSON refusal left undeclared", "GET /api/refuses", &routeDoc{Resp: proto.AgentCommandResult{}},
			"GET /api/refuses: the handler answers 403 with map[string]any; declare ErrorBody"},
		{"a text error left undeclared", "GET /api/refuses", &routeDoc{Resp: proto.AgentCommandResult{}, ErrorBody: map[int]any{403: map[string]any{}}},
			"GET /api/refuses: the handler returns 404; declare it in Errors or ErrorBody"},
		{"a map answer beside a named one", "GET /api/leftover", &routeDoc{Resp: proto.AgentCommandResult{}},
			"GET /api/leftover: the handler also writes a map or anonymous struct; convert it to a named struct and declare it in RespAlt"},
		{"a switch case that rejects, its field left optional", "POST /api/switch", &routeDoc{Body: driftFixtureRequest{}, Errors: []int{400}},
			`POST /api/switch: the handler rejects a request without permissions; tag it api:"required", or list it in Required`},
		{"a switch on a field whose default rejects, the field left optional", "POST /api/switch-tag", &routeDoc{Body: driftFixtureRequest{}, Errors: []int{400}},
			`POST /api/switch-tag: the handler rejects a request without kind; tag it api:"required", or list it in Required`},
		{"a switch on a field with a case for its zero value", "POST /api/switch-zero", &routeDoc{Body: driftFixtureRequest{}, Required: []string{"kind"}, Errors: []int{400}},
			"POST /api/switch-zero: declares kind required, but this handler does not reject a request without it"},
		{"a validator that fills a field in rather than rejecting", "POST /api/validator", &routeDoc{Body: driftFixtureRequest{}, Required: []string{"kind"}, Errors: []int{400}},
			"POST /api/validator: declares kind required, but this handler does not reject a request without it"},
		{"a field parsed as JSON, left optional", "POST /api/unmarshal", &routeDoc{Body: driftFixtureRequest{}, Errors: []int{400}},
			`POST /api/unmarshal: the handler rejects a request without raw; tag it api:"required", or list it in Required`},
		{"a field copied into a local that must not be empty, left optional", "POST /api/filled", &routeDoc{Body: driftFixtureRequest{}, Errors: []int{400}},
			`POST /api/filled: the handler rejects a request without permissions; tag it api:"required", or list it in Required`},
		{"a field that must be one of a list, left optional", "POST /api/allowed", &routeDoc{Body: driftFixtureRequest{}, Required: []string{"url"}, Errors: []int{400}},
			`POST /api/allowed: the handler rejects a request without kind; tag it api:"required", or list it in Required`},
		{"a field that must have a prefix, left optional", "POST /api/allowed", &routeDoc{Body: driftFixtureRequest{}, Required: []string{"kind"}, Errors: []int{400}},
			`POST /api/allowed: the handler rejects a request without url; tag it api:"required", or list it in Required`},
		{"a declaration for no registered route", "GET /api/nowhere", &routeDoc{},
			"GET /api/nowhere: routeDocs declares a route that is not registered"},
	} {
		t.Run(c.name, func(t *testing.T) {
			docs := map[string]routeDoc{}
			for k, v := range good {
				docs[k] = v
			}
			if c.doc == nil {
				delete(docs, c.pattern)
			} else {
				docs[c.pattern] = *c.doc
			}
			got := checkDrift(driftFixtureSource(t), driftFixtureRoutes, docs, driftExceptions{})
			if !strings.Contains(strings.Join(got, "\n"), c.want) {
				t.Errorf("want a problem containing %q, got:\n%s", c.want, strings.Join(got, "\n"))
			}
		})
	}
}

// A response a forwarding handler never reaches passes when the list of
// such writes names it; a name that no longer applies is reported.
func TestDriftCheckWritesUnreached(t *testing.T) {
	routes := map[string]string{"GET /api/forwards": "handleForwards"}
	docs := map[string]routeDoc{"GET /api/forwards": {Resp: proto.AgentCommandResult{}}}
	got := checkDrift(driftFixtureSource(t), routes, docs, driftExceptions{})
	if want := "GET /api/forwards: the handler writes scriptValidation; declare it as Resp"; !strings.Contains(strings.Join(got, "\n"), want) {
		t.Errorf("want %q, got:\n%s", want, strings.Join(got, "\n"))
	}
	listed := map[string]string{"handleForwards scriptValidation": "only /preview answers it", "handleGone proto.AgentCommandResult": "no longer applies"}
	got = checkDrift(driftFixtureSource(t), routes, docs, driftExceptions{writesUnreached: listed})
	if want := "handleGone proto.AgentCommandResult: writesUnreached lists a response the handler does not write undeclared; remove it"; strings.Join(got, "\n") != want {
		t.Errorf("want only %q, got:\n%s", want, strings.Join(got, "\n"))
	}
}

// A check the handler does not reach for every missing value does not
// ask for a tag: a switch case after one that lets the request through,
// a lookup (an empty key might find something), and a validator (which
// is not the handler's own statement).
func TestDriftCheckOptionalWhenNotSure(t *testing.T) {
	routes := map[string]string{"POST /api/switch-skip": "handleSwitchAfterSkip", "POST /api/lookup-field": "handleLookupByField", "POST /api/validator": "handleValidator"}
	docs := map[string]routeDoc{
		"POST /api/switch-skip":  {Body: driftFixtureRequest{}, Errors: []int{400}},
		"POST /api/lookup-field": {Body: driftFixtureRequest{}, Errors: []int{400, 404, 500}},
		"POST /api/validator":    {Body: driftFixtureRequest{}, Errors: []int{400}},
	}
	if got := checkDrift(driftFixtureSource(t), routes, docs, driftExceptions{}); len(got) != 0 {
		t.Errorf("an unsure check asked for a tag:\n%s", strings.Join(got, "\n"))
	}
}

// What only might reject a missing field neither asks for a tag nor
// vouches for one: an error assigned on some paths only, or replaced
// before the test; a local something else may fill (a call it is handed
// to, its address taken); a validator whose problem ends in a 500, or
// which returns a problem it did not make itself or only sometimes; and a
// switch on what a function makes of the field.
func TestDriftCheckUnsureChecks(t *testing.T) {
	for _, c := range []struct {
		name, pattern string
		required      []string
		want          string // "" for no problem
	}{
		{"an error assigned on one path only", "POST /api/err-maybe", nil, ""},
		{"an error replaced before the test", "POST /api/err-again", nil, ""},
		{"a local a call fills too", "POST /api/copied", nil, ""},
		{"a local whose address is handed out", "POST /api/addressed", nil, ""},
		{"a validator whose problem is a 500", "POST /api/validator-5xx", nil,
			"POST /api/validator-5xx: server.driftFixtureRequest.name is tagged required, but this handler does not reject a request without it"},
		{"a validator returning a problem it did not make", "POST /api/validator-loose", []string{"kind"},
			"POST /api/validator-loose: declares kind required, but this handler does not reject a request without it"},
		{"a validator returning a problem only sometimes", "POST /api/validator-loose", []string{"url"},
			"POST /api/validator-loose: declares url required, but this handler does not reject a request without it"},
		{"a switch on what a function makes of a field", "POST /api/switch-normal", nil, ""},
		{"a switch on the field, trimmed and lower-cased", "POST /api/switch-trim", nil,
			`POST /api/switch-trim: the handler rejects a request without kind; tag it api:"required", or list it in Required`},
	} {
		t.Run(c.name, func(t *testing.T) {
			routes := map[string]string{c.pattern: driftFixtureRoutes[c.pattern]}
			errs := []int{400}
			if c.pattern == "POST /api/validator-5xx" {
				errs = append(errs, 500)
			}
			docs := map[string]routeDoc{c.pattern: {Body: driftFixtureRequest{}, Required: c.required, Errors: errs}}
			got := strings.Join(checkDrift(driftFixtureSource(t), routes, docs, driftExceptions{}), "\n")
			if got != c.want {
				t.Errorf("want %q, got:\n%s", c.want, got)
			}
		})
	}
}

// A required field whose check the analyzer cannot follow passes when
// the list of such fields names it; a name that no longer applies is
// reported.
func TestDriftCheckRequiredUnseen(t *testing.T) {
	routes := map[string]string{"POST /api/unchecked": "handleUnchecked"}
	docs := map[string]routeDoc{"POST /api/unchecked": {Body: userIDRequest{}}}
	if got := checkDrift(driftFixtureSource(t), routes, docs, driftExceptions{requiredUnseen: map[string]string{"server.userIDRequest.user_id": "a helper checks it"}}); len(got) != 0 {
		t.Errorf("a listed field reported:\n%s", strings.Join(got, "\n"))
	}
	got := checkDrift(driftFixtureSource(t), routes, docs, driftExceptions{requiredUnseen: map[string]string{"server.userIDRequest.user_id": "a helper checks it", "server.gone.field": "no longer exists"}})
	if want := "server.gone.field: requiredUnseen lists a field that is not a required field of a declared body"; !strings.Contains(strings.Join(got, "\n"), want) {
		t.Errorf("want %q, got:\n%s", want, strings.Join(got, "\n"))
	}
	// Nor may it list a check the analyzer sees.
	routes, docs = map[string]string{"POST /api/validator": "handleValidator"}, map[string]routeDoc{"POST /api/validator": {Body: driftFixtureRequest{}, Errors: []int{400}}}
	got = checkDrift(driftFixtureSource(t), routes, docs, driftExceptions{requiredUnseen: map[string]string{"server.driftFixtureRequest.name": "a validator checks it"}})
	if want := "POST /api/validator: requiredUnseen lists server.driftFixtureRequest.name, but the analyzer sees this handler reject a request without it; remove it"; strings.Join(got, "\n") != want {
		t.Errorf("want only %q, got:\n%s", want, strings.Join(got, "\n"))
	}
}
