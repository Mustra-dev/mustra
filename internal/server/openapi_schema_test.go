package server

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// schemaJSON renders a schema the way the spec serves it, so a test can
// compare against JSON written out by hand.
func schemaJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertJSON(t *testing.T, what string, got any, want string) {
	t.Helper()
	var w any
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("bad expectation for %s: %v", what, err)
	}
	if g, ws := schemaJSON(t, got), schemaJSON(t, w); g != ws {
		t.Errorf("%s:\n got %s\nwant %s", what, g, ws)
	}
}

type schemaFixtureTagged struct {
	Name     string `json:"name"`
	Count    int    `json:"count,omitempty"`
	Untagged bool
	Hidden   string `json:"-"`
	internal string
}

// A named struct becomes a component, referenced by name, with its
// properties named the way encoding/json names them on the wire.
func TestSchemaNamedStructIsAComponent(t *testing.T) {
	typ := reflect.TypeOf(schemaFixtureTagged{})
	set := newSchemaSet(typ)
	assertJSON(t, "reference", set.schema(typ), `{"$ref":"#/components/schemas/SchemaFixtureTagged"}`)
	assertJSON(t, "components", set.components(), `{"SchemaFixtureTagged":{"type":"object","properties":{
		"name":{"type":"string"},
		"count":{"type":"integer","format":"int64"},
		"Untagged":{"type":"boolean"}}}}`)
}

type schemaFixtureLevel string

// Each Go type maps to what encoding/json puts on the wire for it: a nil
// slice or map is null, a fixed-size array never is.
func TestSchemaTypeMapping(t *testing.T) {
	var anyValue any
	for _, c := range []struct {
		v    any
		want string
	}{
		{true, `{"type":"boolean"}`},
		{"", `{"type":"string"}`},
		{schemaFixtureLevel(""), `{"type":"string"}`},
		{0, `{"type":"integer","format":"int64"}`},
		{int32(0), `{"type":"integer","format":"int32"}`},
		// int32 and int64 are signed: a uint32 needs int64, and no format
		// holds every uint64.
		{uint8(0), `{"type":"integer","format":"int32","minimum":0}`},
		{uint32(0), `{"type":"integer","format":"int64","minimum":0,"maximum":4294967295}`},
		{uint64(0), `{"type":"integer","minimum":0}`},
		{float32(0), `{"type":"number","format":"float"}`},
		{0.5, `{"type":"number","format":"double"}`},
		{time.Time{}, `{"type":"string","format":"date-time"}`},
		{time.Duration(0), `{"type":"integer","format":"int64","description":"nanoseconds"}`},
		{[]byte{}, `{"type":["string","null"],"contentEncoding":"base64"}`},
		{json.RawMessage{}, `{}`},
		{&anyValue, `{}`},
		{[]string{}, `{"type":["array","null"],"items":{"type":"string"}}`},
		{[2]int{}, `{"type":"array","items":{"type":"integer","format":"int64"}}`},
		{map[string]int{}, `{"type":["object","null"],"additionalProperties":{"type":"integer","format":"int64"}}`},
		{map[int]bool{}, `{"type":["object","null"],"additionalProperties":{"type":"boolean"}}`},
		{new(string), `{"type":["string","null"]}`},
		{new([]string), `{"type":["array","null"],"items":{"type":"string"}}`},
		{new(time.Time), `{"type":["string","null"],"format":"date-time"}`},
		{new(json.RawMessage), `{}`},
	} {
		typ := reflect.TypeOf(c.v)
		if c.v == &anyValue {
			typ = typ.Elem()
		}
		assertJSON(t, typ.String(), newSchemaSet(typ).schema(typ), c.want)
	}
}

type schemaFixtureRef struct {
	ID string `json:"id"`
}

type schemaFixtureFields struct {
	Ref      *schemaFixtureRef           `json:"ref"`
	Refs     []schemaFixtureRef          `json:"refs"`
	ByName   map[string]schemaFixtureRef `json:"by_name"`
	Quoted   int64                       `json:"quoted,string"`
	Inline   struct{ A int }             `json:"inline"`
	Children []schemaFixtureFields       `json:"children"`
}

// A pointer to a component may be null; ",string" quotes a number; a
// recursive type refers to itself rather than expanding forever.
func TestSchemaStructFields(t *testing.T) {
	typ := reflect.TypeOf(schemaFixtureFields{})
	set := newSchemaSet(typ)
	assertJSON(t, "fields", set.components()["SchemaFixtureFields"], `{"type":"object","properties":{
		"ref":{"anyOf":[{"$ref":"#/components/schemas/SchemaFixtureRef"},{"type":"null"}]},
		"refs":{"type":["array","null"],"items":{"$ref":"#/components/schemas/SchemaFixtureRef"}},
		"by_name":{"type":["object","null"],"additionalProperties":{"$ref":"#/components/schemas/SchemaFixtureRef"}},
		"quoted":{"type":"string"},
		"inline":{"type":"object","properties":{"A":{"type":"integer","format":"int64"}}},
		"children":{"type":["array","null"],"items":{"$ref":"#/components/schemas/SchemaFixtureFields"}}}}`)
	if _, ok := set.components()["SchemaFixtureRef"]; !ok {
		t.Error("a struct reached through a field is a component too")
	}
}

type schemaFixtureBase struct {
	ID      string `json:"id" api:"readonly"`
	Shadow  string `json:"shadow"`
	Dropped string `json:"dropped"`
}

type schemaFixtureOther struct {
	Dropped string `json:"dropped"`
}

type schemaFixtureEmbeds struct {
	schemaFixtureBase
	*schemaFixtureOther
	Named    schemaFixtureRef `json:"named"`
	Shadow   int              `json:"shadow"`
	Name     string           `json:"name" api:"required"`
	Password string           `json:"password,omitempty" api:"required,writeonly"`
}

// Embedded structs flatten the way encoding/json flattens them: promoted
// fields appear at the top, the shallower field wins a name, and two at
// the same depth cancel out. Tagged embeddings stay nested. The api tag
// carries what encoding/json cannot: required, read-only, write-only.
func TestSchemaEmbeddingAndAPITags(t *testing.T) {
	typ := reflect.TypeOf(schemaFixtureEmbeds{})
	set := newSchemaSet(typ)
	assertJSON(t, "embeds", set.components()["SchemaFixtureEmbeds"], `{"type":"object",
		"required":["name","password"],
		"properties":{
		"id":{"type":"string","readOnly":true},
		"named":{"$ref":"#/components/schemas/SchemaFixtureRef"},
		"shadow":{"type":"integer","format":"int64"},
		"name":{"type":"string"},
		"password":{"type":"string","writeOnly":true}}}`)
	if _, ok := set.components()["SchemaFixtureBase"]; ok {
		t.Error("a flattened embedded struct is not a component of its own")
	}
}

// Two types with one name, from different packages, are both prefixed
// with their package, whichever the spec happens to reach first.
func TestSchemaNameCollisionsArePrefixed(t *testing.T) {
	type Survey struct {
		Q string `json:"q"`
	}
	local, other := reflect.TypeOf(Survey{}), reflect.TypeOf(store.Survey{})
	for _, roots := range [][]reflect.Type{{local, other}, {other, local}} {
		set := newSchemaSet(roots...)
		assertJSON(t, "local", set.schema(local), `{"$ref":"#/components/schemas/ServerSurvey"}`)
		assertJSON(t, "store", set.schema(other), `{"$ref":"#/components/schemas/StoreSurvey"}`)
	}
	set := newSchemaSet(other)
	assertJSON(t, "alone", set.schema(other), `{"$ref":"#/components/schemas/Survey"}`)
}

type schemaFixtureCustom struct{ v int }

func (c schemaFixtureCustom) MarshalJSON() ([]byte, error) { return json.Marshal(c.v) }

type schemaFixtureHasCustom struct {
	C  schemaFixtureCustom   `json:"c"`
	Cs []schemaFixtureCustom `json:"cs"`
}

// A type that writes itself with MarshalJSON has no structure to reflect
// on: it becomes "any value" and is reported, so the test over the real
// routes can insist that it gets a schemaOverrides entry.
func TestSchemaReportsCustomMarshalers(t *testing.T) {
	set := newSchemaSet(reflect.TypeOf(schemaFixtureHasCustom{}))
	assertJSON(t, "custom", set.components()["SchemaFixtureHasCustom"], `{"type":"object","properties":{"c":{},"cs":{"type":["array","null"],"items":{}}}}`)
	if got := set.unknown(); len(got) != 1 || got[0] != reflect.TypeOf(schemaFixtureCustom{}) {
		t.Errorf("unknown = %v, want the one custom marshaler", got)
	}
}
