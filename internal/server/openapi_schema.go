package server

// JSON Schema for the OpenAPI spec, reflected from the Go types a route
// declares in routeDocs. It follows encoding/json's rules rather than
// the Go type system's, since what a client sees is what encoding/json
// writes: field names come from json tags, embedded structs flatten, and
// a pointer can be null.

import (
	"encoding"
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// schemaOverrides are the schemas of types encoding/json does not
// encode by their structure: a custom MarshalJSON, or a named number
// whose unit a reader needs to know.
var schemaOverrides = map[reflect.Type]map[string]any{
	reflect.TypeFor[time.Time]():       {"type": "string", "format": "date-time"},
	reflect.TypeFor[time.Duration]():   {"type": "integer", "format": "int64", "description": "nanoseconds"},
	reflect.TypeFor[json.RawMessage](): {},
}

var (
	jsonMarshalerType = reflect.TypeFor[json.Marshaler]()
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
)

// implements reports whether t or *t has iface's methods, since
// encoding/json uses either when the value is addressable.
func implements(t, iface reflect.Type) bool {
	return t.Implements(iface) || (t.Kind() != reflect.Pointer && reflect.PointerTo(t).Implements(iface))
}

// schemaSet holds the component schemas for a set of root types. Every
// named struct reachable from a root becomes one component, referenced by
// $ref, which also keeps recursive types finite.
type schemaSet struct {
	names   map[reflect.Type]string
	schemas map[string]map[string]any
	missing map[reflect.Type]bool // custom marshalers without an override
	docs    map[string]typeDoc    // descriptions, by docKey
}

// newSchemaSet describes roots with the doc comments in typeDocs.
func newSchemaSet(roots ...reflect.Type) *schemaSet { return newSchemaSetWith(typeDocs, roots...) }

// newSchemaSetWith names every component before writing any, so a type's
// name depends on the whole set and not on which route reached it first.
func newSchemaSetWith(docs map[string]typeDoc, roots ...reflect.Type) *schemaSet {
	s := &schemaSet{names: map[reflect.Type]string{}, schemas: map[string]map[string]any{}, missing: map[reflect.Type]bool{}, docs: docs}
	for _, t := range roots {
		s.collect(t)
	}
	byName := map[string][]reflect.Type{}
	for t := range s.names {
		byName[componentName(t)] = append(byName[componentName(t)], t)
	}
	taken := map[string]bool{}
	var clashes []reflect.Type
	for name, ts := range byName {
		if len(ts) == 1 {
			s.names[ts[0]] = name
			taken[name] = true
		} else {
			clashes = append(clashes, ts...)
		}
	}
	// A name two packages share gets each package's name in front:
	// store.Survey is StoreSurvey. Sorted, so that a clash the prefix
	// does not settle is numbered the same way every time.
	sort.Slice(clashes, func(i, j int) bool { return typeKey(clashes[i]) < typeKey(clashes[j]) })
	for _, t := range clashes {
		pkg := t.PkgPath()[strings.LastIndex(t.PkgPath(), "/")+1:]
		name := exportName(sanitizeName(pkg)) + componentName(t)
		for n := 2; taken[name]; n++ {
			name = exportName(sanitizeName(pkg)) + componentName(t) + strconv.Itoa(n)
		}
		s.names[t] = name
		taken[name] = true
	}
	for t, name := range s.names {
		s.schemas[name] = s.object(t)
		if doc := s.docs[docKey(t)].Doc; doc != "" {
			s.schemas[name]["description"] = wireText(doc, s.wireNames(t))
		}
	}
	return s
}

func typeKey(t reflect.Type) string { return t.PkgPath() + "." + t.Name() }

// unknown lists the types written by their own MarshalJSON that have no
// schemaOverrides entry; their schema says only "any value".
func (s *schemaSet) unknown() []reflect.Type {
	out := make([]reflect.Type, 0, len(s.missing))
	for t := range s.missing {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return typeKey(out[i]) < typeKey(out[j]) })
	return out
}

// collect records the named structs reachable from t.
func (s *schemaSet) collect(t reflect.Type) {
	if _, ok := schemaOverrides[t]; ok {
		return
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		s.collect(t.Elem())
		return
	case reflect.Map:
		s.collect(t.Elem())
		return
	case reflect.Struct:
	default:
		return
	}
	if implements(t, jsonMarshalerType) || implements(t, textMarshalerType) {
		return
	}
	if _, seen := s.names[t]; seen {
		return
	}
	if t.Name() != "" {
		s.names[t] = ""
	}
	for _, f := range jsonFields(t) {
		s.collect(f.typ)
	}
}

// componentName is t's name as a component key: exported, and without
// the brackets and paths of a generic instantiation.
func componentName(t reflect.Type) string { return exportName(sanitizeName(t.Name())) }

func exportName(name string) string {
	r := []rune(name)
	if len(r) > 0 {
		r[0] = unicode.ToUpper(r[0])
	}
	return string(r)
}

func sanitizeName(name string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return r
		}
		return '_'
	}, name)
}

// schema is t's schema: a $ref for a named struct, inline otherwise.
func (s *schemaSet) schema(t reflect.Type) map[string]any {
	if o, ok := schemaOverrides[t]; ok {
		return clone(o)
	}
	if name, ok := s.names[t]; ok {
		return map[string]any{"$ref": "#/components/schemas/" + name}
	}
	if t.Kind() != reflect.Pointer && implements(t, jsonMarshalerType) {
		s.missing[t] = true
		return map[string]any{}
	}
	if t.Kind() != reflect.Pointer && implements(t, textMarshalerType) {
		return map[string]any{"type": "string"}
	}
	switch t.Kind() {
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Int8, reflect.Int16, reflect.Int32:
		return map[string]any{"type": "integer", "format": "int32"}
	case reflect.Int, reflect.Int64:
		return map[string]any{"type": "integer", "format": "int64"}
	// The int32 and int64 formats are signed: each fits the unsigned type
	// below its size, and nothing fits a uint64's upper half.
	case reflect.Uint8, reflect.Uint16:
		return map[string]any{"type": "integer", "format": "int32", "minimum": 0}
	case reflect.Uint32:
		return map[string]any{"type": "integer", "format": "int64", "minimum": 0, "maximum": uint64(math.MaxUint32)}
	case reflect.Uint, reflect.Uint64, reflect.Uintptr:
		return map[string]any{"type": "integer", "minimum": 0}
	case reflect.Float32:
		return map[string]any{"type": "number", "format": "float"}
	case reflect.Float64:
		return map[string]any{"type": "number", "format": "double"}
	// A nil slice or map encodes as null, as a nil pointer does; a
	// fixed-size array cannot be nil.
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 && !implements(t.Elem(), jsonMarshalerType) && !implements(t.Elem(), textMarshalerType) {
			return nullable(map[string]any{"type": "string", "contentEncoding": "base64"}) // as encoding/json writes []byte
		}
		return nullable(map[string]any{"type": "array", "items": s.schema(t.Elem())})
	case reflect.Array:
		return map[string]any{"type": "array", "items": s.schema(t.Elem())}
	case reflect.Map:
		return nullable(map[string]any{"type": "object", "additionalProperties": s.schema(t.Elem())})
	case reflect.Pointer:
		return nullable(s.schema(t.Elem()))
	case reflect.Struct:
		return s.object(t)
	}
	return map[string]any{} // interfaces: any JSON value
}

// nullable widens a schema to also admit null, as a nil pointer, slice or
// map encodes.
func nullable(sch map[string]any) map[string]any {
	if len(sch) == 0 {
		return sch // already anything, null included
	}
	switch typ := sch["type"].(type) {
	case string:
		sch["type"] = []string{typ, "null"}
		return sch
	case []string:
		return sch // a pointer to a slice: already nullable
	}
	return map[string]any{"anyOf": []any{sch, map[string]any{"type": "null"}}}
}

// annotatable wraps a $ref in an allOf, so that an annotation beside it
// counts for tools that still follow OpenAPI 3.0's rule that siblings of
// $ref are ignored.
func annotatable(sch map[string]any) map[string]any {
	if _, ref := sch["$ref"]; ref {
		return map[string]any{"allOf": []any{sch}}
	}
	return sch
}

// withFlag sets a boolean annotation.
func withFlag(sch map[string]any, flag string) map[string]any {
	sch = annotatable(sch)
	sch[flag] = true
	return sch
}

// withDescription sets a field's description. One its type already has
// (a unit, such as nanoseconds) follows as a paragraph of its own.
func withDescription(sch map[string]any, doc string) map[string]any {
	sch = annotatable(sch)
	if unit, _ := sch["description"].(string); unit != "" {
		doc += "\n\n" + unit
	}
	sch["description"] = doc
	return sch
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (s *schemaSet) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	var required []string
	for _, f := range jsonFields(t) {
		sch := s.schema(f.typ)
		if f.quoted {
			sch = map[string]any{"type": "string"}
			if f.typ.Kind() == reflect.Pointer {
				sch = nullable(sch)
			}
		}
		if f.readOnly {
			sch = withFlag(sch, "readOnly")
		}
		if f.writeOnly {
			sch = withFlag(sch, "writeOnly")
		}
		if doc := s.docs[docKey(f.owner)].Fields[f.goName]; doc != "" {
			sch = withDescription(sch, wireText(doc, s.wireNames(f.owner)))
		}
		if f.required {
			required = append(required, f.name)
		}
		props[f.name] = sch
	}
	obj := map[string]any{"type": "object", "properties": props}
	if required != nil {
		obj["required"] = required
	}
	return obj
}

// components is the components/schemas section of the spec.
func (s *schemaSet) components() map[string]any {
	out := make(map[string]any, len(s.schemas))
	for name, sch := range s.schemas {
		out[name] = sch
	}
	return out
}

type jsonField struct {
	name   string
	typ    reflect.Type
	quoted bool // ",string": the value is written inside a JSON string
	// From the api tag: what encoding/json does not enforce or know.
	// Handlers check required fields by hand; read-only fields are set by
	// the server whatever a request says; write-only ones are never sent
	// back (passwords, client secrets).
	required, readOnly, writeOnly bool

	goName string       // the struct field's name
	owner  reflect.Type // the struct that declares it, which may be embedded
	index  []int
	tagged bool
}

// jsonFields lists the fields encoding/json writes for struct type t, in
// field order. It follows encoding/json's typeFields: untagged embedded
// structs are flattened breadth first, the shallowest field of a name
// wins, a tagged one beats an untagged one at the same depth, and two
// that still tie are both dropped.
func jsonFields(t reflect.Type) []jsonField {
	type embedded struct {
		typ   reflect.Type
		index []int
	}
	var fields []jsonField
	next := []embedded{{typ: t}}
	count, nextCount := map[reflect.Type]int{}, map[reflect.Type]int{}
	visited := map[reflect.Type]bool{}
	for len(next) > 0 {
		current := next
		next = nil
		count, nextCount = nextCount, map[reflect.Type]int{}
		for _, e := range current {
			if visited[e.typ] {
				continue
			}
			visited[e.typ] = true
			for i := 0; i < e.typ.NumField(); i++ {
				sf := e.typ.Field(i)
				ft := sf.Type
				if ft.Name() == "" && ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if !sf.IsExported() && !(sf.Anonymous && ft.Kind() == reflect.Struct) {
					continue
				}
				tag := sf.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name, opts, _ := strings.Cut(tag, ",")
				index := append(append([]int(nil), e.index...), i)
				if name == "" && sf.Anonymous && ft.Kind() == reflect.Struct {
					nextCount[ft]++
					if nextCount[ft] == 1 {
						next = append(next, embedded{typ: ft, index: index})
					}
					continue
				}
				f := jsonField{name: name, typ: sf.Type, quoted: hasOpt(opts, "string") && quotable(sf.Type), goName: sf.Name, owner: e.typ, index: index, tagged: name != ""}
				if f.name == "" {
					f.name = sf.Name
				}
				api := sf.Tag.Get("api")
				f.required, f.readOnly, f.writeOnly = hasOpt(api, "required"), hasOpt(api, "readonly"), hasOpt(api, "writeonly")
				fields = append(fields, f)
				if count[e.typ] > 1 {
					// The same struct embedded twice at this depth: a
					// duplicate, so the name cancels out below.
					fields = append(fields, f)
				}
			}
		}
	}
	sort.SliceStable(fields, func(i, j int) bool {
		a, b := fields[i], fields[j]
		if a.name != b.name {
			return a.name < b.name
		}
		if len(a.index) != len(b.index) {
			return len(a.index) < len(b.index)
		}
		return a.tagged && !b.tagged
	})
	out := fields[:0]
	for i := 0; i < len(fields); {
		j := i + 1
		for j < len(fields) && fields[j].name == fields[i].name {
			j++
		}
		if j-i == 1 || len(fields[i].index) != len(fields[i+1].index) || fields[i].tagged != fields[i+1].tagged {
			out = append(out, fields[i])
		}
		i = j
	}
	sort.Slice(out, func(i, j int) bool { return slices.Compare(out[i].index, out[j].index) < 0 })
	return out
}

func hasOpt(opts, want string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == want {
			return true
		}
	}
	return false
}

// quotable is whether ",string" applies to a field of type t; encoding/json
// ignores it on anything but a scalar or a pointer to one.
func quotable(t reflect.Type) bool {
	if t.Name() == "" && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Bool, reflect.String, reflect.Float32, reflect.Float64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return true
	}
	return false
}
