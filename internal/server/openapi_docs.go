package server

// Descriptions for the spec's schemas come from the Go doc comments of
// the types the routes declare. The source is not in the binary, so
// `go generate` copies those comments into openapi_docs_gen.go, and a
// test fails when that file no longer matches the comments.

//go:generate go test -run TestOpenAPIDocCommentsAreGenerated -update-openapi-docs

import (
	"reflect"
	"regexp"
	"strings"
)

// typeDoc is a struct type's doc comment and its fields', as plain text.
type typeDoc struct {
	Doc    string
	Fields map[string]string // by Go field name
}

// docKey is the typeDocs key of a named type: its package path and its
// name, without a generic type's arguments. An unnamed type has none.
func docKey(t reflect.Type) string {
	if t.Name() == "" {
		return ""
	}
	name, _, _ := strings.Cut(t.Name(), "[")
	return t.PkgPath() + "." + name
}

// wireNames maps the Go names a comment on t can use to the names a client
// sees: t's own to its component, its fields' to their JSON names. A field
// named by an initialism (ID, OS, URL) is left out: prose uses those as
// words ("every OS", "the same ID") far more often than as the field.
func (s *schemaSet) wireNames(t reflect.Type) map[string]string {
	out := map[string]string{}
	if name := s.names[t]; name != "" {
		goName, _, _ := strings.Cut(t.Name(), "[")
		out[goName] = name
	}
	for _, f := range jsonFields(t) {
		if f.goName != f.name && strings.ToUpper(f.goName) != f.goName {
			out[f.goName] = f.name
		}
	}
	return out
}

var wordRe = regexp.MustCompile(`[\p{L}_][\p{L}\p{N}_]*`)

// wireText puts the names a client sees in place of the Go names a doc
// comment uses. A name after a dot is another type's (EnforcePolicy.Name)
// and is left alone.
func wireText(doc string, names map[string]string) string {
	var b strings.Builder
	last := 0
	for _, m := range wordRe.FindAllStringIndex(doc, -1) {
		wire, ok := names[doc[m[0]:m[1]]]
		if !ok || (m[0] > 0 && doc[m[0]-1] == '.') {
			continue
		}
		b.WriteString(doc[last:m[0]])
		b.WriteString(wire)
		last = m[1]
	}
	b.WriteString(doc[last:])
	return b.String()
}
