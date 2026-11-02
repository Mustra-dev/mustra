package server

// The generator behind openapi_docs_gen.go. It runs as a test because it
// needs what only this package knows: which types the routes declare, and
// how encoding/json lays out their fields. `go generate` runs it with
// -update-openapi-docs to rewrite the file; without the flag it fails
// when the file and the comments disagree.

import (
	"bytes"
	"encoding/json"
	stdflag "flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var updateOpenAPIDocs = stdflag.Bool("update-openapi-docs", false, "rewrite "+openAPIDocsFile+" from the doc comments")

const openAPIDocsFile = "openapi_docs_gen.go"

// openapi_docs_gen.go holds the comments of every type the routes
// declare, as they are now.
func TestOpenAPIDocCommentsAreGenerated(t *testing.T) {
	var roots []reflect.Type
	for _, d := range routeDocs {
		roots = append(roots, d.types()...)
	}
	var types []reflect.Type
	for typ := range newSchemaSet(roots...).names {
		types = append(types, typ)
	}
	docs, err := typeDocsFrom(types, moduleFiles)
	if err != nil {
		t.Fatal(err)
	}
	src, err := renderTypeDocs(docs)
	if err != nil {
		t.Fatal(err)
	}
	if *updateOpenAPIDocs {
		if err := os.WriteFile(openAPIDocsFile, src, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	current, err := os.ReadFile(openAPIDocsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, src) {
		t.Errorf("%s does not match the doc comments: run go generate ./internal/server", openAPIDocsFile)
	}
}

// The served spec describes types and fields with their comments, a
// heading included, in the names a client sees.
func TestOpenAPISpecHasDocComments(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	raw, err := json.Marshal(s.openAPISpec()["components"])
	if err != nil {
		t.Fatal(err)
	}
	var components struct {
		Schemas map[string]struct {
			Description string `json:"description"`
			Properties  map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		} `json:"schemas"`
	}
	if err := json.Unmarshal(raw, &components); err != nil {
		t.Fatal(err)
	}
	if got := components.Schemas["AgentCommandResult"].Description; got != "AgentCommandResult is the reply to an AgentCommand." {
		t.Errorf("AgentCommandResult: %q", got)
	}
	step := components.Schemas["PlaybookStep"]
	if got := step.Properties["follow_latest"].Description; got != "kind: package" {
		t.Errorf("PlaybookStep.follow_latest: %q", got)
	}
	if got := step.Description; !strings.HasPrefix(got, "PlaybookStep is one thing to do.") {
		t.Errorf("PlaybookStep: %q", got)
	}
}

// typeDocsFrom reads the doc comments of the struct types given, and of
// the fields encoding/json writes for them, from the files that declare
// them. files lists a package's files by import path; a package it
// lists none for (the standard library) is skipped. Only what will be
// shown is kept: a type's own comment, and a comment on a field that is
// on the wire, whichever struct (embedded or not) declares it.
func typeDocsFrom(types []reflect.Type, files func(pkgPath string) []string) (map[string]typeDoc, error) {
	want := map[string]map[string]bool{} // docKey → Go field names; "" for the type's own
	for _, t := range types {
		addWant(want, docKey(t), "")
		for _, f := range jsonFields(t) {
			addWant(want, docKey(f.owner), f.goName)
		}
	}
	decls := map[string]*typeDecl{}
	fset := token.NewFileSet()
	parsed := map[string]bool{}
	for key := range want {
		pkgPath := key[:strings.LastIndex(key, ".")]
		if parsed[pkgPath] {
			continue
		}
		parsed[pkgPath] = true
		for _, name := range files(pkgPath) {
			f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
			if err != nil {
				return nil, err
			}
			for _, d := range f.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok || g.Tok != token.TYPE {
					continue
				}
				for _, sp := range g.Specs {
					ts := sp.(*ast.TypeSpec)
					key := pkgPath + "." + ts.Name.Name
					if want[key] == nil {
						continue
					}
					if prev := decls[key]; prev != nil {
						return nil, fmt.Errorf("%s is declared twice, in %s and %s", key, prev.where, fset.Position(ts.Pos()))
					}
					doc := ts.Doc
					if doc == nil && len(g.Specs) == 1 {
						doc = g.Doc
					}
					decls[key] = &typeDecl{spec: ts, doc: doc, where: fset.Position(ts.Pos()).String()}
				}
			}
		}
	}
	out := map[string]typeDoc{}
	for key, names := range want {
		d := decls[key]
		if d == nil {
			if len(files(key[:strings.LastIndex(key, ".")])) == 0 {
				continue
			}
			return nil, fmt.Errorf("%s is not declared at package level in its package's files", key)
		}
		var td typeDoc
		if names[""] {
			td.Doc = docText(d.doc)
		}
		if st, ok := d.spec.Type.(*ast.StructType); ok {
			for _, block := range fieldBlocks(fset, st) {
				shared := docText(block[0].Doc)
				heading := shared != "" && len(block) > 1 && !mentions(shared, block[0])
				for i, field := range block {
					var text string
					if i == 0 || heading || mentions(shared, field) {
						text = shared
					}
					text = joinParagraphs(text, docText(field.Comment))
					if text == "" {
						continue
					}
					for _, name := range fieldNames(field) {
						if names[name] {
							if td.Fields == nil {
								td.Fields = map[string]string{}
							}
							td.Fields[name] = text
						}
					}
				}
			}
		}
		if td.Doc != "" || td.Fields != nil {
			out[key] = td
		}
	}
	return out, nil
}

type typeDecl struct {
	spec  *ast.TypeSpec
	doc   *ast.CommentGroup
	where string
}

func addWant(want map[string]map[string]bool, key, field string) {
	if key == "" {
		return
	}
	if want[key] == nil {
		want[key] = map[string]bool{}
	}
	want[key][field] = true
}

// fieldBlocks splits a struct's fields into the blocks a comment can
// head: a blank line or a comment above a field starts a new one.
func fieldBlocks(fset *token.FileSet, st *ast.StructType) [][]*ast.Field {
	var out [][]*ast.Field
	prevEnd := 0
	for _, f := range st.Fields.List {
		start := fset.Position(f.Pos()).Line
		if len(out) == 0 || f.Doc != nil || start > prevEnd+1 {
			out = append(out, nil)
		}
		out[len(out)-1] = append(out[len(out)-1], f)
		prevEnd = fset.Position(f.End()).Line
	}
	return out
}

// mentions reports whether text names one of field's Go names.
func mentions(text string, field *ast.Field) bool {
	for _, w := range wordRe.FindAllString(text, -1) {
		if slices.Contains(fieldNames(field), w) {
			return true
		}
	}
	return false
}

// fieldNames are a field's Go names: an embedded field is named after
// its type.
func fieldNames(f *ast.Field) []string {
	var out []string
	for _, n := range f.Names {
		out = append(out, n.Name)
	}
	if len(f.Names) == 0 {
		typ := f.Type
		if star, ok := typ.(*ast.StarExpr); ok {
			typ = star.X
		}
		switch x := typ.(type) {
		case *ast.Ident:
			out = append(out, x.Name)
		case *ast.SelectorExpr:
			out = append(out, x.Sel.Name)
		}
	}
	return out
}

// docText is a comment as plain text, without directives (//go:…,
// //nolint:…): each paragraph's lines joined into one, except an indented
// line (a list, code), which keeps its own, as does the line after it.
// Nothing else is rewritten: go/doc/comment would turn two single quotes,
// which these comments use for an empty string, into a closing quote.
func docText(cg *ast.CommentGroup) string {
	if cg == nil {
		return ""
	}
	indented := func(line string) bool { return strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") }
	var b strings.Builder
	prev := ""
	for i, line := range strings.Split(strings.TrimSpace(cg.Text()), "\n") {
		switch {
		case i == 0:
		case line == "" || prev == "" || indented(line) || indented(prev):
			b.WriteString("\n")
		default:
			b.WriteString(" ")
		}
		b.WriteString(line)
		prev = line
	}
	return b.String()
}

func joinParagraphs(ps ...string) string {
	var out []string
	for _, p := range ps {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n\n")
}

// moduleFiles lists the Go files of a package in this module, tests
// aside. The test runs in internal/server, two levels below the root.
func moduleFiles(pkgPath string) []string {
	module := strings.TrimSuffix(serverPkgPath, "/internal/server")
	rel, ok := strings.CutPrefix(pkgPath, module+"/")
	if !ok {
		return nil
	}
	files, _ := filepath.Glob(filepath.Join("..", "..", filepath.FromSlash(rel), "*.go"))
	return slices.DeleteFunc(files, func(name string) bool { return strings.HasSuffix(name, "_test.go") })
}

// renderTypeDocs writes docs as openapi_docs_gen.go, sorted so that the
// file changes only when a comment does.
func renderTypeDocs(docs map[string]typeDoc) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`// Code generated by "go generate ./internal/server" from doc comments; DO NOT EDIT.

package server

// typeDocs are the doc comments of the types the routes declare, by
// docKey, copied from the source by TestOpenAPIDocCommentsAreGenerated.
var typeDocs = map[string]typeDoc{
`)
	keys := make([]string, 0, len(docs))
	for k := range docs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		td := docs[k]
		fmt.Fprintf(&b, "%s: {\n", strconv.Quote(k))
		if td.Doc != "" {
			fmt.Fprintf(&b, "Doc: %s,\n", strconv.Quote(td.Doc))
		}
		if td.Fields != nil {
			b.WriteString("Fields: map[string]string{\n")
			names := make([]string, 0, len(td.Fields))
			for n := range td.Fields {
				names = append(names, n)
			}
			slices.Sort(names)
			for _, n := range names {
				fmt.Fprintf(&b, "%s: %s,\n", strconv.Quote(n), strconv.Quote(td.Fields[n]))
			}
			b.WriteString("},\n")
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n")
	return format.Source(b.Bytes())
}
