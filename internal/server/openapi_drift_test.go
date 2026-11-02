package server

// The drift test: every routeDocs declaration is checked against its
// handler's source, so the spec keeps its promise that it describes what
// the server actually does. It reads the source with go/ast (no type
// checker, no dependency): it finds what a handler decodes from the
// request body, which query keys it reads, what it writes as JSON and
// which statuses it sets, following the helpers it hands the request or
// response writer to, three calls deep (deep enough to reach the approval
// check behind an endpoint action). Local variables are resolved
// through the parser's identifier objects; a value returned by a call is
// typed from the called function's declaration when it is in a package
// under internal. A required field's check is read where the handler
// makes it, in a switch, or in a validator it hands the body to, one call
// deep. What cannot be resolved that way is not guessed at: it neither
// passes nor fails a check.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// undocumentedRoutes is how many /api routes still have no routeDocs
// entry. The test fails when the count rises (a new route must ship with
// a declaration) and when it falls (lower the constant), so coverage only
// moves one way.
const undocumentedRoutes = 0

// driftDepth is how many calls deep a handler's helpers are followed.
const driftDepth = 3

var serverPkgPath = reflect.TypeFor[Server]().PkgPath()

// --- the source -------------------------------------------------------------

type driftSource struct {
	pkgs map[string]*driftPkg
}

type driftPkg struct {
	path    string
	funcs   map[string]*driftFunc
	methods map[string]map[string]*driftFunc // receiver type → name → method
	types   map[string]driftTypeSpec
}

type driftFile struct {
	pkg     *driftPkg
	imports map[string]string // name in this file → import path
}

type driftFunc struct {
	decl *ast.FuncDecl
	file *driftFile
}

type driftTypeSpec struct {
	spec *ast.TypeSpec
	file *driftFile
}

func newDriftSource() *driftSource { return &driftSource{pkgs: map[string]*driftPkg{}} }

func (src *driftSource) add(pkgPath string, f *ast.File) {
	p := src.pkgs[pkgPath]
	if p == nil {
		p = &driftPkg{path: pkgPath, funcs: map[string]*driftFunc{}, methods: map[string]map[string]*driftFunc{}, types: map[string]driftTypeSpec{}}
		src.pkgs[pkgPath] = p
	}
	df := &driftFile{pkg: p, imports: map[string]string{}}
	for _, imp := range f.Imports {
		ip, _ := strconv.Unquote(imp.Path.Value)
		name := path.Base(ip)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		df.imports[name] = ip
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			fn := &driftFunc{decl: d, file: df}
			if d.Recv == nil || len(d.Recv.List) == 0 {
				p.funcs[d.Name.Name] = fn
				continue
			}
			recv := d.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if id, ok := recv.(*ast.Ident); ok {
				if p.methods[id.Name] == nil {
					p.methods[id.Name] = map[string]*driftFunc{}
				}
				p.methods[id.Name][d.Name.Name] = fn
			}
		case *ast.GenDecl:
			for _, sp := range d.Specs {
				if ts, ok := sp.(*ast.TypeSpec); ok {
					p.types[ts.Name.Name] = driftTypeSpec{spec: ts, file: df}
				}
			}
		}
	}
}

// loadDriftSource parses every package under internal: this one, the
// ones whose declared types handlers return (store, proto), and the ones
// whose validators a handler hands its body to (maintenance, signals, …).
func loadDriftSource(t *testing.T) *driftSource {
	t.Helper()
	src := newDriftSource()
	internal := path.Dir(serverPkgPath)
	fset := token.NewFileSet()
	dirs := map[string]string{}
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		if d.Name() == "testdata" {
			return filepath.SkipDir
		}
		rel, err := filepath.Rel("..", p)
		if err == nil && rel != "." {
			dirs[p] = internal + "/" + filepath.ToSlash(rel)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for dir, pkgPath := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 && (pkgPath == serverPkgPath || pkgPath == internal+"/store" || pkgPath == internal+"/proto") {
			t.Fatalf("no Go files in %s", dir)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			src.add(pkgPath, f)
		}
	}
	return src
}

// --- what a handler does ----------------------------------------------------

// driftType is a type expression and the file it is written in, which is
// what its identifiers resolve against. A nil expr is a type the source
// does not say (an unresolved call result, say); anon marks an anonymous
// struct, which no declaration can name.
type driftType struct {
	expr ast.Expr
	file *driftFile
	anon bool
}

type handlerFacts struct {
	decodes []driftType // what the request body is decoded into
	// A decode that copes with no body at all (its error discarded, behind
	// a ContentLength check, or io.EOF accepted) and one that does not.
	tolerantDecode, strictDecode bool
	rawRead                      bool // the body is read as bytes
	multipart                    bool // a multipart form is parsed
	streamsParts                 bool // multipart.Reader: parts are not named in the source
	formFiles                    map[string]bool
	formKeys                     map[string]bool // FormValue: query string or form field
	queryKeys                    map[string]bool
	writes                       []driftType  // JSON success bodies
	writeStatuses                []int        // each write's status, 0 for the default
	errorBodies                  []driftError // JSON written with an error status
	rawWrite                     bool         // bytes written directly (files, pre-encoded JSON)
	statuses                     map[int]bool
	textErrors                   map[int]bool // statuses sent by http.Error, with a text body
	contentTypes                 map[string]bool
	fieldChecks                  []fieldCheck
	// assignedFields are fields the handler sets itself (c.Kind =
	// old.Kind on an edit), other than tidying the client's value: a
	// rejection of one does not show the client must send it.
	assignedFields []fieldCheck
}

// fieldCheck is what a handler does when a field of a value it holds is
// missing (zero): rejects the request, or fills the field in.
type fieldCheck struct {
	typ      driftType // the value's type
	field    string    // the Go field name
	rejects  bool
	defaults bool
	// sure: the test certainly holds for a missing value (x.F == "",
	// x.F < 1), unlike !valid(x.F). top: the if or switch is a statement
	// of the handler itself, not inside a branch. A sure rejection at the top
	// means the field is required.
	sure, top bool
}

type driftError struct {
	status int
	typ    driftType
}

type driftAnalyzer struct {
	src   *driftSource
	facts *handlerFacts
	// seen is the shallowest depth each function was analysed at. A
	// function is analysed again when it is reached shallower (its own
	// callees then get followed further) or handed the body or query for
	// the first time; recorded keeps that from counting a call twice.
	seen     map[*ast.FuncDecl]int
	recorded map[ast.Node]bool
	// JSON written after w.WriteHeader in the same block goes with that
	// status: an error body for 4xx/5xx, an Also answer for a 202.
	headerStatus map[*ast.CallExpr]int
	// tolerant marks calls that run without a body or ignore its absence;
	// lenient counts the tolerant calls being followed into a helper.
	tolerant map[ast.Node]bool
	lenient  int
	// assigns are the values assigned to a local after its declaration
	// (replacement = body.Replacement), for zeroTest.
	assigns map[*ast.Object][]ast.Expr
	// blockOf is the statement list each statement sits in, so a test of
	// err finds the assignment before it.
	blockOf map[ast.Stmt][]ast.Stmt
	// fills are, for each write to a local, the loops it sits in (cleaned
	// in cleaned[k] = v, inside for k, v := range x.F); dirty marks a
	// local also written outside any loop, and handedOut each place it may
	// be filled some other way (maps.Copy(cleaned, …), &cleaned, a method
	// of it). indexed is the function bodies these were collected from.
	fills     map[*ast.Object][][]ast.Expr
	dirty     map[*ast.Object]bool
	handedOut map[*ast.Object][]handout
	indexed   map[*ast.BlockStmt]bool
	// top are the handler's own if and switch statements; errorHelpers
	// caches which helpers answer with an error status.
	top          map[ast.Stmt]bool
	errorHelpers map[*ast.FuncDecl][2]bool
	// within is the statement whose test fieldsOf is resolving: an
	// assignment inside it comes after the test, not before.
	within ast.Node
	// Parameters of a followed helper that were handed the request body
	// or the query: the helper reads them as such.
	bodyObjs, queryObjs map[*ast.Object]bool
	// params are, while a validator's checks are read, its parameters and
	// the arguments the caller passed them. selFile is the file a selector
	// taken from such an argument is written in, which is the caller's.
	params  map[*ast.Object]driftArg
	selFile map[*ast.SelectorExpr]*driftFile
}

// handout is a place a local may be filled other than by assignment,
// and the loops around it: one in a loop may run again after a test
// later in the same loop.
type handout struct {
	pos   token.Pos
	loops []ast.Node
}

type driftArg struct {
	expr ast.Expr
	file *driftFile
}

func analyzeHandler(src *driftSource, fn *driftFunc) *handlerFacts {
	a := &driftAnalyzer{src: src, seen: map[*ast.FuncDecl]int{}, recorded: map[ast.Node]bool{}, headerStatus: map[*ast.CallExpr]int{}, tolerant: map[ast.Node]bool{},
		assigns: map[*ast.Object][]ast.Expr{}, blockOf: map[ast.Stmt][]ast.Stmt{}, fills: map[*ast.Object][][]ast.Expr{}, dirty: map[*ast.Object]bool{},
		handedOut: map[*ast.Object][]handout{}, indexed: map[*ast.BlockStmt]bool{},
		top: map[ast.Stmt]bool{}, errorHelpers: map[*ast.FuncDecl][2]bool{}, bodyObjs: map[*ast.Object]bool{}, queryObjs: map[*ast.Object]bool{},
		selFile: map[*ast.SelectorExpr]*driftFile{},
		facts: &handlerFacts{formFiles: map[string]bool{}, formKeys: map[string]bool{}, queryKeys: map[string]bool{},
			statuses: map[int]bool{}, textErrors: map[int]bool{}, contentTypes: map[string]bool{}}}
	a.fn(fn, 0, false)
	return a.facts
}

func (a *driftAnalyzer) fn(fn *driftFunc, depth int, rebound bool) {
	if prev, ok := a.seen[fn.decl]; fn.decl.Body == nil || ok && prev <= depth && !rebound {
		return
	}
	a.seen[fn.decl] = depth
	a.markTolerant(fn)
	if depth == 0 {
		for _, st := range fn.decl.Body.List {
			switch st.(type) {
			case *ast.IfStmt, *ast.SwitchStmt:
				a.top[st] = true
			}
		}
	}
	a.indexBody(fn.decl.Body)
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		status := 0
		for _, st := range block.List {
			es, ok := st.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := es.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WriteHeader" && len(call.Args) == 1 && a.isWriter(fn.file, sel.X) {
				status = a.status(fn.file, call.Args[0], 0)
			} else if status != 0 {
				a.headerStatus[call] = status
			}
		}
		return true
	})
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			a.call(fn.file, n, depth)
		case *ast.IndexExpr: // q["key"]
			if key, ok := stringLit(n.Index); ok && a.isQuery(fn.file, n.X) {
				a.facts.queryKeys[key] = true
			}
		case *ast.IfStmt:
			if !a.recorded[n] {
				a.recorded[n] = true
				errs, client := a.answersError(fn.file, n.Body.List)
				a.fieldChecks(fn.file, driftBranch{node: n, stmt: n, init: n.Init, cond: n.Cond, body: n.Body.List, top: a.top[n]}, errs, client, true)
			}
		case *ast.SwitchStmt:
			if !a.recorded[n] {
				a.recorded[n] = true
				a.switchChecks(fn.file, n, a.top[n], func(body []ast.Stmt) (bool, bool) { return a.answersError(fn.file, body) }, true)
			}
		case *ast.AssignStmt:
			if !a.recorded[n] && len(n.Lhs) == len(n.Rhs) {
				a.recorded[n] = true
				for i, l := range n.Lhs {
					sel, ok := l.(*ast.SelectorExpr)
					if !ok || strings.Contains(types.ExprString(n.Rhs[i]), types.ExprString(sel)) {
						continue // not a field, or x.F = strings.TrimSpace(x.F)
					}
					a.facts.assignedFields = append(a.facts.assignedFields, fieldCheck{typ: a.typeOf(fn.file, sel.X, 0), field: sel.Sel.Name})
				}
			}
		}
		return true
	})
}

// markTolerant finds the calls in fn that do without a request body: one
// whose error is discarded (_ = dec.Decode(&v)), one run only when
// r.ContentLength says there is a body, and every decode in a function
// that accepts io.EOF.
func (a *driftAnalyzer) markTolerant(fn *driftFunc) {
	eof := false
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := n.X.(*ast.Ident); ok && fn.file.imports[id.Name] == "io" && n.Sel.Name == "EOF" {
				eof = true
			}
		case *ast.ExprStmt:
			if call, ok := n.X.(*ast.CallExpr); ok {
				a.tolerant[call] = true
			}
		case *ast.AssignStmt:
			blank := true
			for _, l := range n.Lhs {
				id, ok := l.(*ast.Ident)
				blank = blank && ok && id.Name == "_"
			}
			if call, ok := n.Rhs[0].(*ast.CallExpr); ok && blank && len(n.Rhs) == 1 {
				a.tolerant[call] = true
			}
		case *ast.IfStmt:
			guarded := false
			ast.Inspect(n.Cond, func(m ast.Node) bool {
				if sel, ok := m.(*ast.SelectorExpr); ok && sel.Sel.Name == "ContentLength" {
					guarded = true
				}
				return true
			})
			if guarded {
				ast.Inspect(n.Body, func(m ast.Node) bool {
					if call, ok := m.(*ast.CallExpr); ok {
						a.tolerant[call] = true
					}
					return true
				})
			}
		}
		return true
	})
	if eof {
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				a.tolerant[call] = true
			}
			return true
		})
	}
}

// decoded records a decode of the request body into t.
func (a *driftAnalyzer) decoded(call *ast.CallExpr, t driftType) {
	a.facts.decodes = append(a.facts.decodes, t)
	if a.tolerant[call] || a.lenient > 0 {
		a.facts.tolerantDecode = true
	} else {
		a.facts.strictDecode = true
	}
}

// driftBranch is code that runs when a condition holds: an if statement,
// or one case of a switch read as one.
type driftBranch struct {
	node ast.Node // the statement or case clause, for a.within
	stmt ast.Stmt // the if or switch statement
	init ast.Stmt // the if's or switch's init statement
	cond ast.Expr
	body []ast.Stmt
	top  bool // a statement of the handler itself, not inside a branch
}

// answersError reports whether code answers the request with an error
// status (errs), and with one that blames the request (client, a 4xx):
// http.Error, http.NotFound, a JSON error, WriteHeader, or a helper that
// does one of those (writeDefinitionError(w, err)).
func (a *driftAnalyzer) answersError(f *driftFile, body []ast.Stmt) (errs, client bool) {
	note := func(code int) {
		errs = errs || code >= 400
		client = client || code >= 400 && code < 500
	}
	for _, st := range body {
		ast.Inspect(st, func(m ast.Node) bool {
			c, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch {
			case a.isFunc(f, c.Fun, "net/http", "NotFound"):
				note(http.StatusNotFound)
			case a.isFunc(f, c.Fun, "net/http", "Error") && len(c.Args) == 3:
				note(a.status(f, c.Args[2], 0))
			case (a.isFunc(f, c.Fun, serverPkgPath, "writeJSONStatus") || a.isFunc(f, c.Fun, serverPkgPath, "writeJSONError")) && len(c.Args) == 3:
				note(a.status(f, c.Args[1], 0))
			}
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WriteHeader" && len(c.Args) == 1 {
				note(a.status(f, c.Args[0], 0))
			}
			if callee := a.callee(f, c); callee != nil && callee.file.pkg.path == serverPkgPath {
				he, hc := a.writesError(callee)
				errs, client = errs || he, client || hc
			}
			return true
		})
	}
	return errs, client
}

// returnsProblem reports whether a validator's branch returns a problem
// in result idx, which is ok when it is nil (an error) or "" (a message).
// Only a return that is a statement of the branch itself counts, and only
// with a problem made there (fmt.Errorf, errors.New, a message, an error
// literal): an error from elsewhere (return err, return s.exec(…)) may
// well be nil.
func (a *driftAnalyzer) returnsProblem(f *driftFile, body []ast.Stmt, idx int, ok string) bool {
	for _, st := range body {
		ret, isRet := st.(*ast.ReturnStmt)
		if !isRet || len(ret.Results) <= idx || len(ret.Results) == 1 && idx > 0 {
			continue
		}
		if a.madeProblem(f, ret.Results[idx], ok) {
			return true
		}
	}
	return false
}

// madeProblem reports whether e is a problem made on the spot: a new
// error for a validator that returns one, a message for one that returns
// a string.
func (a *driftAnalyzer) madeProblem(f *driftFile, e ast.Expr, ok string) bool {
	if ok == `""` {
		switch e := e.(type) {
		case *ast.BasicLit:
			return e.Kind == token.STRING && e.Value != `""`
		case *ast.BinaryExpr: // "unknown kind: " + k
			return e.Op == token.ADD && (a.madeProblem(f, e.X, ok) || a.madeProblem(f, e.Y, ok))
		}
		return false
	}
	switch e := e.(type) {
	case *ast.CallExpr:
		return a.isFunc(f, e.Fun, "fmt", "Errorf") || a.isFunc(f, e.Fun, "errors", "New")
	case *ast.UnaryExpr: // &DefinitionError{…}
		_, lit := e.X.(*ast.CompositeLit)
		return e.Op == token.AND && lit
	case *ast.CompositeLit:
		return true
	}
	return false
}

// okValue is "nil" or `""` for an expression that is one of those, and ""
// otherwise.
func okValue(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		if e.Name == "nil" {
			return "nil"
		}
	case *ast.BasicLit:
		if e.Value == `""` {
			return `""`
		}
	}
	return ""
}

// assignedIn is what code assigns: fields (x.F = …) by their source, and
// locals.
func assignedIn(body []ast.Stmt) (map[string]bool, map[*ast.Object]bool) {
	fields, locals := map[string]bool{}, map[*ast.Object]bool{}
	for _, st := range body {
		ast.Inspect(st, func(m ast.Node) bool {
			if as, ok := m.(*ast.AssignStmt); ok {
				for _, l := range as.Lhs {
					switch l := l.(type) {
					case *ast.SelectorExpr:
						fields[types.ExprString(l)] = true
					case *ast.Ident:
						if l.Obj != nil {
							locals[l.Obj] = true
						}
					}
				}
			}
			return true
		})
	}
	return fields, locals
}

// fieldChecks records what a branch does about missing fields: one whose
// condition finds a field zero (x.F == "", len(x.F) == 0, x.F < 1,
// !valid(x.F)) and whose body rejects (errs) rejects requests without it;
// one whose body assigns the field fills it in. A condition joined by &&
// only rejects when all of it holds, so only || is followed for that.
// follow lets a test of a validator's result (err != nil) read the
// validator's own checks, which do not follow further. A test of a
// call's result rejects only when the body blames the request (client, a
// 4xx): a 500 there says the call failed, not that the field is missing.
func (a *driftAnalyzer) fieldChecks(f *driftFile, br driftBranch, errs, client, follow bool) {
	prev := a.within
	a.within = br.node
	defer func() { a.within = prev }()
	assigned, assignedLocals := assignedIn(br.body) // pkgID = p.PackageID: the local is filled in
	// fillsLocal: the value tested is a local the body assigns
	// (pkgID == "" { pkgID = p.PackageID }).
	fillsLocal := func(e ast.Expr) bool {
		be, ok := e.(*ast.BinaryExpr)
		if !ok {
			return false
		}
		for _, side := range []ast.Expr{be.X, be.Y} {
			for {
				if c, ok := side.(*ast.CallExpr); ok && len(c.Args) == 1 {
					side = c.Args[0]
					continue
				}
				if p, ok := side.(*ast.ParenExpr); ok {
					side = p.X
					continue
				}
				break
			}
			if id, ok := side.(*ast.Ident); ok && id.Obj != nil && assignedLocals[id.Obj] {
				return true
			}
		}
		return false
	}
	var walk func(e ast.Expr, orOnly bool)
	walk = func(e ast.Expr, orOnly bool) {
		switch e := e.(type) {
		case *ast.ParenExpr:
			walk(e.X, orOnly)
			return
		case *ast.BinaryExpr, *ast.UnaryExpr:
			if sels := a.allowList(f, e); sels != nil { // x.F != "a" && x.F != "b"
				for _, sel := range sels {
					a.emit(f, sel, errs && orOnly, false, true, br.top)
				}
				return
			}
			if be, ok := e.(*ast.BinaryExpr); ok && (be.Op == token.LOR || be.Op == token.LAND) {
				walk(be.X, orOnly && be.Op == token.LOR)
				walk(be.Y, orOnly && be.Op == token.LOR)
				return
			}
		}
		if a.resultChecks(f, br, e, client && orOnly, follow) {
			return
		}
		sels, sure := a.zeroTest(f, e)
		for _, sel := range sels {
			a.emit(f, sel, errs && orOnly, assigned[types.ExprString(sel)] || fillsLocal(e), sure, br.top)
		}
	}
	walk(br.cond, true)
}

// emit records what a branch does when field sel is missing. A sure
// rejection of a validator parameter's field (d.Version < 1) also
// rejects a request that leaves out the argument it was handed: missing,
// that is zero all through. What a validator fills in is not counted: it
// may fill in its own copy (store.UpsertRevealRuleSet), and the handler
// has had its say before it.
func (a *driftAnalyzer) emit(f *driftFile, sel *ast.SelectorExpr, rejects, defaults, sure, top bool) {
	defaults = defaults && a.params == nil
	if !rejects && !defaults {
		return
	}
	file := f
	if sf := a.selFile[sel]; sf != nil {
		file = sf
	}
	a.facts.fieldChecks = append(a.facts.fieldChecks, fieldCheck{typ: a.typeOf(file, sel.X, 0), field: sel.Sel.Name,
		rejects: rejects, defaults: defaults, sure: sure, top: top})
	if id, ok := sel.X.(*ast.Ident); ok && id.Obj != nil && rejects && sure {
		if arg, ok := a.params[id.Obj]; ok {
			for _, s := range a.argFields(arg) {
				a.emit(arg.file, s, true, false, true, false)
			}
		}
	}
}

// argFields is the fields a validator's argument is read from, each
// noted as written in the caller's file.
func (a *driftAnalyzer) argFields(arg driftArg) []*ast.SelectorExpr {
	saved := a.params
	a.params = nil // the caller's own locals, not the validator's
	defer func() { a.params = saved }()
	sels := a.fieldsOf(arg.expr, 0)
	for _, s := range sels {
		if a.selFile[s] == nil {
			a.selFile[s] = arg.file
		}
	}
	return sels
}

// switchChecks reads a switch as the branches it stands for. A switch
// without a tag is a chain of ifs: a case surely rejects only when every
// case before it rejects too, or a missing value could stop at an earlier
// one. A switch on a field (switch x.F { case "a", "b": … default:
// reject }) rejects a missing value when the default does and no case
// lists the zero value, and surely so when every case is a literal (a
// constant may itself be ""); a case that lists it decides instead. The
// tag must be the field itself, trimmed or with its case changed at most:
// what another function makes of a missing value may be anything.
func (a *driftAnalyzer) switchChecks(f *driftFile, sw *ast.SwitchStmt, top bool, errs func([]ast.Stmt) (bool, bool), follow bool) {
	if sw.Tag == nil {
		earlier := true
		for _, st := range sw.Body.List {
			cc := st.(*ast.CaseClause)
			if cc.List == nil {
				continue // default
			}
			cond := cc.List[0]
			for _, e := range cc.List[1:] {
				cond = &ast.BinaryExpr{X: cond, Op: token.LOR, Y: e}
			}
			rejects, client := errs(cc.Body)
			a.fieldChecks(f, driftBranch{node: cc, stmt: sw, init: sw.Init, cond: cond, body: cc.Body, top: top && earlier}, rejects, client, follow)
			earlier = earlier && rejects
		}
		return
	}
	var def, zero *ast.CaseClause
	literal := true
	for _, st := range sw.Body.List {
		cc := st.(*ast.CaseClause)
		if cc.List == nil {
			def = cc
		}
		for _, e := range cc.List {
			lit, ok := e.(*ast.BasicLit)
			switch {
			case ok && (lit.Value == `""` || lit.Value == "0"):
				zero = cc
			case !ok:
				literal = false
			}
		}
	}
	missing := def
	if zero != nil {
		missing = zero
	}
	if missing == nil {
		return
	}
	prev := a.within
	a.within = sw
	defer func() { a.within = prev }()
	rejects, _ := errs(missing.Body)
	assigned, _ := assignedIn(missing.Body)
	for _, sel := range a.tagFields(f, sw.Tag, 0) {
		a.emit(f, sel, rejects, assigned[types.ExprString(sel)], zero != nil || literal, top)
	}
}

// resultChecks reads a test of what a call returned, and reports whether
// it was one: a problem from a validator the body is handed to (err !=
// nil after validatePatchPolicy(&in) or signals.Compile(in.Expression),
// problem != "" after validateQuestions(sv.Questions)), whose own checks
// are read one call deep when follow is set; an error from json.Unmarshal
// of a field, which fails on nothing at all; and a lookup by a field that
// finds nothing (pb == nil after GetPlaybook(ctx, t.PlaybookID)).
func (a *driftAnalyzer) resultChecks(f *driftFile, br driftBranch, e ast.Expr, rejects, follow bool) bool {
	be, ok := e.(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ && be.Op != token.EQL {
		return false
	}
	x, want := be.X, okValue(be.Y)
	if want == "" {
		x, want = be.Y, okValue(be.X)
	}
	if want == "" {
		return false
	}
	call, idx := a.resultOf(br, x)
	if call == nil {
		return false
	}
	switch {
	case be.Op == token.NEQ && a.isFunc(f, call.Fun, "encoding/json", "Unmarshal") && idx == 0 && len(call.Args) == 2:
		for _, sel := range a.fieldsOf(call.Args[0], 0) {
			a.emit(f, sel, rejects, false, true, br.top)
		}
	case be.Op == token.EQL && want == "nil" && strings.HasPrefix(funcName(call), "Get"):
		for _, arg := range call.Args {
			for _, sel := range a.fieldsOf(arg, 0) {
				a.emit(f, sel, rejects, false, false, br.top)
			}
		}
	case be.Op == token.NEQ:
		if rejects && follow {
			a.validatorChecks(f, call, idx, want)
		}
	default:
		return false
	}
	return true
}

func funcName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// resultOf is the call, and which of its results, an expression in a
// branch's condition holds: the call itself, or a local assigned from it
// in the branch's init statement, or by the last statement before the
// branch in the same block that sets the local. That statement must be
// the assignment itself: one that sets it only on some paths (inside an
// if), or to something other than a call, leaves the result unknown.
func (a *driftAnalyzer) resultOf(br driftBranch, x ast.Expr) (*ast.CallExpr, int) {
	for {
		p, ok := x.(*ast.ParenExpr)
		if !ok {
			break
		}
		x = p.X
	}
	switch x := x.(type) {
	case *ast.CallExpr:
		return x, 0
	case *ast.Ident:
		if x.Obj == nil {
			return nil, 0
		}
		if br.init != nil && writes(br.init, x.Obj) {
			return assignedCall(br.init, x.Obj)
		}
		block := a.blockOf[br.stmt]
		at := slices.Index(block, br.stmt)
		for i := at - 1; i >= 0; i-- {
			if writes(block[i], x.Obj) {
				return assignedCall(block[i], x.Obj)
			}
		}
	}
	return nil, 0
}

// writes reports whether a statement may set local obj.
func writes(st ast.Stmt, obj *ast.Object) bool {
	found := false
	ast.Inspect(st, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				if id, ok := l.(*ast.Ident); ok && id.Obj == obj {
					found = true
				}
			}
		case *ast.ValueSpec:
			for _, id := range n.Names {
				found = found || id.Obj == obj
			}
		case *ast.UnaryExpr:
			if id, ok := n.X.(*ast.Ident); ok && n.Op == token.AND && id.Obj == obj {
				found = true
			}
		}
		return !found
	})
	return found
}

// assignedCall is the call, and which of its results, statement st sets
// local obj to, when st is that assignment.
func assignedCall(st ast.Stmt, obj *ast.Object) (*ast.CallExpr, int) {
	var lhs []ast.Expr
	var rhs []ast.Expr
	switch st := st.(type) {
	case *ast.AssignStmt:
		lhs, rhs = st.Lhs, st.Rhs
	case *ast.DeclStmt:
		gd, ok := st.Decl.(*ast.GenDecl)
		if !ok || len(gd.Specs) != 1 {
			return nil, 0
		}
		vs, ok := gd.Specs[0].(*ast.ValueSpec)
		if !ok {
			return nil, 0
		}
		for _, n := range vs.Names {
			lhs = append(lhs, n)
		}
		rhs = vs.Values
	default:
		return nil, 0
	}
	for i, l := range lhs {
		id, ok := l.(*ast.Ident)
		if !ok || id.Obj != obj {
			continue
		}
		switch {
		case len(rhs) == 1:
			if c, ok := rhs[0].(*ast.CallExpr); ok {
				return c, i
			}
		case len(rhs) == len(lhs):
			if c, ok := rhs[i].(*ast.CallExpr); ok {
				return c, 0
			}
		}
	}
	return nil, 0
}

// validatorChecks reads the checks of a validator that call hands the
// body or its fields to: a branch on a field of a parameter, or on a
// parameter itself (len(qs) == 0), that returns a problem in result idx
// (anything but ok there) rejects the field the caller passed. It is
// followed one call deep, into any package of this repository.
func (a *driftAnalyzer) validatorChecks(f *driftFile, call *ast.CallExpr, idx int, ok string) {
	callee := a.callee(f, call)
	if callee == nil || callee.decl.Body == nil || callee.decl.Type.TypeParams != nil || a.params != nil {
		return
	}
	a.indexBody(callee.decl.Body)
	a.params = map[*ast.Object]driftArg{}
	defer func() { a.params = nil }()
	for i, p := range flattenFields(callee.decl.Type.Params) {
		if _, variadic := p.typ.(*ast.Ellipsis); i < len(call.Args) && !variadic && p.name != nil && p.name.Obj != nil {
			a.params[p.name.Obj] = driftArg{expr: call.Args[i], file: f}
		}
	}
	problem := func(body []ast.Stmt) (bool, bool) {
		p := a.returnsProblem(callee.file, body, idx, ok)
		return p, p
	}
	ast.Inspect(callee.decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			p, _ := problem(n.Body.List)
			a.fieldChecks(callee.file, driftBranch{node: n, stmt: n, init: n.Init, cond: n.Cond, body: n.Body.List}, p, p, false)
		case *ast.SwitchStmt:
			a.switchChecks(callee.file, n, false, problem, false)
		}
		return true
	})
}

// indexBody notes, for a function body, what fieldsOf and resultOf need:
// the values and call results assigned to its locals, and the loops each
// write to a local sits in.
func (a *driftAnalyzer) indexBody(body *ast.BlockStmt) {
	if body == nil || a.indexed[body] {
		return
	}
	a.indexed[body] = true
	var stack []ast.Node
	write := func(id *ast.Ident, st ast.Node) {
		if id == nil || id.Obj == nil || id.Obj.Decl == st {
			return
		}
		var loops []ast.Expr
		for _, n := range stack {
			if rs, ok := n.(*ast.RangeStmt); ok && st.Pos() >= rs.Body.Pos() && st.End() <= rs.Body.End() {
				loops = append(loops, rs.X)
			}
		}
		if len(loops) == 0 {
			a.dirty[id.Obj] = true
			return
		}
		a.fills[id.Obj] = append(a.fills[id.Obj], loops)
	}
	handOut := func(id *ast.Ident, at ast.Node) {
		if id.Obj == nil || id.Obj.Kind != ast.Var {
			return
		}
		var loops []ast.Node
		for _, n := range stack {
			switch n.(type) {
			case *ast.ForStmt, *ast.RangeStmt:
				loops = append(loops, n)
			}
		}
		a.handedOut[id.Obj] = append(a.handedOut[id.Obj], handout{at.Pos(), loops})
	}
	target := func(e ast.Expr) *ast.Ident {
		if ix, ok := e.(*ast.IndexExpr); ok {
			e = ix.X
		}
		id, _ := e.(*ast.Ident)
		return id
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				id := target(l)
				write(id, n)
				if id == nil || id.Obj == nil || id != l {
					continue
				}
				if n.Tok == token.ASSIGN && len(n.Lhs) == len(n.Rhs) {
					a.assigns[id.Obj] = append(a.assigns[id.Obj], n.Rhs[i])
				}
			}
		case *ast.IncDecStmt:
			write(target(n.X), n)
		case *ast.BlockStmt:
			for _, st := range n.List {
				a.blockOf[st] = n.List
			}
		case *ast.CaseClause:
			for _, st := range n.Body {
				a.blockOf[st] = n.Body
			}
		case *ast.CommClause:
			for _, st := range n.Body {
				a.blockOf[st] = n.Body
			}
		case *ast.UnaryExpr: // &cleaned
			if id, ok := n.X.(*ast.Ident); ok && n.Op == token.AND {
				handOut(id, n)
			}
		case *ast.CallExpr:
			// A local handed to a call, or whose method is called, may come
			// back filled; the builtins that only read or append do not.
			if fun, ok := n.Fun.(*ast.Ident); ok && fun.Obj == nil && (fun.Name == "len" || fun.Name == "cap" || fun.Name == "append" || fun.Name == "delete") {
				return true
			}
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok {
					handOut(id, n)
				}
			}
			for _, arg := range n.Args {
				if id, ok := arg.(*ast.Ident); ok {
					handOut(id, n)
				}
			}
		}
		return true
	})
}

// filledFrom is the field a local is filled from by looping over it
// (cleaned := map[string]string{}; for os, cmd := range body.Commands {
// cleaned[os] = cmd }), when it starts empty and is written nowhere
// else (nor handed to a call, nor its address taken, before the test):
// missing the field, it stays empty. Every write must sit in a loop over
// that same field.
func (a *driftAnalyzer) filledFrom(id *ast.Ident, n int) []*ast.SelectorExpr {
	if id.Obj == nil || a.dirty[id.Obj] || len(a.fills[id.Obj]) == 0 || !startsEmpty(id) {
		return nil
	}
	// Handed out before the test, or in a loop around it, the local may
	// be filled from elsewhere.
	for _, h := range a.handedOut[id.Obj] {
		if a.within == nil || h.pos < a.within.Pos() {
			return nil
		}
		for _, l := range h.loops {
			if l.Pos() <= a.within.Pos() && a.within.End() <= l.End() {
				return nil
			}
		}
	}
	var common map[string]*ast.SelectorExpr
	for _, loops := range a.fills[id.Obj] {
		here := map[string]*ast.SelectorExpr{}
		for _, x := range loops {
			for _, sel := range a.fieldsOf(x, n+1) {
				if common == nil || common[types.ExprString(sel)] != nil {
					here[types.ExprString(sel)] = sel
				}
			}
		}
		common = here
	}
	var out []*ast.SelectorExpr
	for _, k := range slices.Sorted(maps.Keys(common)) {
		out = append(out, common[k])
	}
	return out
}

// startsEmpty reports whether a local is declared empty: 0, "", nil, an
// empty literal, a new map or a slice made with no elements, or no value.
func startsEmpty(id *ast.Ident) bool {
	var v ast.Expr
	switch d := id.Obj.Decl.(type) {
	case *ast.ValueSpec:
		if len(d.Values) == 0 {
			return true
		}
		v = declValue(id)
	case *ast.AssignStmt:
		v = declValue(id)
	}
	switch v := v.(type) {
	case *ast.BasicLit:
		return v.Value == "0" || v.Value == `""`
	case *ast.Ident:
		return v.Name == "nil"
	case *ast.CompositeLit:
		return len(v.Elts) == 0
	case *ast.CallExpr:
		if fun, ok := v.Fun.(*ast.Ident); !ok || fun.Name != "make" || len(v.Args) == 0 {
			return false
		}
		if _, isMap := v.Args[0].(*ast.MapType); isMap {
			return true
		}
		return len(v.Args) > 1 && isZeroLit(v.Args[1])
	}
	return false
}

// allowList is x.F in x.F != "a" && x.F != "b" …, which rejects anything
// but the values listed, a missing one included; a prefix test
// (!strings.HasPrefix(x.F, "https://")) is such a part too.
func (a *driftAnalyzer) allowList(f *driftFile, e ast.Expr) []*ast.SelectorExpr {
	if u, ok := e.(*ast.UnaryExpr); ok {
		if c, ok := u.X.(*ast.CallExpr); ok && u.Op == token.NOT && a.isFunc(f, c.Fun, "strings", "HasPrefix") && len(c.Args) == 2 {
			if v, ok := stringLit(c.Args[1]); ok && v != "" {
				return a.fieldsOf(c.Args[0], 0)
			}
		}
		return nil
	}
	be, ok := e.(*ast.BinaryExpr)
	if !ok {
		return nil
	}
	if be.Op == token.LAND {
		l, r := a.allowList(f, be.X), a.allowList(f, be.Y)
		if l == nil || r == nil || len(l) != len(r) || types.ExprString(l[0]) != types.ExprString(r[0]) {
			return nil
		}
		return l
	}
	if v, ok := stringLit(be.Y); be.Op != token.NEQ || !ok || v == "" {
		return nil
	}
	return a.fieldsOf(be.X, 0)
}

// zeroTest is x.F in a test that holds when the field is missing:
// x.F == "", len(x.F) == 0, x.F < min, !valid(x.F), m[x.F] == "", or the
// ok of v, ok := m[x.F]. The field may be read through a local first
// (cmd := strings.TrimSpace(x.F); cmd == "").
//
// sure is whether a missing value certainly fails the test: !valid(x.F)
// may accept one, and x.F < min does only when min is above zero. A list
// of literals the value must be in (!slices.Contains([]string{"a", "b"},
// x.F)) is sure when none of them is "".
func (a *driftAnalyzer) zeroTest(f *driftFile, e ast.Expr) (sels []*ast.SelectorExpr, sure bool) {
	switch e := e.(type) {
	case *ast.BinaryExpr:
		switch e.Op {
		case token.EQL:
			for _, pair := range [][2]ast.Expr{{e.X, e.Y}, {e.Y, e.X}} {
				lit, isLit := pair[1].(*ast.BasicLit)
				id, isIdent := pair[1].(*ast.Ident)
				if isLit && (lit.Value == `""` || lit.Value == "0") || isIdent && id.Name == "nil" {
					return a.fieldsOf(pair[0], 0), true
				}
			}
		case token.LSS:
			return a.fieldsOf(e.X, 0), a.status(f, e.Y, 0) > 0
		case token.LEQ:
			return a.fieldsOf(e.X, 0), isZeroLit(e.Y) || a.status(f, e.Y, 0) > 0
		}
	case *ast.UnaryExpr:
		if e.Op != token.NOT {
			return nil, false
		}
		switch x := e.X.(type) {
		case *ast.CallExpr: // !valid(x.F)
			if a.isFunc(f, x.Fun, "slices", "Contains") && len(x.Args) == 2 && nonEmptyLits(x.Args[0]) {
				return a.fieldsOf(x.Args[1], 0), true
			}
			for _, arg := range x.Args {
				sels = append(sels, a.fieldsOf(arg, 0)...)
			}
			return sels, false
		case *ast.IndexExpr: // !allowed[x.F]
			return a.fieldsOf(x.Index, 0), false
		case *ast.Ident: // v, ok := m[x.F]; !ok
			if x.Obj == nil {
				return nil, false
			}
			if as, ok := x.Obj.Decl.(*ast.AssignStmt); ok && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
				if l, ok := as.Lhs[1].(*ast.Ident); ok && l.Name == x.Name {
					if ix, ok := as.Rhs[0].(*ast.IndexExpr); ok {
						return a.fieldsOf(ix.Index, 0), true
					}
				}
			}
		}
	}
	return nil, false
}

// nonEmptyLits reports whether e is a slice literal of string literals,
// none of them "".
func nonEmptyLits(e ast.Expr) bool {
	cl, ok := e.(*ast.CompositeLit)
	if !ok || len(cl.Elts) == 0 {
		return false
	}
	for _, el := range cl.Elts {
		if v, ok := stringLit(el); !ok || v == "" {
			return false
		}
	}
	return true
}

func isZeroLit(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Value == "0"
}

// writesError reports whether a helper answers with an error status
// (writeDefinitionError(w, err)), so calling it in an if rejects, and
// whether with a 4xx.
func (a *driftAnalyzer) writesError(fn *driftFunc) (errs, client bool) {
	if v, ok := a.errorHelpers[fn.decl]; ok {
		return v[0], v[1]
	}
	a.errorHelpers[fn.decl] = [2]bool{} // a helper that calls itself
	note := func(code int) {
		errs = errs || code >= 400
		client = client || code >= 400 && code < 500
	}
	if fn.decl.Body != nil {
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch {
			case a.isFunc(fn.file, c.Fun, "net/http", "Error") && len(c.Args) == 3:
				note(a.status(fn.file, c.Args[2], 0))
			case a.isFunc(fn.file, c.Fun, serverPkgPath, "writeJSONStatus") && len(c.Args) == 3:
				note(a.status(fn.file, c.Args[1], 0))
			}
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WriteHeader" && len(c.Args) == 1 {
				note(a.status(fn.file, c.Args[0], 0))
			}
			return true
		})
	}
	a.errorHelpers[fn.decl] = [2]bool{errs, client}
	return errs, client
}

// tagFields is the field a switch's tag is: the field itself, through
// parentheses, strings.TrimSpace, ToLower or ToUpper, a local holding
// that, or a validator's parameter its caller passed that.
func (a *driftAnalyzer) tagFields(f *driftFile, e ast.Expr, n int) []*ast.SelectorExpr {
	if n > 6 {
		return nil
	}
	switch e := e.(type) {
	case *ast.SelectorExpr:
		return []*ast.SelectorExpr{e}
	case *ast.ParenExpr:
		return a.tagFields(f, e.X, n+1)
	case *ast.CallExpr:
		for _, name := range []string{"TrimSpace", "ToLower", "ToUpper"} {
			if len(e.Args) == 1 && a.isFunc(f, e.Fun, "strings", name) {
				return a.tagFields(f, e.Args[0], n+1)
			}
		}
	case *ast.Ident:
		if e.Obj == nil {
			return nil
		}
		if arg, ok := a.params[e.Obj]; ok {
			if len(a.tagFields(arg.file, arg.expr, n+1)) == 0 {
				return nil
			}
			return a.argFields(arg)
		}
		if v := declValue(e); v != nil && len(a.assigns[e.Obj]) == 0 {
			return a.tagFields(f, v, n+1)
		}
	}
	return nil
}

// fieldsOf is the fields an expression is read from: x.F itself, through
// a one-argument call (strings.TrimSpace, len), a map index, or a local
// declared or later assigned from one.
func (a *driftAnalyzer) fieldsOf(e ast.Expr, n int) []*ast.SelectorExpr {
	if n > 4 {
		return nil
	}
	switch e := e.(type) {
	case *ast.SelectorExpr:
		return []*ast.SelectorExpr{e}
	case *ast.ParenExpr:
		return a.fieldsOf(e.X, n+1)
	case *ast.CallExpr:
		if len(e.Args) == 1 {
			return a.fieldsOf(e.Args[0], n+1)
		}
	case *ast.IndexExpr:
		return a.fieldsOf(e.Index, n+1)
	case *ast.Ident:
		// Only a single-value declaration derives the local from what it
		// was given: the err of u, err := url.Parse(body.URL) says nothing
		// about body.URL being set.
		var out []*ast.SelectorExpr
		if src := declValue(e); src != nil {
			out = append(out, a.fieldsOf(src, n+1)...)
		}
		if e.Obj != nil {
			// A validator's parameter is the argument its caller passed.
			if arg, ok := a.params[e.Obj]; ok {
				out = append(out, a.argFields(arg)...)
			}
			out = append(out, a.filledFrom(e, n)...)
			for _, src := range a.assigns[e.Obj] {
				if a.within != nil && src.Pos() >= a.within.Pos() && src.Pos() < a.within.End() {
					continue
				}
				out = append(out, a.fieldsOf(src, n+1)...)
			}
		}
		return out
	}
	return nil
}

func (a *driftAnalyzer) call(f *driftFile, call *ast.CallExpr, depth int) {
	if !a.recorded[call] {
		a.record(f, call)
	}
	a.follow(f, call, depth)
}

// record notes what one call does to the request or the response.
func (a *driftAnalyzer) record(f *driftFile, call *ast.CallExpr) {
	facts := a.facts
	sel, _ := call.Fun.(*ast.SelectorExpr)
	recorded := true
	defer func() { a.recorded[call] = recorded }()
	arg := func(i int) ast.Expr {
		if i < len(call.Args) {
			return call.Args[i]
		}
		return nil
	}
	switch {
	case sel != nil && sel.Sel.Name == "Decode" && len(call.Args) == 1:
		// Not settled until the reader is known to be the body: a later
		// visit may hand this function the body.
		r := a.decoderReader(f, sel.X)
		recorded = r != nil && a.isBody(f, r)
		if recorded {
			a.decoded(call, a.typeOf(f, call.Args[0], 0))
		}
	case a.isFunc(f, call.Fun, "encoding/json", "Unmarshal") && len(call.Args) == 2:
		recorded = a.isBody(f, call.Args[0])
		if recorded {
			a.decoded(call, a.typeOf(f, call.Args[1], 0))
		}
	case a.isFunc(f, call.Fun, "io", "ReadAll") && a.isBody(f, arg(0)),
		(a.isFunc(f, call.Fun, "io", "Copy") || a.isFunc(f, call.Fun, "io", "CopyN")) && a.isBody(f, arg(1)):
		facts.rawRead = true
	case sel != nil && a.isRequest(f, sel.X):
		switch sel.Sel.Name {
		case "ParseMultipartForm":
			facts.multipart = true
		case "MultipartReader":
			facts.multipart, facts.streamsParts = true, true
		case "FormFile":
			facts.multipart = true
			if k, ok := stringLit(arg(0)); ok {
				facts.formFiles[k] = true
			}
		case "FormValue", "PostFormValue":
			if k, ok := stringLit(arg(0)); ok {
				facts.formKeys[k] = true
			}
		}
	case sel != nil && (sel.Sel.Name == "Get" || sel.Sel.Name == "Has") && a.isQuery(f, sel.X):
		if k, ok := stringLit(arg(0)); ok {
			facts.queryKeys[k] = true
		}
	case a.isFunc(f, call.Fun, serverPkgPath, "writeJSONResponse") && len(call.Args) == 2:
		a.wroteJSON(f, call, a.headerStatus[call], call.Args[1])
	case (a.isFunc(f, call.Fun, serverPkgPath, "writeJSONStatus") || a.isFunc(f, call.Fun, serverPkgPath, "writeJSONError")) && len(call.Args) == 3:
		code := a.status(f, call.Args[1], 0)
		facts.statuses[code] = true
		a.wroteJSON(f, call, code, call.Args[2])
	case sel != nil && sel.Sel.Name == "Encode" && len(call.Args) == 1 && a.encodesToWriter(f, sel.X):
		a.wroteJSON(f, call, a.headerStatus[call], call.Args[0])
	case a.isFunc(f, call.Fun, "net/http", "Error") && len(call.Args) == 3:
		code := a.status(f, call.Args[2], 0)
		facts.statuses[code], facts.textErrors[code] = true, true
	case a.isFunc(f, call.Fun, "net/http", "NotFound"):
		facts.statuses[http.StatusNotFound], facts.textErrors[http.StatusNotFound] = true, true
	case sel != nil && sel.Sel.Name == "WriteHeader" && len(call.Args) == 1 && a.isWriter(f, sel.X):
		facts.statuses[a.status(f, call.Args[0], 0)] = true
	case sel != nil && (sel.Sel.Name == "Set" || sel.Sel.Name == "Add") && a.isHeaderOf(f, sel.X):
		if k, ok := stringLit(arg(0)); ok && http.CanonicalHeaderKey(k) == "Content-Type" {
			v, ok := stringLit(arg(1))
			if id, isIdent := arg(1).(*ast.Ident); isIdent {
				v, ok = stringLit(declValue(id))
			}
			if ok {
				mt, _, _ := strings.Cut(v, ";")
				facts.contentTypes[strings.TrimSpace(mt)] = true
			}
		}
	case sel != nil && sel.Sel.Name == "Write" && a.isWriter(f, sel.X),
		a.isFunc(f, call.Fun, "net/http", "ServeContent"), a.isFunc(f, call.Fun, "net/http", "ServeFile"),
		(a.isFunc(f, call.Fun, "io", "Copy") || a.isFunc(f, call.Fun, "io", "CopyN")) && a.isWriter(f, arg(0)):
		facts.rawWrite = true
	// Not settled: a later visit may hand this function the body or query.
	case a.isFunc(f, call.Fun, "io", "ReadAll"), a.isFunc(f, call.Fun, "io", "Copy"), a.isFunc(f, call.Fun, "io", "CopyN"),
		sel != nil && (sel.Sel.Name == "Get" || sel.Sel.Name == "Has"):
		recorded = false
	}
}

// follow analyses a helper in this package that is handed the request,
// the writer, the query or the body.
func (a *driftAnalyzer) follow(f *driftFile, call *ast.CallExpr, depth int) {
	if depth >= driftDepth || a.isFunc(f, call.Fun, serverPkgPath, "writeJSONResponse") || a.isFunc(f, call.Fun, serverPkgPath, "writeJSONStatus") ||
		a.isFunc(f, call.Fun, serverPkgPath, "writeJSONError") {
		return
	}
	callee := a.callee(f, call)
	if callee == nil || callee.file.pkg.path != serverPkgPath || callee.decl.Type.TypeParams != nil {
		return
	}
	follow, rebound := false, false
	params := flattenFields(callee.decl.Type.Params)
	for i, e := range call.Args {
		body, query := a.isBody(f, e), a.isQuery(f, e)
		if body || query || a.isRequest(f, e) || a.isWriter(f, e) {
			follow = true
		}
		if i < len(params) && params[i].name != nil && params[i].name.Obj != nil {
			obj := params[i].name.Obj
			if body && !a.bodyObjs[obj] {
				a.bodyObjs[obj], rebound = true, true
			}
			if query && !a.queryObjs[obj] {
				a.queryObjs[obj], rebound = true, true
			}
		}
	}
	if follow {
		if a.tolerant[call] {
			a.lenient++
			defer func() { a.lenient-- }()
		}
		a.fn(callee, depth+1, rebound)
	}
}

// wroteJSON records a JSON body written with status (0 for the default).
func (a *driftAnalyzer) wroteJSON(f *driftFile, call *ast.CallExpr, status int, v ast.Expr) {
	t := a.typeOf(f, v, 0)
	if status >= 400 {
		a.facts.errorBodies = append(a.facts.errorBodies, driftError{status, t})
		return
	}
	a.facts.writes = append(a.facts.writes, t)
	a.facts.writeStatuses = append(a.facts.writeStatuses, status)
}

// decoderReader is r in json.NewDecoder(r).Decode, also through a
// variable holding the decoder.
func (a *driftAnalyzer) decoderReader(f *driftFile, x ast.Expr) ast.Expr {
	if id, ok := x.(*ast.Ident); ok {
		if v := declValue(id); v != nil {
			x = v
		}
	}
	if c, ok := x.(*ast.CallExpr); ok && a.isFunc(f, c.Fun, "encoding/json", "NewDecoder") && len(c.Args) == 1 {
		return c.Args[0]
	}
	return nil
}

func (a *driftAnalyzer) encodesToWriter(f *driftFile, x ast.Expr) bool {
	if id, ok := x.(*ast.Ident); ok {
		if v := declValue(id); v != nil {
			x = v
		}
	}
	c, ok := x.(*ast.CallExpr)
	return ok && a.isFunc(f, c.Fun, "encoding/json", "NewEncoder") && len(c.Args) == 1 && a.isWriter(f, c.Args[0])
}

// isHeaderOf is w.Header() for the response writer.
func (a *driftAnalyzer) isHeaderOf(f *driftFile, x ast.Expr) bool {
	c, ok := x.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Header" && a.isWriter(f, sel.X)
}

func (a *driftAnalyzer) isRequest(f *driftFile, e ast.Expr) bool {
	return e != nil && a.isNamedType(a.typeOf(f, e, 0), "net/http", "Request", true)
}

func (a *driftAnalyzer) isWriter(f *driftFile, e ast.Expr) bool {
	return e != nil && a.isNamedType(a.typeOf(f, e, 0), "net/http", "ResponseWriter", false)
}

// isBody is the request body, or a value read or wrapped from it
// (http.MaxBytesReader, io.LimitReader, io.ReadAll).
func (a *driftAnalyzer) isBody(f *driftFile, e ast.Expr) bool {
	return a.isBodyN(f, e, 0)
}

func (a *driftAnalyzer) isBodyN(f *driftFile, e ast.Expr, n int) bool {
	if e == nil || n > 6 {
		return false
	}
	switch e := e.(type) {
	case *ast.ParenExpr:
		return a.isBodyN(f, e.X, n+1)
	case *ast.SelectorExpr:
		return e.Sel.Name == "Body" && a.isRequest(f, e.X)
	case *ast.CallExpr:
		if a.isFunc(f, e.Fun, "encoding/json", "NewDecoder") {
			return false
		}
		for _, x := range e.Args {
			if a.isBodyN(f, x, n+1) {
				return true
			}
		}
	case *ast.Ident:
		if e.Obj != nil && a.bodyObjs[e.Obj] {
			return true
		}
		return a.isBodyN(f, declSource(e), n+1)
	}
	return false
}

// isQuery is r.URL.Query(), or a variable or parameter holding it.
func (a *driftAnalyzer) isQuery(f *driftFile, e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Query" {
			return false
		}
		u, ok := sel.X.(*ast.SelectorExpr)
		return ok && u.Sel.Name == "URL" && a.isRequest(f, u.X)
	case *ast.Ident:
		if e.Obj != nil && a.queryObjs[e.Obj] {
			return true
		}
		if v := declValue(e); v != nil {
			return a.isQuery(f, v)
		}
	}
	return false
}

// isFunc reports whether fun names the function pkgPath.name: a
// qualified pkg.name, or a bare name within that package.
func (a *driftAnalyzer) isFunc(f *driftFile, fun ast.Expr, pkgPath, name string) bool {
	switch fun := fun.(type) {
	case *ast.Ident:
		return f.pkg.path == pkgPath && fun.Name == name && (fun.Obj == nil || fun.Obj.Kind == ast.Fun)
	case *ast.SelectorExpr:
		id, ok := fun.X.(*ast.Ident)
		return ok && id.Obj == nil && f.imports[id.Name] == pkgPath && fun.Sel.Name == name
	}
	return false
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// status evaluates a status code: a literal, an http.Status constant, or
// a constant or variable initialized from one.
func (a *driftAnalyzer) status(f *driftFile, e ast.Expr, n int) int {
	if n > 4 {
		return 0
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		code, _ := strconv.Atoi(e.Value)
		return code
	case *ast.SelectorExpr:
		if id, ok := e.X.(*ast.Ident); ok && f.imports[id.Name] == "net/http" {
			return httpStatusConsts[e.Sel.Name]
		}
	case *ast.Ident:
		if v := declValue(e); v != nil {
			return a.status(f, v, n+1)
		}
	}
	return 0
}

var httpStatusConsts = map[string]int{
	"StatusOK": 200, "StatusCreated": 201, "StatusAccepted": 202, "StatusNonAuthoritativeInfo": 203, "StatusNoContent": 204,
	"StatusResetContent": 205, "StatusPartialContent": 206, "StatusMultiStatus": 207,
	"StatusMultipleChoices": 300, "StatusMovedPermanently": 301, "StatusFound": 302, "StatusSeeOther": 303,
	"StatusNotModified": 304, "StatusTemporaryRedirect": 307, "StatusPermanentRedirect": 308,
	"StatusBadRequest": 400, "StatusUnauthorized": 401, "StatusPaymentRequired": 402, "StatusForbidden": 403,
	"StatusNotFound": 404, "StatusMethodNotAllowed": 405, "StatusNotAcceptable": 406, "StatusRequestTimeout": 408,
	"StatusConflict": 409, "StatusGone": 410, "StatusLengthRequired": 411, "StatusPreconditionFailed": 412,
	"StatusRequestEntityTooLarge": 413, "StatusRequestURITooLong": 414, "StatusUnsupportedMediaType": 415,
	"StatusRequestedRangeNotSatisfiable": 416, "StatusExpectationFailed": 417, "StatusTeapot": 418,
	"StatusMisdirectedRequest": 421, "StatusUnprocessableEntity": 422, "StatusLocked": 423, "StatusFailedDependency": 424,
	"StatusTooEarly": 425, "StatusUpgradeRequired": 426, "StatusPreconditionRequired": 428, "StatusTooManyRequests": 429,
	"StatusRequestHeaderFieldsTooLarge": 431, "StatusUnavailableForLegalReasons": 451,
	"StatusInternalServerError": 500, "StatusNotImplemented": 501, "StatusBadGateway": 502, "StatusServiceUnavailable": 503,
	"StatusGatewayTimeout": 504, "StatusHTTPVersionNotSupported": 505, "StatusInsufficientStorage": 507,
}

// --- types from the source ----------------------------------------------------

// declValue is the expression a local variable or constant was
// initialized with, when it was declared with exactly one value.
func declValue(id *ast.Ident) ast.Expr {
	if id.Obj == nil {
		return nil
	}
	switch d := id.Obj.Decl.(type) {
	case *ast.ValueSpec:
		for i, n := range d.Names {
			if n.Name == id.Name && len(d.Values) == len(d.Names) {
				return d.Values[i]
			}
		}
	case *ast.AssignStmt:
		for i, l := range d.Lhs {
			if l, ok := l.(*ast.Ident); ok && l.Name == id.Name && len(d.Rhs) == len(d.Lhs) {
				return d.Rhs[i]
			}
		}
	}
	return nil
}

// declSource is what a local variable was initialized from: its own
// value, or the one call that returned several (raw, err := io.ReadAll(…)).
func declSource(id *ast.Ident) ast.Expr {
	if v := declValue(id); v != nil {
		return v
	}
	if id.Obj == nil {
		return nil
	}
	switch d := id.Obj.Decl.(type) {
	case *ast.ValueSpec:
		if len(d.Values) == 1 {
			return d.Values[0]
		}
	case *ast.AssignStmt:
		if len(d.Rhs) == 1 {
			if _, ok := d.Rhs[0].(*ast.CallExpr); ok {
				return d.Rhs[0]
			}
		}
	}
	return nil
}

// typeOf is the type of expression e, as far as the source says it.
func (a *driftAnalyzer) typeOf(f *driftFile, e ast.Expr, n int) driftType {
	if n > 10 {
		return driftType{}
	}
	switch e := e.(type) {
	case *ast.ParenExpr:
		return a.typeOf(f, e.X, n+1)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return a.typeOf(f, e.X, n+1)
		}
	case *ast.StarExpr: // *p is what p points at
		t := a.typeOf(f, e.X, n+1)
		if star, ok := t.expr.(*ast.StarExpr); ok {
			t.expr = star.X
		}
		return t
	case *ast.CompositeLit:
		switch e.Type.(type) {
		case nil:
			return driftType{}
		case *ast.StructType:
			return driftType{anon: true}
		}
		return driftType{expr: e.Type, file: f}
	case *ast.Ident:
		if e.Obj == nil {
			return driftType{}
		}
		switch d := e.Obj.Decl.(type) {
		case *ast.Field: // a parameter or receiver
			return a.declared(f, d.Type)
		case *ast.ValueSpec:
			i := identIndex(d.Names, e.Name)
			switch {
			case d.Type != nil:
				return a.declared(f, d.Type)
			case len(d.Values) == len(d.Names):
				return a.typeOf(f, d.Values[i], n+1)
			case len(d.Values) == 1:
				return a.result(f, d.Values[0], i)
			}
		case *ast.AssignStmt:
			var lhs []*ast.Ident
			for _, l := range d.Lhs {
				id, _ := l.(*ast.Ident)
				lhs = append(lhs, id)
			}
			i := identIndex(lhs, e.Name)
			switch {
			case i < 0:
			case len(d.Rhs) == len(d.Lhs):
				return a.typeOf(f, d.Rhs[i], n+1)
			case len(d.Rhs) == 1:
				return a.result(f, d.Rhs[0], i)
			}
		}
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok && id.Obj == nil && len(e.Args) > 0 {
			switch id.Name {
			case "make":
				return a.declared(f, e.Args[0])
			case "new":
				return driftType{expr: &ast.StarExpr{X: e.Args[0]}, file: f}
			}
		}
		return a.result(f, e, 0)
	case *ast.SelectorExpr: // a struct field
		return a.field(a.typeOf(f, e.X, n+1), e.Sel.Name, 0)
	case *ast.IndexExpr: // an element
		t := a.resolveNamed(a.typeOf(f, e.X, n+1))
		switch x := t.expr.(type) {
		case *ast.ArrayType:
			return driftType{expr: x.Elt, file: t.file}
		case *ast.MapType:
			return driftType{expr: x.Value, file: t.file}
		}
	}
	return driftType{}
}

func (a *driftAnalyzer) declared(f *driftFile, e ast.Expr) driftType {
	if _, ok := e.(*ast.StructType); ok {
		return driftType{anon: true}
	}
	return driftType{expr: e, file: f}
}

func identIndex(ids []*ast.Ident, name string) int {
	for i, id := range ids {
		if id != nil && id.Name == name {
			return i
		}
	}
	return -1
}

// result is the type of a call's i'th result, from the callee's
// declaration.
func (a *driftAnalyzer) result(f *driftFile, e ast.Expr, i int) driftType {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return driftType{}
	}
	callee := a.callee(f, call)
	if callee == nil || callee.decl.Type.TypeParams != nil {
		return driftType{}
	}
	results := flattenFields(callee.decl.Type.Results)
	if i < 0 || i >= len(results) {
		return driftType{}
	}
	return a.declared(callee.file, results[i].typ)
}

type flatField struct {
	name *ast.Ident
	typ  ast.Expr
}

func flattenFields(fl *ast.FieldList) []flatField {
	var out []flatField
	if fl == nil {
		return nil
	}
	for _, fd := range fl.List {
		if len(fd.Names) == 0 {
			out = append(out, flatField{typ: fd.Type})
		}
		for _, n := range fd.Names {
			out = append(out, flatField{name: n, typ: fd.Type})
		}
	}
	return out
}

// callee is the function or method a call resolves to, when it is
// declared in a parsed package.
func (a *driftAnalyzer) callee(f *driftFile, call *ast.CallExpr) *driftFunc {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if fun.Obj != nil && fun.Obj.Kind != ast.Fun {
			return nil
		}
		return f.pkg.funcs[fun.Name]
	case *ast.SelectorExpr:
		if id, ok := fun.X.(*ast.Ident); ok && id.Obj == nil {
			if ip, ok := f.imports[id.Name]; ok {
				if p := a.src.pkgs[ip]; p != nil {
					return p.funcs[fun.Sel.Name]
				}
				return nil
			}
		}
		t := a.resolveNamed(a.typeOf(f, fun.X, 0))
		if pkg, name := a.namedIn(t); pkg != nil {
			return pkg.methods[name][fun.Sel.Name]
		}
	}
	return nil
}

// namedIn is the parsed package and name of a named type (through one
// pointer), or nil.
func (a *driftAnalyzer) namedIn(t driftType) (*driftPkg, string) {
	e := t.expr
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	switch e := e.(type) {
	case *ast.Ident:
		if _, ok := t.file.pkg.types[e.Name]; ok {
			return t.file.pkg, e.Name
		}
	case *ast.SelectorExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			if p := a.src.pkgs[t.file.imports[id.Name]]; p != nil {
				if _, ok := p.types[e.Sel.Name]; ok {
					return p, e.Sel.Name
				}
			}
		}
	}
	return nil, ""
}

// resolveNamed follows aliases (type A = B) to the aliased type, and
// leaves anything else as it is.
func (a *driftAnalyzer) resolveNamed(t driftType) driftType {
	for i := 0; i < 4 && t.expr != nil; i++ {
		pkg, name := a.namedIn(t)
		if pkg == nil {
			return t
		}
		ts := pkg.types[name]
		if !ts.spec.Assign.IsValid() {
			return t
		}
		t = driftType{expr: ts.spec.Type, file: ts.file}
	}
	return t
}

// underlying is the definition of a named type (its struct, map, …).
func (a *driftAnalyzer) underlying(t driftType) driftType {
	for i := 0; i < 4 && t.expr != nil; i++ {
		pkg, name := a.namedIn(driftType{expr: unstar(t.expr), file: t.file})
		if pkg == nil {
			return driftType{expr: unstar(t.expr), file: t.file}
		}
		ts := pkg.types[name]
		t = driftType{expr: ts.spec.Type, file: ts.file}
	}
	return t
}

func unstar(e ast.Expr) ast.Expr {
	if star, ok := e.(*ast.StarExpr); ok {
		return star.X
	}
	return e
}

// field is the type of a struct's field, promoted ones included.
func (a *driftAnalyzer) field(t driftType, name string, n int) driftType {
	if t.expr == nil || n > 3 {
		return driftType{}
	}
	st, ok := a.underlying(t).expr.(*ast.StructType)
	if !ok {
		return driftType{}
	}
	file := a.underlying(t).file
	for _, fd := range st.Fields.List {
		for _, fn := range fd.Names {
			if fn.Name == name {
				return a.declared(file, fd.Type)
			}
		}
	}
	for _, fd := range st.Fields.List {
		if len(fd.Names) == 0 {
			emb := driftType{expr: fd.Type, file: file}
			if _, en := a.namedIn(emb); en == name {
				return emb
			}
			if ft := a.field(emb, name, n+1); ft.expr != nil || ft.anon {
				return ft
			}
		}
	}
	return driftType{}
}

func (a *driftAnalyzer) isNamedType(t driftType, pkgPath, name string, pointer bool) bool {
	e := t.expr
	if pointer {
		star, ok := e.(*ast.StarExpr)
		if !ok {
			return false
		}
		e = star.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && t.file.imports[id.Name] == pkgPath && sel.Sel.Name == name
}

// matches reports whether the source type is the Go type t.
func (a *driftAnalyzer) matches(dt driftType, t reflect.Type) bool {
	dt = a.resolveNamed(dt)
	switch e := dt.expr.(type) {
	case *ast.ParenExpr:
		return a.matches(driftType{expr: e.X, file: dt.file}, t)
	case *ast.StarExpr:
		return t.Kind() == reflect.Pointer && a.matches(driftType{expr: e.X, file: dt.file}, t.Elem())
	case *ast.ArrayType:
		if e.Len == nil && t.Kind() != reflect.Slice || e.Len != nil && t.Kind() != reflect.Array {
			return false
		}
		return a.matches(driftType{expr: e.Elt, file: dt.file}, t.Elem())
	case *ast.MapType:
		return t.Kind() == reflect.Map && a.matches(driftType{expr: e.Key, file: dt.file}, t.Key()) &&
			a.matches(driftType{expr: e.Value, file: dt.file}, t.Elem())
	case *ast.InterfaceType:
		return t.Kind() == reflect.Interface && len(e.Methods.List) == 0 && t.NumMethod() == 0
	case *ast.Ident:
		if _, local := dt.file.pkg.types[e.Name]; !local && types.Universe.Lookup(e.Name) != nil {
			switch e.Name {
			case "any":
				return t.Kind() == reflect.Interface && t.NumMethod() == 0
			case "byte":
				return t == reflect.TypeFor[byte]()
			case "rune":
				return t == reflect.TypeFor[rune]()
			}
			return t.PkgPath() == "" && t.Name() == e.Name
		}
		return t.PkgPath() == dt.file.pkg.path && t.Name() == e.Name
	case *ast.SelectorExpr:
		id, ok := e.X.(*ast.Ident)
		return ok && t.PkgPath() == dt.file.imports[id.Name] && t.Name() == e.Sel.Name
	}
	return false
}

// matchesResponse also accepts a pointer on either side: *T and T are
// the same JSON.
func (a *driftAnalyzer) matchesResponse(dt driftType, t reflect.Type) bool {
	if a.matches(dt, t) || t.Kind() == reflect.Pointer && a.matches(dt, t.Elem()) {
		return true
	}
	if star, ok := dt.expr.(*ast.StarExpr); ok {
		return a.matches(driftType{expr: star.X, file: dt.file}, t)
	}
	return false
}

// isNamedValue is a written value whose type has a name a declaration
// can give it: T, *T or []T, for a type that is not a map, any or raw
// JSON.
func (a *driftAnalyzer) isNamedValue(dt driftType) bool {
	e := a.resolveNamed(dt).expr
	for {
		switch x := e.(type) {
		case *ast.StarExpr:
			e = x.X
			continue
		case *ast.ArrayType:
			e = x.Elt
			continue
		}
		break
	}
	elem := driftType{expr: e, file: dt.file}
	switch x := e.(type) {
	case *ast.Ident:
		if types.Universe.Lookup(x.Name) != nil {
			if _, local := dt.file.pkg.types[x.Name]; !local {
				return false
			}
		}
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok && dt.file.imports[id.Name] == "encoding/json" {
			return false
		}
	default:
		return false
	}
	_, isMap := a.underlying(elem).expr.(*ast.MapType)
	return !isMap
}

// isMapValue is a map, or a slice of maps: a response with no type to
// reflect on.
func (a *driftAnalyzer) isMapValue(dt driftType) bool {
	e := a.underlying(dt).expr
	for {
		switch x := e.(type) {
		case *ast.ArrayType:
			e = a.underlying(driftType{expr: x.Elt, file: dt.file}).expr
			continue
		case *ast.MapType:
			return true
		}
		return false
	}
}

func describe(ts []driftType) string {
	if len(ts) == 0 {
		return "nothing"
	}
	var out []string
	for _, t := range ts {
		switch {
		case t.anon:
			out = append(out, "an anonymous struct")
		case t.expr == nil:
			out = append(out, "a value of unknown type")
		default:
			out = append(out, render(t.expr, t.file))
		}
	}
	return strings.Join(out, ", ")
}

// render writes a type expression the way a declaration in this package
// would: a type from store is store.T, wherever it was resolved from.
func render(e ast.Expr, f *driftFile) string {
	switch e := e.(type) {
	case *ast.Ident:
		if _, local := f.pkg.types[e.Name]; !local && types.Universe.Lookup(e.Name) != nil || f.pkg.path == serverPkgPath {
			return e.Name
		}
		return path.Base(f.pkg.path) + "." + e.Name
	case *ast.StarExpr:
		return "*" + render(e.X, f)
	case *ast.ArrayType:
		if e.Len == nil {
			return "[]" + render(e.Elt, f)
		}
		return "[" + types.ExprString(e.Len) + "]" + render(e.Elt, f)
	case *ast.MapType:
		return "map[" + render(e.Key, f) + "]" + render(e.Value, f)
	}
	return types.ExprString(e)
}

// --- the checks -----------------------------------------------------------------

// driftExceptions are what the analyzer cannot see, each listed with the
// reason; an entry that stops applying is reported.
type driftExceptions struct {
	// requiredUnseen: package.Type.field of a required field whose check
	// happens out of sight.
	requiredUnseen map[string]string
	// writesUnreached: "handler Type" of a response the handler reaches
	// only through another route's handler, in a branch its own routes
	// never take.
	writesUnreached map[string]string
}

// checkDrift compares each declaration with what its handler does.
// handlers maps every registered /api pattern to its handler method's
// name on *Server.
func checkDrift(src *driftSource, handlers map[string]string, docs map[string]routeDoc, ex driftExceptions) []string {
	var problems []string
	add := func(where, format string, args ...any) {
		problems = append(problems, where+": "+fmt.Sprintf(format, args...))
	}
	for p := range docs {
		if _, ok := handlers[p]; !ok {
			add(p, "routeDocs declares a route that is not registered")
		}
	}
	byHandler := map[string][]string{}
	for p, h := range handlers {
		byHandler[h] = append(byHandler[h], p)
	}
	unseen, unreached := map[string]bool{}, map[string]bool{}
	for h, patterns := range byHandler {
		sort.Strings(patterns)
		var documented, undocumented []string
		skip := false
		for _, p := range patterns {
			if d, ok := docs[p]; ok {
				documented = append(documented, p)
				skip = skip || d.DriftOK != ""
			} else {
				undocumented = append(undocumented, p)
			}
		}
		switch {
		case len(documented) == 0 || skip:
			continue
		case len(undocumented) > 0:
			// One handler, one set of facts: they can only be checked
			// against all of its routes' declarations at once.
			add(strings.Join(documented, ", "), "%s also serves %s; declare all of its routes", h, strings.Join(undocumented, ", "))
			continue
		}
		fn := src.pkgs[serverPkgPath].methods["Server"][h]
		if fn == nil {
			add(strings.Join(patterns, ", "), "handler %s is not in the source", h)
			continue
		}
		a := &driftAnalyzer{src: src}
		facts := analyzeHandler(src, fn)
		checkHandler(a, facts, h, patterns, docs, ex.writesUnreached, unreached, add)
		for _, p := range patterns {
			checkRequired(a, facts, p, docs[p], ex.requiredUnseen, unseen, add)
		}
	}
	for key := range ex.requiredUnseen {
		if !unseen[key] {
			add(key, "requiredUnseen lists a field that is not a required field of a declared body; remove it")
		}
	}
	for key := range ex.writesUnreached {
		if !unreached[key] {
			add(key, "writesUnreached lists a response the handler does not write undeclared; remove it")
		}
	}
	sort.Strings(problems)
	return slices.Compact(problems)
}

// checkRequired holds a route's required body fields (tagged on its type,
// or listed in its Required) to its handler: each must be rejected when
// missing and never filled in, and a field the handler itself surely
// rejects at its top level must be one of them.
func checkRequired(a *driftAnalyzer, facts *handlerFacts, p string, d routeDoc, unseenOK map[string]string, unseen map[string]bool, add func(string, string, ...any)) {
	if d.Body == nil || reflect.TypeOf(d.Body).Kind() != reflect.Struct {
		if len(d.Required) > 0 {
			add(p, "declares Required, but its body is not a struct")
		}
		return
	}
	t := reflect.TypeOf(d.Body)
	// A promoted field is checked on the body or on its embedded struct
	// (in := body.Integration; in.Kind == "").
	holders := []reflect.Type{t}
	for i := 0; i < t.NumField(); i++ {
		if sf := t.Field(i); sf.Anonymous {
			holders = append(holders, sf.Type)
		}
	}
	held := func(fc fieldCheck) bool {
		for _, h := range holders {
			if a.matches(fc.typ, h) || a.matches(fc.typ, reflect.PointerTo(h)) {
				return true
			}
		}
		return false
	}
	rejects, defaults, surely, set := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, fc := range facts.fieldChecks {
		if held(fc) {
			rejects[fc.field] = rejects[fc.field] || fc.rejects
			defaults[fc.field] = defaults[fc.field] || fc.defaults
			surely[fc.field] = surely[fc.field] || fc.rejects && fc.sure && fc.top
		}
	}
	for _, fc := range facts.assignedFields {
		if held(fc) {
			set[fc.field] = true
		}
	}
	goName, tagged, listed := map[string]string{}, map[string]bool{}, map[string]bool{}
	fields := jsonFields(t)
	for _, f := range fields {
		goName[f.name] = t.FieldByIndex(f.index).Name
		tagged[f.name] = f.required
	}
	for _, name := range d.Required {
		if _, ok := goName[name]; !ok {
			add(p, "declares Required %q, which %s has no field for", name, t)
			continue
		}
		listed[name] = true
	}
	for _, f := range fields {
		g, key := goName[f.name], t.String()+"."+f.name
		switch {
		case !tagged[f.name] && !listed[f.name]:
			if surely[g] && !defaults[g] && !set[g] {
				add(p, "the handler rejects a request without %s; tag it api:\"required\", or list it in Required", f.name)
			}
		case defaults[g] && tagged[f.name]:
			add(p, "%s.%s is tagged required, but a handler fills it in when it is missing; drop the tag", t, f.name)
		case defaults[g]:
			add(p, "declares %s required, but the handler fills it in when it is missing", f.name)
		case unseenOK[key] != "" && rejects[g]:
			unseen[key] = true
			add(p, "requiredUnseen lists %s, but the analyzer sees this handler reject a request without it; remove it", key)
		case unseenOK[key] != "":
			unseen[key] = true
		case !rejects[g] && tagged[f.name]:
			add(p, "%s.%s is tagged required, but this handler does not reject a request without it", t, f.name)
		case !rejects[g]:
			add(p, "declares %s required, but this handler does not reject a request without it", f.name)
		}
	}
}

// requiredUnseen are required fields whose check the analyzer cannot
// follow, rejected two calls down, on a copy, or after a search; each
// says where. Keep it short: a check written as x.F == "" or similar,
// in a switch, a validator or a lookup, needs no entry, and an entry
// whose check the analyzer comes to see is reported.
var requiredUnseen = map[string]string{
	"server.importDeployFileRequest.url":                "url.Parse(body.URL) must give an https URL with a host",
	"server.completeCustomSensorScriptRequest.platform": "normalizeSensorScripts accepts only linux, darwin and windows",
	"server.enforceCompileRequest.kind":                 "enforcekinds.Compile rejects a kind it does not know",
	"server.enforceCompileRequest.config":               "enforcekinds.Compile rejects an empty configuration",
	"server.saveDashboardAlertRequest.panel_id":         "no panel on the dashboard has an empty ID, so the search for it fails",
	"store.MaintenanceWindow.start_time":                "maintenance.Window.Validate rejects it, on the copy engineWindow makes",
	"store.MaintenanceWindow.duration_minutes":          "maintenance.Window.Validate rejects it, on the copy engineWindow makes",
	"server.testCustomSensorRequest.sensor":             "a sensor without a script for the endpoint's platform is rejected",
	"server.adoptSoftwareRequest.platforms":             "no platform, no guessed command, and a package without one is rejected",
	"proto.DeploySettings.endpoint_logs":                "deploylog.Validate rejects zero limits, called in a loop over both blocks",
	"proto.DeploySettings.server_logs":                  "deploylog.Validate rejects zero limits, called in a loop over both blocks",
}

// writesUnreached are responses a handler reaches only through another
// route's handler, in a branch its own requests never take.
var writesUnreached = map[string]string{
	"handleDeploySoftware deployPreviewResponse":       "forwards to handleDeployRun, whose preview answers only /api/deploy/preview",
	"handleRemoveUnusedSoftware deployPreviewResponse": "forwards to handleDeployRun, whose preview answers only /api/deploy/preview",
}

func checkHandler(a *driftAnalyzer, facts *handlerFacts, h string, patterns []string, docs map[string]routeDoc, unreachedOK map[string]string, unreached map[string]bool, add func(string, string, ...any)) {
	bodyClaimed := false
	queryDeclared, formDeclared := map[string]bool{}, map[string]bool{}
	statusDeclared, contentDeclared := map[int]bool{}, map[string]bool{}
	// Every route's spec carries 401 and 403 already.
	errorDeclared := map[int]bool{http.StatusUnauthorized: true, http.StatusForbidden: true}
	alsoDeclared := map[int]bool{}
	var resps []reflect.Type
	for _, p := range patterns {
		d := docs[p]
		bodyClaimed = bodyClaimed || d.Body != nil || d.Upload != nil || d.Raw != ""
		for _, q := range d.Query {
			queryDeclared[q.Name] = true
		}
		for _, f := range d.Upload {
			formDeclared[f.Name] = true
		}
		statusDeclared[d.Status] = true
		for _, code := range d.Also {
			statusDeclared[code], alsoDeclared[code] = true, true
		}
		contentDeclared[d.Content] = true
		for _, code := range d.Errors {
			errorDeclared[code] = true
		}
		for code := range d.ErrorBody {
			errorDeclared[code] = true
		}
		if d.Resp != nil {
			resps = append(resps, reflect.TypeOf(d.Resp))
		}
		for _, v := range d.RespAlt {
			resps = append(resps, reflect.TypeOf(v))
		}
	}
	jsonErrors := map[int]bool{}
	for _, e := range facts.errorBodies {
		jsonErrors[e.status] = true
	}
	unknownWrite := facts.rawWrite
	for _, w := range facts.writes {
		unknownWrite = unknownWrite || w.expr == nil && !w.anon
	}

	for _, p := range patterns {
		d := docs[p]
		hasBody := d.Body != nil || d.Upload != nil || d.Raw != ""
		if mutatingMethod(routeMethod(p)) && routeMethod(p) != http.MethodDelete && !hasBody && !d.NoBody {
			add(p, "declare what the body is: Body, NoBody, Upload or Raw")
		}
		if d.NoBody && hasBody {
			add(p, "NoBody, and also a body")
		}
		if d.Body != nil {
			t := reflect.TypeOf(d.Body)
			found := false
			for _, dt := range facts.decodes {
				found = found || a.matches(dt, t)
			}
			if !found {
				add(p, "declares Body %s, but the handler decodes %s", t, describe(facts.decodes))
			}
		}
		// A body is optional when the handler copes without one and the
		// type has no field a request must carry. Optional uploads and
		// raw bodies are taken on trust: the parse is skipped by logic
		// (restore by ?id=) the checker does not follow.
		if d.Body != nil {
			optional := facts.tolerantDecode && !facts.strictDecode && !hasRequired(reflect.TypeOf(d.Body))
			switch {
			case optional && !d.BodyOptional:
				add(p, "the handler accepts a request without a body; declare BodyOptional")
			case d.BodyOptional && !optional:
				add(p, "declares BodyOptional, but the handler rejects a request without a body")
			}
		}
		if d.NoBody && !bodyClaimed && (len(facts.decodes) > 0 || facts.rawRead || facts.multipart) {
			add(p, "declares NoBody, but the handler reads one (decodes %s)", describe(facts.decodes))
		}
		if d.Upload != nil && !facts.multipart {
			add(p, "declares Upload, but the handler parses no multipart form")
		}
		for _, f := range d.Upload {
			read := facts.formKeys[f.Name] || facts.streamsParts
			if f.File {
				read = facts.formFiles[f.Name] || facts.streamsParts
			}
			if !read {
				add(p, "declares upload field %q, which the handler never reads", f.Name)
			}
		}
		if d.Raw != "" && !facts.rawRead {
			add(p, "declares Raw %s, but the handler does not read the body as bytes", d.Raw)
		}
		for _, q := range d.Query {
			if !facts.queryKeys[q.Name] && !facts.formKeys[q.Name] {
				add(p, "declares query parameter %q, which the handler never reads", q.Name)
			}
		}
		if d.Resp != nil {
			t := reflect.TypeOf(d.Resp)
			found, maps := false, false
			for _, w := range facts.writes {
				found = found || a.matchesResponse(w, t)
				maps = maps || w.anon || a.isMapValue(w)
			}
			switch {
			case found || unknownWrite:
			case maps:
				add(p, "declares Resp %s, but the handler writes a map or anonymous struct; convert this response to a named struct", t)
			default:
				add(p, "declares Resp %s, but the handler writes %s", t, describe(facts.writes))
			}
		}
		if d.Resp == nil && len(d.RespAlt) > 0 {
			add(p, "declares RespAlt without Resp")
		}
		for _, v := range d.RespAlt {
			t := reflect.TypeOf(v)
			found := unknownWrite
			for _, w := range facts.writes {
				found = found || a.matchesResponse(w, t)
			}
			if !found {
				add(p, "declares RespAlt %s, but the handler writes %s", t, describe(facts.writes))
			}
		}
		for _, code := range append([]int{d.Status}, d.Also...) {
			if code != 0 && !facts.statuses[code] {
				add(p, "declares status %d, which the handler never sets", code)
			}
		}
		if d.Content != "" && !facts.contentTypes[d.Content] {
			add(p, "declares Content %q, which the handler never sets", d.Content)
		}
		for _, code := range d.Errors {
			if !facts.statuses[code] {
				add(p, "declares error %d, which the handler never returns", code)
			} else if !facts.textErrors[code] && jsonErrors[code] {
				add(p, "declares error %d as text, but the handler answers it only with JSON; that is ErrorBody's", code)
			}
		}
		for code, v := range d.ErrorBody {
			t := reflect.TypeOf(v)
			var written []driftType
			found := false
			for _, e := range facts.errorBodies {
				if e.status == code {
					written = append(written, e.typ)
					found = found || a.matchesResponse(e.typ, t) || e.typ.expr == nil && !e.typ.anon
				}
			}
			if !found {
				add(p, "declares ErrorBody %d %s, but the handler writes %s", code, t, describe(written))
			}
		}
	}

	// What the handler does, one of its routes has to declare.
	where := strings.Join(patterns, ", ")
	var keys []string
	for k := range facts.queryKeys {
		keys = append(keys, k)
	}
	for k := range facts.formKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !queryDeclared[k] && !formDeclared[k] {
			add(where, "the handler reads query parameter %q; declare it", k)
			queryDeclared[k] = true
		}
	}
	for i, w := range facts.writes {
		named, shapeless := a.isNamedValue(w), w.anon || a.isMapValue(w)
		if alsoDeclared[facts.writeStatuses[i]] {
			continue // an Also answer is any object
		}
		if !named && !shapeless {
			continue
		}
		found := false
		for _, t := range resps {
			found = found || a.matchesResponse(w, t)
		}
		key := h + " " + describe([]driftType{w})
		switch {
		case found:
		case unreachedOK[key] != "":
			unreached[key] = true
		case named:
			add(where, "the handler writes %s; declare it as Resp", describe([]driftType{w}))
		case len(resps) > 0:
			add(where, "the handler also writes a map or anonymous struct; convert it to a named struct and declare it in RespAlt")
		}
	}
	for _, e := range facts.errorBodies {
		if e.typ.expr == nil && !e.typ.anon {
			continue
		}
		found := false
		for _, p := range patterns {
			if v, ok := docs[p].ErrorBody[e.status]; ok {
				found = found || a.matchesResponse(e.typ, reflect.TypeOf(v))
			}
		}
		if !found {
			add(where, "the handler answers %d with %s; declare ErrorBody: map[int]any{%d: …}", e.status, describe([]driftType{e.typ}), e.status)
		}
	}
	var codes []int
	for code := range facts.statuses {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	for _, code := range codes {
		if code > 200 && code < 300 && !statusDeclared[code] {
			add(where, "the handler responds %d; declare Status: %d, or Also: []int{%d} beside a 200", code, code, code)
		}
		if code >= 400 && !errorDeclared[code] {
			add(where, "the handler returns %d; declare it in Errors or ErrorBody", code)
		}
	}
	var cts []string
	for ct := range facts.contentTypes {
		if ct != "application/json" {
			cts = append(cts, ct)
		}
	}
	sort.Strings(cts)
	for _, ct := range cts {
		if !contentDeclared[ct] {
			add(where, "the handler sends %s; declare it as Content", ct)
		}
	}
	if len(cts) > 0 && len(resps) == 0 && len(facts.writes) > 0 {
		add(where, "the handler also writes JSON; declare Resp (map[string]any{} for a map)")
	}
	if !bodyClaimed && (len(facts.decodes) > 0 || facts.rawRead || facts.multipart) {
		noBody := false
		for _, p := range patterns {
			noBody = noBody || docs[p].NoBody
		}
		if !noBody {
			add(where, "the handler reads a request body (%s); declare it", describe(facts.decodes))
		}
	}
}

// hasRequired reports whether a body of type t has a field tagged
// required, which an empty body cannot supply.
func hasRequired(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	for _, f := range jsonFields(t) {
		if f.required {
			return true
		}
	}
	return false
}

// --- the tests ------------------------------------------------------------------

// apiHandlers maps each /api route to the name of its handler method.
func apiHandlers(t *testing.T) map[string]string {
	t.Helper()
	s := &Server{logger: slog.Default()}
	s.routes()
	out := map[string]string{}
	for _, e := range s.routeLog.entries {
		_, p, _ := strings.Cut(e.Pattern, " ")
		if !strings.HasPrefix(p, "/api/") || strings.HasSuffix(p, "/") {
			continue
		}
		f, ok := unwrapHandler(e.Handler).(http.HandlerFunc)
		if !ok {
			t.Fatalf("%s: handler is %T, not a method", e.Pattern, unwrapHandler(e.Handler))
		}
		m := handlerNameRe.FindStringSubmatch(runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name())
		if m == nil {
			t.Fatalf("%s: handler is not a (*Server).handle… method", e.Pattern)
		}
		out[e.Pattern] = m[1]
	}
	return out
}

func TestOpenAPIRouteDocsMatchHandlers(t *testing.T) {
	for _, p := range checkDrift(loadDriftSource(t), apiHandlers(t), routeDocs, driftExceptions{requiredUnseen, writesUnreached}) {
		t.Error(p)
	}
}

func TestOpenAPIDeclarationRatchet(t *testing.T) {
	n := 0
	for p := range apiHandlers(t) {
		if _, ok := routeDocs[p]; !ok {
			n++
		}
	}
	switch {
	case n > undocumentedRoutes:
		t.Errorf("%d /api routes have no routeDocs entry, more than the %d allowed: a new route needs one (openapi_routes.go)", n, undocumentedRoutes)
	case n < undocumentedRoutes:
		t.Errorf("only %d /api routes have no routeDocs entry: lower undocumentedRoutes to %d", n, n)
	}
}
