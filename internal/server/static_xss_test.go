package server

// This test is a static guard against DOM XSS in the console. Every page
// builds markup with template literals and innerHTML, and every value that
// came from the API has to be treated as an attacker-chosen string: agents
// report raw JSON that the server passes through, and lower-privileged
// operators choose object IDs and names. A missed escapeHtml() is therefore
// stored XSS in an operator session that can run commands fleet-wide.
//
// The checker lexes every inline <script> and every first-party .js file
// under static/ and, for each template literal containing markup, each
// innerHTML/outerHTML assignment and each insertAdjacentHTML call, proves
// that every interpolated value is one of:
//
//   - escapeHtml(...) / chartEsc(...), or another call whose result cannot
//     carry markup (Number(...), Math.*, a comparison, arithmetic, ...);
//   - a string/number literal or a nested template literal that is itself
//     checked the same way;
//   - a ternary/||/&&/+ whose output operands are all of the above;
//   - xs.map(f).join(sep) where f returns one of the above;
//   - a first-party function whose every return value is one of the above;
//   - a local variable whose every assignment (and every .push) is one of
//     the above and which is never a function parameter or a destructured
//     binding anywhere in the same file.
//
// Values interpolated at the start of an href/src/action attribute must also
// pass through safeUrl(...) (or be a relative literal path), so a javascript:
// URL from data can't be produced even when the markup is escaped.
//
// Anything else fails the test. A value that is safe for a reason this
// checker can't see is accepted only with an explicit comment as the first
// thing in the expression, which a reviewer can then read:
//
//   ${/* safe-html: rows were each built from escaped cells above */ rows}
//   return /* safe-html: ... */ html;
//
// The comment needs a reason after the colon. Keep these rare.

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type jsTokKind int

const (
	tkIdent jsTokKind = iota
	tkNum
	tkStr
	tkTmpl
	tkPunct
	tkComment
	tkRegex
)

type jsTok struct {
	kind  jsTokKind
	text  string
	pos   int  // byte offset in the file
	nl    bool // a line break precedes this token
	allow bool // an allow comment preceded this token
	quasi []string
	exprs [][]jsTok
	epos  []int // offset of each "${"
	eend  []int // offset of the "}" closing each one
}

var jsPuncts = []string{
	">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
	"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=",
	"*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
}

var regexAfterKeyword = map[string]bool{
	"return": true, "typeof": true, "case": true, "in": true, "of": true, "delete": true,
	"void": true, "throw": true, "new": true, "instanceof": true, "else": true, "do": true, "yield": true, "await": true,
}

type jsLexer struct {
	src  string
	base int // added to every recorded position
	i    int
	err  error
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isIdentPart(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

// lex reads tokens until EOF or, in template-expression mode, the "}" that
// closes the "${".
func (l *jsLexer) lex(inTemplate bool) []jsTok {
	var out []jsTok
	depth := 0
	nl := false
	prevSig := func() *jsTok {
		for k := len(out) - 1; k >= 0; k-- {
			if out[k].kind != tkComment {
				return &out[k]
			}
		}
		return nil
	}
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case c == '\n':
			nl = true
			l.i++
			continue
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			l.i++
			continue
		}
		start := l.i
		tok := jsTok{pos: l.base + start, nl: nl}
		nl = false
		switch {
		case strings.HasPrefix(l.src[l.i:], "//"):
			j := strings.IndexByte(l.src[l.i:], '\n')
			if j < 0 {
				j = len(l.src) - l.i
			}
			tok.kind, tok.text = tkComment, l.src[l.i:l.i+j]
			l.i += j
		case strings.HasPrefix(l.src[l.i:], "/*"):
			j := strings.Index(l.src[l.i+2:], "*/")
			if j < 0 {
				l.err = fmt.Errorf("unterminated comment at %d", tok.pos)
				return out
			}
			tok.kind, tok.text = tkComment, l.src[l.i:l.i+2+j+2]
			if strings.Contains(tok.text, "\n") {
				nl = true
			}
			l.i += 2 + j + 2
		case c == '"' || c == '\'':
			j := l.i + 1
			for j < len(l.src) && l.src[j] != c {
				if l.src[j] == '\\' {
					j++
				}
				j++
			}
			tok.kind, tok.text = tkStr, l.src[l.i+1:min(j, len(l.src))]
			l.i = j + 1
		case c == '`':
			l.i++
			l.template(&tok)
		case c >= '0' && c <= '9' || c == '.' && l.i+1 < len(l.src) && l.src[l.i+1] >= '0' && l.src[l.i+1] <= '9':
			j := l.i
			for j < len(l.src) && (isIdentPart(l.src[j]) || l.src[j] == '.') {
				j++
			}
			tok.kind, tok.text = tkNum, l.src[l.i:j]
			l.i = j
		case isIdentStart(c):
			j := l.i
			for j < len(l.src) && isIdentPart(l.src[j]) {
				j++
			}
			tok.kind, tok.text = tkIdent, l.src[l.i:j]
			l.i = j
		case c == '/':
			p := prevSig()
			isRegex := p == nil || p.kind == tkPunct && p.text != ")" && p.text != "]" ||
				p.kind == tkIdent && regexAfterKeyword[p.text]
			if isRegex {
				j := l.i + 1
				inClass := false
				for j < len(l.src) && l.src[j] != '\n' {
					if l.src[j] == '\\' {
						j += 2
						continue
					}
					if l.src[j] == '[' {
						inClass = true
					} else if l.src[j] == ']' {
						inClass = false
					} else if l.src[j] == '/' && !inClass {
						break
					}
					j++
				}
				j++
				for j < len(l.src) && isIdentPart(l.src[j]) {
					j++
				}
				tok.kind, tok.text = tkRegex, l.src[l.i:min(j, len(l.src))]
				l.i = j
				break
			}
			fallthrough
		default:
			tok.kind = tkPunct
			tok.text = string(c)
			for _, p := range jsPuncts {
				if strings.HasPrefix(l.src[l.i:], p) {
					tok.text = p
					break
				}
			}
			// "?." followed by a digit is a ternary and a number.
			if tok.text == "?." && l.i+2 < len(l.src) && l.src[l.i+2] >= '0' && l.src[l.i+2] <= '9' {
				tok.text = "?"
			}
			l.i += len(tok.text)
			if tok.text == "{" {
				depth++
			} else if tok.text == "}" {
				if depth == 0 && inTemplate {
					return out
				}
				depth--
			}
		}
		out = append(out, tok)
	}
	if inTemplate {
		l.err = fmt.Errorf("unterminated template expression")
	}
	return out
}

func (l *jsLexer) template(tok *jsTok) {
	tok.kind = tkTmpl
	var b strings.Builder
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case c == '\\':
			b.WriteString(l.src[l.i:min(l.i+2, len(l.src))])
			l.i += 2
		case c == '`':
			l.i++
			tok.quasi = append(tok.quasi, b.String())
			return
		case c == '$' && l.i+1 < len(l.src) && l.src[l.i+1] == '{':
			tok.quasi = append(tok.quasi, b.String())
			b.Reset()
			tok.epos = append(tok.epos, l.base+l.i)
			l.i += 2
			tok.exprs = append(tok.exprs, l.lex(true))
			tok.eend = append(tok.eend, l.base+l.i-1)
		default:
			b.WriteByte(c)
			l.i++
		}
	}
	l.err = fmt.Errorf("unterminated template literal at %d", tok.pos)
}

// ---------------------------------------------------------------------------
// Per-file facts: function definitions, variable assignments, bindings.

type jsFunc struct {
	body  []jsTok // block contents (without braces) or an expression
	block bool
}

type jsFile struct {
	name    string
	src     string
	streams [][]jsTok // one per <script> block (or the whole .js file)
	funcs   map[string][]jsFunc
	binds   map[string][]*jsBind
	blocks  [][2]int
	// htmlParamAt marks parameters declared as markup, by position;
	// htmlParams lists them per function name.
	htmlParamAt map[int]bool
	htmlParams  map[string][]int
	pend        []jsAssign
}

type xssFound struct {
	file     string
	pos, end int
	expr     []jsTok
}

type xssChecker struct {
	files      map[string]*jsFile
	shared     []*jsFile
	violations map[string]string // "file:line" -> message
	found      []xssFound
	seenTmpl   map[int]bool
	funcMemo   map[string]int // 0 unknown, 1 safe, 2 unsafe, 3 in progress
	indirect   int            // >0 while evaluating a function's or variable's value
	varMemo    map[string]int
	cur        *jsFile
}

// noComments drops comments. An allow comment is remembered on the token
// that follows it, so it still applies to expressions sliced out later.
func noComments(ts []jsTok) []jsTok {
	out := make([]jsTok, 0, len(ts))
	allow := false
	for _, t := range ts {
		if t.kind == tkComment {
			allow = allow || isAllowComment(t)
			continue
		}
		t.allow = t.allow || allow
		allow = false
		out = append(out, t)
	}
	return out
}

func isP(t jsTok, s ...string) bool {
	if t.kind != tkPunct {
		return false
	}
	for _, x := range s {
		if t.text == x {
			return true
		}
	}
	return false
}

func isKw(t jsTok, s ...string) bool {
	if t.kind != tkIdent {
		return false
	}
	for _, x := range s {
		if t.text == x {
			return true
		}
	}
	return false
}

// match returns the index of the bracket closing ts[i].
func match(ts []jsTok, i int) int {
	open := ts[i].text
	closeB := map[string]string{"(": ")", "[": "]", "{": "}"}[open]
	d := 0
	for j := i; j < len(ts); j++ {
		if isP(ts[j], open) {
			d++
		} else if isP(ts[j], closeB) {
			d--
			if d == 0 {
				return j
			}
		}
	}
	return len(ts) - 1
}

// matchBack returns the index of the bracket opening ts[i].
func matchBack(ts []jsTok, i int) int {
	closeB := ts[i].text
	open := map[string]string{")": "(", "]": "[", "}": "{"}[closeB]
	d := 0
	for j := i; j >= 0; j-- {
		if isP(ts[j], closeB) {
			d++
		} else if isP(ts[j], open) {
			d--
			if d == 0 {
				return j
			}
		}
	}
	return 0
}

func endsOperand(t jsTok) bool {
	switch t.kind {
	case tkNum, tkStr, tkTmpl, tkRegex:
		return true
	case tkIdent:
		return !regexAfterKeyword[t.text]
	case tkPunct:
		return t.text == ")" || t.text == "]" || t.text == "}" || t.text == "++" || t.text == "--"
	}
	return false
}

var continuesExpr = map[string]bool{
	".": true, "?.": true, "?": true, ":": true, "+": true, "-": true, "*": true, "/": true, "%": true,
	"**": true, "||": true, "&&": true, "??": true, "==": true, "===": true, "!=": true, "!==": true,
	"<": true, ">": true, "<=": true, ">=": true, "&": true, "|": true, "^": true, ",": true, "=>": true,
	"<<": true, ">>": true, ">>>": true, "=": true,
}

// extent returns the end (exclusive) of the expression starting at i: the
// first ";" or "," at depth 0, a bracket closing below depth 0, or a line
// break where automatic semicolon insertion would end the statement.
func extent(ts []jsTok, i int, stopComma bool) int {
	d := 0
	for j := i; j < len(ts); j++ {
		t := ts[j]
		if j > i && d == 0 && t.nl && endsOperand(ts[j-1]) && !(t.kind == tkPunct && continuesExpr[t.text]) &&
			!isKw(t, "instanceof", "in") {
			return j
		}
		if t.kind == tkPunct {
			switch t.text {
			case "(", "[", "{":
				d++
			case ")", "]", "}":
				if d == 0 {
					return j
				}
				d--
			case ";":
				if d == 0 {
					return j
				}
			case ",":
				if d == 0 && stopComma {
					return j
				}
			}
		}
	}
	return len(ts)
}

// splitTop splits ts at depth-0 occurrences of any of ops.
func splitTop(ts []jsTok, binaryOnly bool, ops ...string) [][]jsTok {
	var parts [][]jsTok
	d, last := 0, 0
	for j, t := range ts {
		if t.kind == tkPunct {
			switch t.text {
			case "(", "[", "{":
				d++
				continue
			case ")", "]", "}":
				d--
				continue
			}
		}
		if d != 0 {
			continue
		}
		hit := false
		for _, op := range ops {
			if t.text == op && (t.kind == tkPunct || t.kind == tkIdent && (op == "instanceof" || op == "in")) {
				hit = true
			}
		}
		if hit && binaryOnly && (j == 0 || !endsOperand(ts[j-1])) {
			hit = false
		}
		if hit {
			parts = append(parts, ts[last:j])
			last = j + 1
		}
	}
	return append(parts, ts[last:])
}

// collect walks every token stream (including template expressions) of a
// file and records blocks, bindings with their lexical scope, function
// definitions, and assignments to be resolved once every binding is known.
func (f *jsFile) collect(ts []jsTok) {
	for _, t := range ts {
		if t.kind == tkTmpl {
			for _, e := range t.exprs {
				f.collect(e)
			}
		}
	}
	// "/* html-param: reason */ name" in a parameter list declares a
	// parameter that carries markup: inside the function it counts as safe,
	// and every call has to pass a safe value in that position instead.
	for k := 0; k+1 < len(ts); k++ {
		if ts[k].kind == tkComment && strings.Contains(ts[k].text, htmlParamMarker) && ts[k+1].kind == tkIdent {
			f.htmlParamAt[ts[k+1].pos] = true
		}
	}
	ts = noComments(ts)
	// htmlParamIdx lists which parameters in ts[a:b] (a parameter list
	// without its parentheses) were declared as markup.
	htmlParamIdx := func(a, b int) []int {
		var idx []int
		for n, part := range splitTop(ts[a:b], false, ",") {
			if len(part) > 0 && part[0].kind == tkIdent && f.htmlParamAt[part[0].pos] {
				idx = append(idx, n)
			}
		}
		return idx
	}
	for i, t := range ts {
		if isP(t, "{") {
			f.blocks = append(f.blocks, [2]int{t.pos, ts[match(ts, i)].pos})
		}
	}
	// endPos is the byte offset at which an expression ending before token
	// index e ends.
	endPos := func(e int) int {
		if e < len(ts) {
			return ts[e].pos
		}
		if len(ts) == 0 {
			return 0
		}
		return ts[len(ts)-1].pos + len(ts[len(ts)-1].text) + 1
	}
	bindRange := func(a, b int, start, end int, kind int) {
		for k := a; k <= b && k < len(ts); k++ {
			// Default values in a parameter list are expressions, but binding
			// every identifier in the list only ever makes more names unsafe.
			if ts[k].kind == tkIdent && !(k > 0 && isP(ts[k-1], ".", "?.")) {
				if kind == bindParam && f.htmlParamAt[ts[k].pos] {
					f.addBind(ts[k].text, start, end, bindHTMLParam, nil)
					continue
				}
				f.addBind(ts[k].text, start, end, kind, nil)
			}
		}
	}
	// funcScope returns the scope of a function whose body starts at token b.
	funcScope := func(b int) (int, int) {
		if b < len(ts) && isP(ts[b], "{") {
			return ts[b].pos, ts[match(ts, b)].pos
		}
		return endPos(b - 1), endPos(extent(ts, b, true))
	}
	declared := map[int]bool{}
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		prevDot := i > 0 && isP(ts[i-1], ".", "?.")
		switch {
		case isP(t, "=>"):
			start, end := funcScope(i + 1)
			if i > 0 && ts[i-1].kind == tkIdent {
				f.addBind(ts[i-1].text, ts[i-1].pos, end, bindParam, nil)
			} else if i > 0 && isP(ts[i-1], ")") {
				open := matchBack(ts, i-1)
				start = ts[open].pos
				// The second parameter of an array callback is the element's
				// index, always a number.
				if open >= 3 && isP(ts[open-1], "(") && isP(ts[open-3], ".") && isKw(ts[open-2], indexCallbacks...) {
					ps := splitTop(ts[open+1:i-1], false, ",")
					if len(ps) == 2 && len(ps[1]) == 1 && ps[1][0].kind == tkIdent {
						bindRange(open, open+len(ps[0]), start, end, bindParam)
						f.addBind(ps[1][0].text, start, end, bindIndex, nil)
						break
					}
				}
				bindRange(open, i-1, start, end, bindParam)
			}
		case isKw(t, "function"):
			j := i + 1
			name := ""
			if j < len(ts) && isP(ts[j], "*") {
				j++
			}
			if j < len(ts) && ts[j].kind == tkIdent {
				name = ts[j].text
				j++
			}
			if j < len(ts) && isP(ts[j], "(") {
				e := match(ts, j)
				if e+1 < len(ts) && isP(ts[e+1], "{") {
					be := match(ts, e+1)
					bindRange(j, e, ts[j].pos, ts[be].pos, bindParam)
					if name != "" {
						f.funcs[name] = append(f.funcs[name], jsFunc{body: ts[e+2 : be], block: true})
						f.htmlParams[name] = append(f.htmlParams[name], htmlParamIdx(j+1, e)...)
						s, en := f.scopeOf(t.pos)
						f.addBind(name, s, en, bindFunc, nil)
					}
				}
			}
		case isKw(t, "catch") && i+1 < len(ts) && isP(ts[i+1], "("):
			e := match(ts, i+1)
			if e+1 < len(ts) && isP(ts[e+1], "{") {
				bindRange(i+1, e, ts[i+1].pos, ts[match(ts, e+1)].pos, bindParam)
			}
		case isKw(t, "const", "let", "var") && !prevDot:
			start, end := f.scopeOf(t.pos)
			j := i + 1
			for j < len(ts) {
				if isP(ts[j], "{", "[") {
					e := match(ts, j)
					bindRange(j, e, start, end, bindParam) // destructured: unknown
					j = e + 1
				} else if ts[j].kind == tkIdent {
					name := ts[j].text
					j++
					if j < len(ts) && isKw(ts[j], "of", "in") {
						f.addBind(name, start, end, bindParam, nil) // loop variable
						break
					}
					if j < len(ts) && isP(ts[j], "=") {
						declared[j-1] = true
						e := extent(ts, j+1, true)
						if fn, ok := arrowOrFunc(ts[j+1 : e]); ok {
							f.funcs[name] = append(f.funcs[name], fn)
							k := j + 1
							if k < e && isKw(ts[k], "async") {
								k++
							}
							if k < e && isKw(ts[k], "function") {
								for k < e && !isP(ts[k], "(") {
									k++
								}
							}
							if k < e && isP(ts[k], "(") {
								f.htmlParams[name] = append(f.htmlParams[name], htmlParamIdx(k+1, match(ts, k))...)
							}
							f.addBind(name, start, end, bindFunc, nil)
						} else {
							f.addBind(name, start, end, bindDecl, ts[j+1:e])
						}
						j = e
					} else {
						f.addBind(name, start, end, bindDecl, nil) // undefined until assigned
					}
				} else {
					break
				}
				if j < len(ts) && isP(ts[j], "=") { // destructuring default value
					j = extent(ts, j+1, true)
				}
				if j < len(ts) && isP(ts[j], ",") {
					j++
					continue
				}
				break
			}
		case t.kind == tkIdent && !prevDot && !declared[i] && i+1 < len(ts) && isP(ts[i+1], "=", "+=", "||=", "??=", "&&="):
			e := extent(ts, i+2, true)
			if fn, ok := arrowOrFunc(ts[i+2 : e]); ok {
				f.funcs[t.text] = append(f.funcs[t.text], fn)
			}
			f.pend = append(f.pend, jsAssign{t.text, t.pos, ts[i+2 : e]})
		case t.kind == tkIdent && !prevDot && i+1 < len(ts) && isP(ts[i+1], "(") && i > 0 && isP(ts[i-1], "{", ",") &&
			!regexAfterKeyword[t.text] && !isKw(t, "if", "for", "while", "switch", "function", "catch"):
			// Method shorthand in an object literal: name(params) { body }.
			e := match(ts, i+1)
			if e+1 < len(ts) && isP(ts[e+1], "{") {
				bindRange(i+1, e, ts[i+1].pos, ts[match(ts, e+1)].pos, bindParam)
			}
		case isP(t, "]", "}") && i+1 < len(ts) && isP(ts[i+1], "="):
			// Destructuring assignment: whatever it assigns is unknown.
			for k := matchBack(ts, i); k < i; k++ {
				if ts[k].kind == tkIdent && !isP(ts[k+1], ":") {
					f.pend = append(f.pend, jsAssign{ts[k].text, ts[k].pos, []jsTok{{kind: tkIdent, text: "\x00unknown"}}})
				}
			}
		case t.kind == tkIdent && i+3 < len(ts) && isP(ts[i+1], ".") && isKw(ts[i+2], "push", "unshift") && isP(ts[i+3], "("):
			e := match(ts, i+3)
			for _, a := range splitTop(ts[i+4:e], false, ",") {
				f.pend = append(f.pend, jsAssign{t.text, t.pos, a})
			}
		}
	}
}

const (
	bindDecl = iota
	bindParam
	bindIndex
	bindFunc
	bindImplicit
	bindHTMLParam
)

const htmlParamMarker = "html-param:"

type jsBind struct {
	start, end int
	kind       int
	exprs      [][]jsTok
	memo       int
}

type jsAssign struct {
	name string
	pos  int
	expr []jsTok
}

func (f *jsFile) addBind(name string, start, end, kind int, expr []jsTok) {
	b := &jsBind{start: start, end: end, kind: kind}
	if expr != nil {
		b.exprs = append(b.exprs, expr)
	}
	f.binds[name] = append(f.binds[name], b)
}

// scopeOf returns the innermost block containing pos, or the whole file.
func (f *jsFile) scopeOf(pos int) (int, int) {
	s, e := 0, len(f.src)
	for _, b := range f.blocks {
		if b[0] < pos && pos <= b[1] && b[1]-b[0] < e-s {
			s, e = b[0], b[1]
		}
	}
	return s, e
}

// lookup resolves name at pos to its innermost binding.
func (f *jsFile) lookup(name string, pos int) *jsBind {
	var best *jsBind
	for _, b := range f.binds[name] {
		if b.start <= pos && pos <= b.end && (best == nil || b.end-b.start < best.end-best.start) {
			best = b
		}
	}
	return best
}

// resolve attaches assignments and pushes to the bindings they write.
func (f *jsFile) resolve() {
	for _, a := range f.pend {
		b := f.lookup(a.name, a.pos)
		if b == nil {
			f.addBind(a.name, 0, len(f.src), bindImplicit, nil)
			b = f.lookup(a.name, a.pos)
		}
		b.exprs = append(b.exprs, a.expr)
	}
	f.pend = nil
}

var indexCallbacks = []string{"map", "forEach", "filter", "flatMap", "some", "every", "find", "findIndex", "from"}

// arrowOrFunc reports whether ts is a function expression, and returns it.
func arrowOrFunc(ts []jsTok) (jsFunc, bool) {
	ts = noComments(ts)
	if len(ts) > 0 && isKw(ts[0], "async") {
		ts = ts[1:]
	}
	if len(ts) == 0 {
		return jsFunc{}, false
	}
	j := -1
	if ts[0].kind == tkIdent && len(ts) > 1 && isP(ts[1], "=>") {
		j = 1
	} else if isP(ts[0], "(") {
		e := match(ts, 0)
		if e+1 < len(ts) && isP(ts[e+1], "=>") {
			j = e + 1
		}
	} else if isKw(ts[0], "function") {
		k := 1
		for k < len(ts) && !isP(ts[k], "(") {
			k++
		}
		if k < len(ts) {
			e := match(ts, k)
			if e+1 < len(ts) && isP(ts[e+1], "{") {
				return jsFunc{body: ts[e+2 : match(ts, e+1)], block: true}, true
			}
		}
		return jsFunc{}, false
	}
	if j < 0 {
		return jsFunc{}, false
	}
	body := ts[j+1:]
	if len(body) > 0 && isP(body[0], "{") {
		return jsFunc{body: body[1:match(body, 0)], block: true}, true
	}
	return jsFunc{body: body}, true
}

// ---------------------------------------------------------------------------
// Safety analysis.

var safeCalls = map[string]bool{
	"escapeHtml": true, "chartEsc": true, "Number": true, "parseInt": true, "parseFloat": true,
	"Boolean": true, "isNaN": true, "isFinite": true, "encodeURIComponent": true,
	// sx (app.js) returns ` data-sx="<integer>"` whatever its argument.
	"sx": true,
}

// Methods whose result is a number or boolean whatever the receiver is.
var scalarMethods = map[string]bool{
	"toFixed": true, "toPrecision": true, "getTime": true, "indexOf": true, "lastIndexOf": true,
	"findIndex": true, "includes": true, "some": true, "every": true, "startsWith": true, "endsWith": true,
	"test": true, "localeCompare": true, "hasOwnProperty": true, "has": true, "getFullYear": true,
	"getMonth": true, "getDate": true, "getDay": true, "getHours": true, "getMinutes": true, "getSeconds": true,
	"getUTCFullYear": true, "getUTCMonth": true, "getUTCDate": true, "getUTCHours": true, "getUTCMinutes": true,
	"getTimezoneOffset": true, "valueOf": true, "contains": true,
}

// Methods that keep a safe receiver safe.
var preservingMethods = map[string]bool{
	"slice": true, "substring": true, "substr": true, "trim": true, "trimStart": true, "trimEnd": true,
	"toUpperCase": true, "toLowerCase": true, "toLocaleUpperCase": true, "toLocaleLowerCase": true,
	"charAt": true, "at": true, "toString": true, "toLocaleString": true, "filter": true, "sort": true,
	"reverse": true, "padStart": true, "padEnd": true, "repeat": true, "concat": true, "flat": true,
}

const allowMarker = "safe-html:"

func isAllowComment(t jsTok) bool {
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(t.text, "//"), "/*"), "*/"))
	return t.kind == tkComment && strings.HasPrefix(body, allowMarker) && len(strings.TrimSpace(body[len(allowMarker):])) >= 3
}

// allowComment: the expression starts with an allow comment.
func allowComment(ts []jsTok) bool {
	for _, t := range ts {
		if t.kind != tkComment {
			return t.allow
		}
		if isAllowComment(t) {
			return true
		}
	}
	return false
}

func (c *xssChecker) lookupFile(name string, has func(*jsFile) bool) *jsFile {
	if has(c.cur) {
		return c.cur
	}
	for _, f := range c.shared {
		if has(f) {
			return f
		}
	}
	return nil
}

func (c *xssChecker) funcSafe(name string) bool {
	f := c.lookupFile(name, func(f *jsFile) bool { return len(f.funcs[name]) > 0 })
	if f == nil {
		return false
	}
	key := f.name + "#" + name
	if m := c.funcMemo[key]; m != 0 {
		return m == 1 // recursion (3) counts as unsafe
	}
	c.funcMemo[key] = 3
	prev := c.cur
	c.cur = f
	c.indirect++
	ok := true
	for _, fn := range f.funcs[name] {
		if !c.funcReturnsSafe(fn) {
			ok = false
		}
	}
	c.indirect--
	c.cur = prev
	c.funcMemo[key] = 2
	if ok {
		c.funcMemo[key] = 1
	}
	return ok
}

func (c *xssChecker) funcReturnsSafe(fn jsFunc) bool {
	if !fn.block {
		return c.safe(fn.body)
	}
	ok := true
	ts := fn.body
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		switch {
		case isP(t, "=>") && i+1 < len(ts) && isP(ts[i+1], "{"):
			i = match(ts, i+1)
		case isKw(t, "function"):
			for i < len(ts) && !isP(ts[i], "{") {
				i++
			}
			if i < len(ts) {
				i = match(ts, i)
			}
		case isKw(t, "return"):
			j := i + 1
			for j < len(ts) && ts[j].kind == tkComment && !ts[j].nl {
				j++
			}
			if j < len(ts) && ts[j].nl && !allowComment(ts[i+1:j]) {
				continue // "return" then a line break returns undefined
			}
			e := extent(ts, j, false)
			if !c.safe(ts[i+1 : e]) {
				ok = false
			}
		}
	}
	return ok
}

// binding resolves an identifier at pos: in the current file by scope, then
// as a top-level binding of a shared script. Assignments a page makes to a
// shared global are checked together with the shared declaration.
func (c *xssChecker) binding(name string, pos int) []*jsBind {
	var out []*jsBind
	b := c.cur.lookup(name, pos)
	if b != nil {
		out = append(out, b)
		if b.kind != bindImplicit {
			return out
		}
	}
	for _, f := range c.shared {
		if f == c.cur {
			continue
		}
		for _, x := range f.binds[name] {
			if x.start == 0 && x.end == len(f.src) {
				out = append(out, x)
			}
		}
	}
	return out
}

func (c *xssChecker) varSafe(name string, pos int) bool {
	switch name {
	case "true", "false", "null", "undefined", "NaN", "Infinity":
		return true
	}
	bs := c.binding(name, pos)
	if len(bs) == 0 {
		return false
	}
	for _, b := range bs {
		switch b.kind {
		case bindIndex, bindHTMLParam:
			continue
		case bindParam, bindFunc:
			return false
		}
		if b.memo == 2 || b.memo == 3 {
			return false // unsafe, or defined in terms of itself
		}
		if b.memo == 1 {
			continue
		}
		b.memo = 3
		c.indirect++
		ok := true
		for _, e := range b.exprs {
			if !c.safe(e) {
				ok = false
				break
			}
		}
		c.indirect--
		b.memo = 2
		if !ok {
			return false
		}
		b.memo = 1
	}
	return true
}

// fnArgSafe: a callback passed to map() returns safe values.
func (c *xssChecker) fnArgSafe(ts []jsTok) bool {
	if allowComment(ts) {
		return true
	}
	ts = noComments(ts)
	if len(ts) == 1 && ts[0].kind == tkIdent {
		return safeCalls[ts[0].text] || c.funcSafe(ts[0].text)
	}
	fn, ok := arrowOrFunc(ts)
	return ok && c.funcReturnsSafe(fn)
}

type jsSeg struct {
	kind string // "prop", "index", "call"
	name string
	args []jsTok
}

func (c *xssChecker) safe(ts []jsTok) bool {
	if allowComment(ts) {
		return true
	}
	ts = noComments(ts)
	for len(ts) >= 2 && isP(ts[0], "(") && match(ts, 0) == len(ts)-1 {
		ts = ts[1 : len(ts)-1]
	}
	if len(ts) == 0 {
		return true
	}
	if p := splitTop(ts, false, ","); len(p) > 1 {
		return c.safe(p[len(p)-1])
	}
	if _, ok := arrowOrFunc(ts); ok {
		return false
	}
	// Ternary: the condition is never output.
	d, q := 0, -1
	for j, t := range ts {
		if isP(t, "(", "[", "{") {
			d++
		} else if isP(t, ")", "]", "}") {
			d--
		} else if d == 0 && isP(t, "?") {
			q = j
			break
		}
	}
	if q >= 0 {
		nest := 0
		for j := q + 1; j < len(ts); j++ {
			t := ts[j]
			if isP(t, "(", "[", "{") {
				d++
			} else if isP(t, ")", "]", "}") {
				d--
			} else if d == 0 && isP(t, "?") {
				nest++
			} else if d == 0 && isP(t, ":") {
				if nest == 0 {
					return c.safe(ts[q+1:j]) && c.safe(ts[j+1:])
				}
				nest--
			}
		}
		return false
	}
	if len(splitTop(ts, false, "=", "+=", "-=", "||=", "??=", "&&=")) > 1 {
		return false // assignment as a value: don't guess
	}
	if p := splitTop(ts, false, "||", "??"); len(p) > 1 {
		for _, x := range p {
			if !c.safe(x) {
				return false
			}
		}
		return true
	}
	// a && b outputs b, or a falsy a (false, 0, "", null, undefined, NaN).
	if p := splitTop(ts, false, "&&"); len(p) > 1 {
		return c.safe(p[len(p)-1])
	}
	// Bitwise, comparison and shift operators produce numbers or booleans.
	if len(splitTop(ts, true, "|", "^", "&", "==", "!=", "===", "!==", "<", ">", "<=", ">=", "instanceof", "in", "<<", ">>", ">>>")) > 1 {
		return true
	}
	if p := splitTop(ts, true, "+"); len(p) > 1 {
		for _, x := range p {
			if !c.safe(x) {
				return false
			}
		}
		return true
	}
	if len(splitTop(ts, true, "-", "*", "/", "%", "**")) > 1 {
		return true
	}
	if isP(ts[0], "!", "-", "+", "~") || isKw(ts[0], "typeof", "void", "delete") {
		return true
	}
	if isP(ts[len(ts)-1], "++", "--") {
		return true
	}
	return c.primary(ts)
}

func (c *xssChecker) primary(ts []jsTok) bool {
	// Atom.
	i := 1
	atom := ts[0]
	isNewDate := false
	switch {
	case isKw(atom, "new"):
		if len(ts) > 1 && isKw(ts[1], "Date") {
			isNewDate = true
		}
		i = 2
		if i < len(ts) && isP(ts[i], "(") {
			i = match(ts, i) + 1
		}
	case isP(atom, "(", "[", "{"):
		i = match(ts, 0) + 1
	case atom.kind == tkPunct:
		return false
	}
	var segs []jsSeg
	for i < len(ts) {
		t := ts[i]
		switch {
		case isP(t, ".", "?.") && i+1 < len(ts) && ts[i+1].kind == tkIdent:
			segs = append(segs, jsSeg{kind: "prop", name: ts[i+1].text})
			i += 2
		case isP(t, "?.") && i+1 < len(ts) && isP(ts[i+1], "(", "["):
			i++
		case isP(t, "["):
			e := match(ts, i)
			segs = append(segs, jsSeg{kind: "index", args: ts[i+1 : e]})
			i = e + 1
		case isP(t, "("):
			e := match(ts, i)
			segs = append(segs, jsSeg{kind: "call", args: ts[i+1 : e]})
			i = e + 1
		case t.kind == tkTmpl:
			return false // tagged template
		default:
			return false // something this checker does not model
		}
	}
	if isNewDate {
		return true
	}
	if len(segs) == 0 {
		switch atom.kind {
		case tkStr, tkNum:
			return true
		case tkTmpl:
			if hasMarkup(atom) || c.indirect == 0 {
				// Markup, or text written straight into markup: each
				// interpolation is checked and reported where it is.
				c.checkTemplate(atom)
				return true
			}
			// Text a helper returns (a label, a formatted date): unsafe
			// unless every part is, and then the caller has to escape it.
			for _, e := range atom.exprs {
				if !c.safe(e) {
					return false
				}
			}
			return true
		case tkIdent:
			return c.varSafe(atom.text, atom.pos)
		case tkPunct:
			if atom.text == "{" {
				return true // "[object Object]"
			}
			inner := ts[1 : len(ts)-1]
			if atom.text == "[" {
				for _, e := range splitTop(inner, false, ",") {
					if len(e) > 0 && isP(e[0], "...") {
						e = e[1:] // spread: the elements of a safe array
					}
					if !c.safe(e) {
						return false
					}
				}
				return true
			}
			return c.safe(inner)
		}
		return false
	}
	// receiverSafe: the expression up to (not including) segment n.
	var receiverSafe func(n int) bool
	receiverSafe = func(n int) bool {
		end := len(ts)
		// Find the token index where segment n starts by rescanning.
		k, s := 1, 0
		if isKw(atom, "new") {
			k = 2
			if k < len(ts) && isP(ts[k], "(") {
				k = match(ts, k) + 1
			}
		} else if isP(atom, "(", "[", "{") {
			k = match(ts, 0) + 1
		}
		for k < len(ts) && s < n {
			switch {
			case isP(ts[k], ".", "?.") && k+1 < len(ts) && ts[k+1].kind == tkIdent:
				k += 2
				s++
			case isP(ts[k], "?."):
				k++
			case isP(ts[k], "(", "["):
				k = match(ts, k) + 1
				s++
			}
		}
		end = k
		for end > 0 && isP(ts[end-1], "?.") {
			end--
		}
		return c.safe(ts[:end])
	}
	last := len(segs) - 1
	ls := segs[last]
	if ls.kind == "call" {
		if last == 0 && atom.kind == tkIdent {
			if safeCalls[atom.text] {
				return true
			}
			if atom.text == "String" {
				return c.safe(ls.args)
			}
			return c.funcSafe(atom.text)
		}
		if last == 1 && atom.kind == tkIdent && (atom.text == "Math" || atom.text == "Number" || atom.text == "Date") && segs[0].kind == "prop" {
			return true
		}
		if last >= 1 && segs[last-1].kind == "prop" {
			m := segs[last-1].name
			switch {
			case scalarMethods[m]:
				return true
			case m == "join":
				if !c.safe(ls.args) {
					return false
				}
				// xs.map(f)[.filter/.slice/...].join(sep)
				for k := last - 2; k >= 1; k -= 2 {
					if segs[k].kind != "call" || segs[k-1].kind != "prop" {
						break
					}
					switch segs[k-1].name {
					case "map", "flatMap":
						return c.fnArgSafe(segs[k].args)
					case "filter", "slice", "sort", "reverse":
						continue
					}
					break
				}
				return receiverSafe(last - 1)
			case m == "map" || m == "flatMap":
				return c.fnArgSafe(ls.args)
			case preservingMethods[m]:
				if m == "padStart" || m == "padEnd" || m == "concat" {
					if !c.safe(ls.args) {
						return false
					}
				}
				return receiverSafe(last - 1)
			}
		}
		return false
	}
	if ls.kind == "prop" && ls.name == "length" {
		return receiverSafe(last)
	}
	return false
}

var safeURLLead = regexp.MustCompile(`^(/[^/\\]|/$|#|\?|\./|https?://|mailto:|$)`)

// urlSafe: a value at the start of a URL attribute either goes through
// safeUrl() or is built from a literal that fixes the scheme.
func (c *xssChecker) urlSafe(ts []jsTok) bool {
	if allowComment(ts) {
		return true
	}
	ts = noComments(ts)
	for _, t := range ts {
		if isKw(t, "safeUrl") {
			return true
		}
	}
	for len(ts) >= 2 && isP(ts[0], "(") && match(ts, 0) == len(ts)-1 {
		ts = ts[1 : len(ts)-1]
	}
	if len(ts) == 0 {
		return true
	}
	if len(ts) == 1 {
		switch ts[0].kind {
		case tkStr:
			return safeURLLead.MatchString(ts[0].text)
		case tkTmpl:
			if len(ts[0].exprs) == 0 || ts[0].quasi[0] != "" {
				return safeURLLead.MatchString(ts[0].quasi[0])
			}
			return c.urlSafe(ts[0].exprs[0])
		}
	}
	if len(ts) == 4 && isKw(ts[0], "encodeURIComponent") {
		return true
	}
	d, q := 0, -1
	for j, t := range ts {
		if isP(t, "(", "[", "{") {
			d++
		} else if isP(t, ")", "]", "}") {
			d--
		} else if d == 0 && isP(t, "?") {
			q = j
			break
		}
	}
	if q >= 0 {
		nest := 0
		for j := q + 1; j < len(ts); j++ {
			if isP(ts[j], "(", "[", "{") {
				d++
			} else if isP(ts[j], ")", "]", "}") {
				d--
			} else if d == 0 && isP(ts[j], "?") {
				nest++
			} else if d == 0 && isP(ts[j], ":") {
				if nest == 0 {
					return c.urlSafe(ts[q+1:j]) && c.urlSafe(ts[j+1:])
				}
				nest--
			}
		}
		return false
	}
	if p := splitTop(ts, true, "+"); len(p) > 1 {
		return c.urlSafe(p[0])
	}
	if len(ts) == 1 && ts[0].kind == tkIdent {
		// A variable whose every assignment fixes the scheme.
		bs := c.binding(ts[0].text, ts[0].pos)
		if len(bs) == 0 {
			return false
		}
		for _, b := range bs {
			if b.kind != bindDecl && b.kind != bindImplicit {
				return false
			}
			for _, e := range b.exprs {
				if !c.urlSafe(e) {
					return false
				}
			}
		}
		return true
	}
	return false
}

func (c *xssChecker) report(pos int, expr []jsTok, why string) {
	line := strings.Count(c.cur.src[:min(pos, len(c.cur.src))], "\n") + 1
	var b strings.Builder
	for _, t := range noComments(expr) {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		if t.kind == tkTmpl {
			b.WriteString("`…`")
		} else if t.kind == tkStr {
			b.WriteString(`"` + t.text + `"`)
		} else {
			b.WriteString(t.text)
		}
	}
	s := b.String()
	if len(s) > 110 {
		s = s[:110] + "…"
	}
	c.violations[fmt.Sprintf("%s:%d:%d", c.cur.name, line, pos)] = why + ": " + s
}

var urlAttrs = map[string]bool{"href": true, "src": true, "action": true, "formaction": true, "xlink:href": true,
	"poster": true, "srcset": true, "background": true, "data": true, "ping": true}

// tagCtx describes where the end of some markup sits: inside a tag, and if
// so in which attribute and whether its value is quoted.
type tagCtx struct {
	inTag    bool
	attr     string
	quoted   bool
	unquoted bool // at or inside an unquoted attribute value
	atStart  bool // nothing of the quoted value precedes this point
}

func tagContext(raw string) tagCtx {
	lt := -1
	for k := len(raw) - 1; k >= 0; k-- {
		if raw[k] == '<' && k+1 < len(raw) && (raw[k+1] >= 'a' && raw[k+1] <= 'z' || raw[k+1] >= 'A' && raw[k+1] <= 'Z' || raw[k+1] == '/') {
			lt = k
			break
		}
	}
	if lt < 0 {
		return tagCtx{}
	}
	i := lt + 1
	for i < len(raw) && raw[i] != ' ' && raw[i] != '\n' && raw[i] != '\t' && raw[i] != '>' {
		i++
	}
	state, name, attr, valStart := 0, "", "", 0
	var q byte
	for ; i < len(raw); i++ {
		ch := raw[i]
		space := ch == ' ' || ch == '\n' || ch == '\t' || ch == '\r'
		switch state {
		case 0:
			switch {
			case ch == '>':
				return tagCtx{}
			case space || ch == '/':
				name = ""
			case ch == '=':
				state = 1
			default:
				name += string(ch)
			}
		case 1:
			switch {
			case space:
			case ch == '"' || ch == '\'':
				q, state, attr, valStart = ch, 2, strings.ToLower(name), i+1
			case ch == '>':
				return tagCtx{}
			default:
				state, attr = 3, strings.ToLower(name)
			}
		case 2:
			if ch == q {
				state, name = 0, ""
			}
		case 3:
			if space {
				state, name = 0, ""
			} else if ch == '>' {
				return tagCtx{}
			}
		}
	}
	switch state {
	case 1:
		return tagCtx{inTag: true, attr: strings.ToLower(name), unquoted: true}
	case 2:
		return tagCtx{inTag: true, attr: attr, quoted: true, atStart: valStart == len(raw)}
	case 3:
		return tagCtx{inTag: true, attr: attr, unquoted: true}
	}
	return tagCtx{inTag: true, attr: strings.ToLower(name)}
}

func (c *xssChecker) checkTemplate(t jsTok) {
	if c.seenTmpl[t.pos] {
		return
	}
	c.seenTmpl[t.pos] = true
	var sofar strings.Builder
	for k, e := range t.exprs {
		sofar.WriteString(t.quasi[k])
		tc := tagContext(sofar.String())
		switch {
		case tc.inTag && (tc.quoted || tc.unquoted) && strings.HasPrefix(tc.attr, "on"):
			c.report(t.epos[k], e, "inline event handler attribute")
		case tc.unquoted && !allowComment(e):
			c.report(t.epos[k], e, "unquoted attribute value")
		case tc.quoted && tc.atStart && urlAttrs[tc.attr]:
			if !c.urlSafe(e) || !c.safe(e) {
				c.report(t.epos[k], e, "URL attribute needs escapeHtml(safeUrl(…))")
			}
		default:
			if !c.safe(e) {
				c.report(t.epos[k], e, "unescaped interpolation")
				c.found = append(c.found, xssFound{c.cur.name, t.epos[k], t.eend[k], e})
			}
		}
		sofar.WriteString("\x00")
	}
}

func hasMarkup(t jsTok) bool {
	for _, q := range t.quasi {
		if strings.Contains(q, "<") {
			return true
		}
	}
	return false
}

// scan checks every template literal with markup and every HTML sink.
func (c *xssChecker) scan(ts []jsTok) {
	for _, t := range ts {
		if t.kind == tkTmpl {
			if hasMarkup(t) {
				c.checkTemplate(t)
			}
			for _, e := range t.exprs {
				c.scan(e)
			}
		}
	}
	nc := noComments(ts)
	for i := 0; i+2 < len(ts); i++ {
		// Use the comment-bearing stream for sink RHS so allow comments work.
		if isP(ts[i], ".") && isKw(ts[i+1], "innerHTML", "outerHTML") && isP(ts[i+2], "=", "+=") {
			e := extent(ts, i+3, false)
			if !c.safe(ts[i+3 : e]) {
				c.report(ts[i+1].pos, ts[i+3:e], "unescaped "+ts[i+1].text+" assignment")
			}
		}
		if isP(ts[i], ".") && isKw(ts[i+1], "insertAdjacentHTML") && isP(ts[i+2], "(") {
			e := match(ts, i+2)
			args := splitTop(ts[i+3:e], false, ",")
			if len(args) < 2 || !c.safe(args[1]) {
				c.report(ts[i+1].pos, ts[i+3:e], "unescaped insertAdjacentHTML")
			}
		}
	}
	// Calls to a function with markup parameters must pass safe markup.
	for i := 0; i+1 < len(nc); i++ {
		t := nc[i]
		if t.kind != tkIdent || !isP(nc[i+1], "(") || i > 0 && (isP(nc[i-1], ".", "?.") || isKw(nc[i-1], "function")) {
			continue
		}
		var idx []int
		if f := c.lookupFile(t.text, func(f *jsFile) bool { return len(f.funcs[t.text]) > 0 }); f != nil {
			idx = f.htmlParams[t.text]
		}
		if len(idx) == 0 {
			continue
		}
		e := match(nc, i+1)
		// Use the comment-bearing arguments so an allow comment applies.
		var args [][]jsTok
		for k := range ts {
			if ts[k].pos == nc[i+1].pos {
				ke := k
				for ke < len(ts) && ts[ke].pos != nc[e].pos {
					ke++
				}
				args = splitTop(ts[k+1:ke], false, ",")
				break
			}
		}
		for _, n := range idx {
			if n < len(args) && !c.safe(args[n]) {
				c.report(t.pos, args[n], "unescaped markup argument to "+t.text)
			}
		}
	}
}

var scriptRe = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)

func loadJSFile(name, src string, html bool) (*jsFile, error) {
	f := &jsFile{name: name, src: src, funcs: map[string][]jsFunc{}, binds: map[string][]*jsBind{},
		htmlParamAt: map[int]bool{}, htmlParams: map[string][]int{}}
	var blocks [][2]int
	if html {
		for _, m := range scriptRe.FindAllStringSubmatchIndex(src, -1) {
			if strings.Contains(strings.ToLower(src[m[2]:m[3]]), "src=") {
				continue
			}
			blocks = append(blocks, [2]int{m[4], m[5]})
		}
	} else {
		blocks = [][2]int{{0, len(src)}}
	}
	for _, b := range blocks {
		l := &jsLexer{src: src[b[0]:b[1]], base: b[0]}
		ts := l.lex(false)
		if l.err != nil {
			return nil, fmt.Errorf("%s: %v", name, l.err)
		}
		f.streams = append(f.streams, ts)
		f.collect(ts)
	}
	f.resolve()
	return f, nil
}

func newXSSChecker(files map[string]string) (*xssChecker, error) {
	c := &xssChecker{files: map[string]*jsFile{}, violations: map[string]string{}, seenTmpl: map[int]bool{},
		funcMemo: map[string]int{}, varMemo: map[string]int{}}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := loadJSFile(n, files[n], strings.HasSuffix(n, ".html"))
		if err != nil {
			return nil, err
		}
		c.files[n] = f
		if strings.HasSuffix(n, ".js") {
			c.shared = append(c.shared, f)
		}
	}
	return c, nil
}

func (c *xssChecker) run() []string {
	names := make([]string, 0, len(c.files))
	for n := range c.files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c.cur = c.files[n]
		c.seenTmpl = map[int]bool{}
		for _, ts := range c.cur.streams {
			c.scan(ts)
		}
	}
	var out []string
	for k, v := range c.violations {
		out = append(out, k+": "+v)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.SplitN(out[i], ":", 3), strings.SplitN(out[j], ":", 3)
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		var x, y int
		fmt.Sscan(a[1], &x)
		fmt.Sscan(b[1], &y)
		return x < y
	})
	return out
}

func consoleSources(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := fs.WalkDir(staticFS, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(path, "static/vendor/") {
			return err
		}
		if strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".js") {
			b, err := staticFS.ReadFile(path)
			if err != nil {
				return err
			}
			files[strings.TrimPrefix(path, "static/")] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestConsoleTemplatesEscapeInterpolations(t *testing.T) {
	c, err := newXSSChecker(consoleSources(t))
	if err != nil {
		t.Fatal(err)
	}
	v := c.run()
	for _, s := range v {
		t.Error(s)
	}
	if len(v) > 0 {
		t.Logf("%d unproven interpolations. Wrap the value in escapeHtml(...), or for a proven-safe value add /* %s <reason> */ as the first thing in the expression.", len(v), allowMarker)
	}
}

// The checker itself: known-bad shapes must be caught, known-good accepted.
func TestXSSCheckerCatchesKnownShapes(t *testing.T) {
	bad := map[string]string{
		"pid":        "function f(p){ el.innerHTML = `<span data-toggle=\"${p.pid}\">`; }",
		"helper":     "const st = c => `${c.settings.log_level || \"?\"}s`;\nfunction g(c){ el.innerHTML = `<td>${st(c)}</td>`; }",
		"number":     "function f(a){ return `<td>${a.device_count}</td>`; }",
		"or":         "function f(a){ return `<td>${a.name || \"—\"}</td>`; }",
		"join":       "function f(rows){ el.innerHTML = rows.join(\"\"); }",
		"param":      "const name = \"ok\";\nfunction f(xs){ return xs.map(name => `<li>${name}</li>`).join(\"\"); }",
		"href":       "function f(n){ return `<a href=\"${escapeHtml(n.link)}\">x</a>`; }",
		"sink":       "function f(r){ el.innerHTML = r.html; }",
		"unquoted":   "function f(r){ return `<td class=${escapeHtml(r.c)}>`; }",
		"badallow":   "function f(r){ return `<td>${/* safe-html: */ r.c}</td>`; }",
		"concat":     "function f(r){ el.innerHTML = \"<b>\" + r.name + \"</b>\"; }",
		"nestedtmpl": "function f(r){ return `<td>${r.ok ? `<b>${r.name}</b>` : \"\"}</td>`; }",
		"localeStr":  "function f(r){ return `<td>${r.n.toLocaleString()}</td>`; }",
		"pushed":     "function f(r){ const out = []; out.push(r.name); el.innerHTML = out.join(\"\"); }",
		"htmlarg":    "function wrap(/* html-param: callers pass markup */ inner){ return `<div>${inner}</div>`; }\nfunction f(a){ el.innerHTML = wrap(a.x); }",
		"shadow":     "const x = \"ok\";\nfunction f(x){ return `<b>${x}</b>`; }",
		"textfn":     "function fmt(v){ return `${v} items`; }\nfunction f(a){ return `<b>${fmt(a.n)}</b>`; }",
		"onattr":     "function f(r){ return `<b onclick=\"go('${escapeHtml(r.x)}')\">`; }",
		"jsurl":      "function f(r){ return `<a href=\"${r.ok ? escapeHtml(r.u) : \"#\"}\">`; }",
	}
	for name, src := range bad {
		c, err := newXSSChecker(map[string]string{"t.js": src})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v := c.run(); len(v) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
	good := map[string]string{
		"escaped":  "function f(p){ el.innerHTML = `<span data-toggle=\"${escapeHtml(p.pid)}\">`; }",
		"ternary":  "function f(a){ return `<td class=\"${a.ok ? \"ok\" : \"bad\"}\">${escapeHtml(a.n)}</td>`; }",
		"map":      "function f(xs){ el.innerHTML = xs.map(x => `<li>${escapeHtml(x)}</li>`).join(\"\"); }",
		"arith":    "function f(xs){ return `<td>${xs.length - 12} more ${Number(xs.n).toLocaleString()}</td>`; }",
		"local":    "function f(a){ const cls = a.ok ? \"ok\" : \"bad\"; return `<td class=\"${cls}\">`; }",
		"helper":   "function pill(s){ return `<b>${escapeHtml(s)}</b>`; }\nfunction f(a){ el.innerHTML = `<td>${pill(a.s)}</td>`; }",
		"allow":    "function f(r){ return `<td>${/* safe-html: built from escaped rows */ r.c}</td>`; }",
		"url":      "function f(n){ return `<a href=\"${escapeHtml(safeUrl(n.link))}\">x</a><a href=\"/endpoint/${encodeURIComponent(n.id)}\">y</a>`; }",
		"pushed":   "function f(r){ const out = []; out.push(`<b>${escapeHtml(r.name)}</b>`); el.innerHTML = out.join(\"\"); }",
		"cmp":      "function f(r){ return `<option ${r.a === r.b ? \"selected\" : \"\"}>`; }",
		"date":     "function f(r){ return `<td>${new Date(r.t).toLocaleString()}</td>`; }",
		"index":    "function f(xs){ return xs.map((x, i) => `<b data-i=\"${i}\">${escapeHtml(x)}</b>`).join(\"\"); }",
		"query":    "function f(a){ return `<a href=\"/endpoint?id=${encodeURIComponent(a.id)}\">x</a>`; }",
		"htmlarg":  "function wrap(/* html-param: callers pass markup */ inner){ return `<div>${inner}</div>`; }\nfunction f(a){ el.innerHTML = wrap(`<b>${escapeHtml(a.x)}</b>`); }",
		"scoped":   "function a(rows){ return rows.length; }\nfunction b(jobs){ const rows = jobs.map(j => `<li>${escapeHtml(j)}</li>`).join(\"\"); el.innerHTML = `<ul>${rows}</ul>`; }",
		"textfn":   "function fmt(v){ return `${escapeHtml(v)} items`; }\nfunction f(a){ return `<b>${fmt(a.n)}</b>`; }",
		"andCheck": "function f(r){ return `<td>${r.x && `<b>${escapeHtml(r.x)}</b>`}</td>`; }",
	}
	for name, src := range good {
		c, err := newXSSChecker(map[string]string{"t.js": src})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v := c.run(); len(v) != 0 {
			t.Errorf("%s: false positive: %v", name, v)
		}
	}
}
