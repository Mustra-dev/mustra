// Package signals is a small rule language over recorder events, in the
// shape signals take:
//
//	process.command_line contains '-enc' AND process.name equals 'powershell.exe'
//	(network.remote_port == 4444 OR network.remote_port == 1337) AND NOT network.process starts with 'ssh'
//	registry.key contains '\CurrentVersion\Run' AND registry.op != 'delete'
//	dns.query ends with '.onion' OR dns.query matches '^[a-z0-9]{20,}\.'
//	logon.outcome equals 'failure' AND logon.type in ['10', '3']
//
// A rule is compiled once and evaluated against a flat map of
// object.property -> value for every event of the objects it names. String
// comparisons are case-insensitive; numeric operators parse both sides as
// numbers and fail closed when either is not one. NOT binds tightest, then
// AND, then OR; parentheses override.
package signals

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Objects are the event kinds a rule may address, with the properties
// each exposes. The editor shows this; the compiler checks against it so a
// typo like process.cmdline is refused at save time rather than matching
// nothing forever.
var Objects = map[string][]string{
	"process":  {"name", "command_line", "user", "pid", "ppid"},
	"file":     {"path", "op"},
	"registry": {"key", "value", "data", "op", "process", "user"},
	"network":  {"protocol", "direction", "local_ip", "local_port", "remote_ip", "remote_port", "process", "user"},
	"dns":      {"query", "answers", "process"},
	"logon":    {"user", "domain", "source", "type", "outcome", "reason"},
}

// Rule is a compiled expression.
type Rule struct {
	root    node
	objects []string
	Source  string
}

// Objects lists the event kinds the rule reads, so the server evaluates it
// only against those.
func (r *Rule) Objects() []string { return r.objects }

// Eval reports whether the event satisfies the rule. Missing properties
// read as empty strings, which makes "contains" false and "!=" true; that
// is the conservative reading for a detection rule.
func (r *Rule) Eval(event map[string]string) bool {
	return r.root.eval(event)
}

type node interface{ eval(map[string]string) bool }

type andNode struct{ l, r node }
type orNode struct{ l, r node }
type notNode struct{ n node }

func (n andNode) eval(e map[string]string) bool { return n.l.eval(e) && n.r.eval(e) }
func (n orNode) eval(e map[string]string) bool  { return n.l.eval(e) || n.r.eval(e) }
func (n notNode) eval(e map[string]string) bool { return !n.n.eval(e) }

type cmpNode struct {
	field string
	op    string
	value string
	list  []string
	re    *regexp.Regexp
	num   float64
}

func (n cmpNode) eval(e map[string]string) bool {
	got := e[n.field]
	lg := strings.ToLower(got)
	lv := strings.ToLower(n.value)
	switch n.op {
	case "equals":
		return lg == lv
	case "not_equals":
		return lg != lv
	case "contains":
		return strings.Contains(lg, lv)
	case "not_contains":
		return !strings.Contains(lg, lv)
	case "starts_with":
		return strings.HasPrefix(lg, lv)
	case "ends_with":
		return strings.HasSuffix(lg, lv)
	case "matches":
		return n.re.MatchString(got)
	case "in":
		for _, x := range n.list {
			if strings.EqualFold(x, got) {
				return true
			}
		}
		return false
	case "not_in":
		for _, x := range n.list {
			if strings.EqualFold(x, got) {
				return false
			}
		}
		return true
	case ">", "<", ">=", "<=":
		f, err := strconv.ParseFloat(strings.TrimSpace(got), 64)
		if err != nil {
			return false
		}
		switch n.op {
		case ">":
			return f > n.num
		case "<":
			return f < n.num
		case ">=":
			return f >= n.num
		default:
			return f <= n.num
		}
	}
	return false
}

// --- lexer ----------------------------------------------------------------

type token struct {
	kind string // ident | str | num | op | lparen | rparen | lbracket | rbracket | comma | eof
	text string
}

func lex(src string) ([]token, error) {
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, token{"lparen", "("})
			i++
		case c == ')':
			out = append(out, token{"rparen", ")"})
			i++
		case c == '[':
			out = append(out, token{"lbracket", "["})
			i++
		case c == ']':
			out = append(out, token{"rbracket", "]"})
			i++
		case c == ',':
			out = append(out, token{"comma", ","})
			i++
		case c == '\'' || c == '"':
			q := c
			j := i + 1
			var b strings.Builder
			for j < len(src) && src[j] != q {
				// Backslash escapes only the quote and itself, so Windows
				// paths ('\CurrentVersion\Run') can be written as they are.
				if src[j] == '\\' && j+1 < len(src) && (src[j+1] == q || src[j+1] == '\\') {
					j++
				}
				b.WriteByte(src[j])
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("unterminated string starting at position %d", i+1)
			}
			out = append(out, token{"str", b.String()})
			i = j + 1
		case strings.HasPrefix(src[i:], "=="), strings.HasPrefix(src[i:], "!="), strings.HasPrefix(src[i:], ">="), strings.HasPrefix(src[i:], "<="):
			out = append(out, token{"op", src[i : i+2]})
			i += 2
		case c == '=' || c == '>' || c == '<':
			out = append(out, token{"op", string(c)})
			i++
		case c >= '0' && c <= '9' || (c == '-' && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9'):
			j := i + 1
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.') {
				j++
			}
			out = append(out, token{"num", src[i:j]})
			i = j
		case unicode.IsLetter(rune(c)) || c == '_':
			j := i
			for j < len(src) && (unicode.IsLetter(rune(src[j])) || unicode.IsDigit(rune(src[j])) || src[j] == '_' || src[j] == '.') {
				j++
			}
			out = append(out, token{"ident", src[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q at position %d", c, i+1)
		}
	}
	return append(out, token{"eof", ""}), nil
}

// --- parser ---------------------------------------------------------------

type parser struct {
	toks    []token
	pos     int
	objects map[string]bool
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *parser) isWord(w string) bool {
	t := p.peek()
	return t.kind == "ident" && strings.EqualFold(t.text, w)
}

// Compile parses an expression. Errors name the position and what was
// expected, because a rule editor with "syntax error" and nothing else is
// a rule editor nobody uses.
func Compile(src string) (*Rule, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, fmt.Errorf("the expression is empty")
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, objects: map[string]bool{}}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != "eof" {
		return nil, fmt.Errorf("unexpected %q after the end of the expression", p.peek().text)
	}
	objs := make([]string, 0, len(p.objects))
	for o := range p.objects {
		objs = append(objs, o)
	}
	sort.Strings(objs)
	return &Rule{root: root, objects: objs, Source: src}, nil
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isWord("or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.isWord("and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
	return left, nil
}

func (p *parser) parseNot() (node, error) {
	if p.isWord("not") {
		p.next()
		n, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notNode{n}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	t := p.peek()
	if t.kind == "lparen" {
		p.next()
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != "rparen" {
			return nil, fmt.Errorf("expected ) but found %q", p.peek().text)
		}
		p.next()
		return n, nil
	}
	if t.kind != "ident" {
		return nil, fmt.Errorf("expected a field such as process.command_line but found %q", t.text)
	}
	p.next()
	field := strings.ToLower(t.text)
	obj, prop, ok := strings.Cut(field, ".")
	if !ok {
		return nil, fmt.Errorf("%q is not a field: write object.property, for example process.name", t.text)
	}
	props, known := Objects[obj]
	if !known {
		return nil, fmt.Errorf("unknown object %q (process, file, registry, network, dns, logon)", obj)
	}
	found := false
	for _, x := range props {
		if x == prop {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("%s has no property %q (%s)", obj, prop, strings.Join(props, ", "))
	}
	p.objects[obj] = true

	op, err := p.parseOp()
	if err != nil {
		return nil, err
	}
	n := cmpNode{field: field, op: op}
	switch op {
	case "in", "not_in":
		if p.peek().kind != "lbracket" {
			return nil, fmt.Errorf("%s expects a list like ['a', 'b']", strings.ReplaceAll(op, "_", " "))
		}
		p.next()
		for {
			v := p.next()
			if v.kind != "str" && v.kind != "num" {
				return nil, fmt.Errorf("a list holds quoted strings or numbers, not %q", v.text)
			}
			n.list = append(n.list, v.text)
			if p.peek().kind == "comma" {
				p.next()
				continue
			}
			if p.peek().kind == "rbracket" {
				p.next()
				break
			}
			return nil, fmt.Errorf("expected , or ] in the list but found %q", p.peek().text)
		}
	default:
		v := p.next()
		if v.kind != "str" && v.kind != "num" {
			return nil, fmt.Errorf("expected a quoted string or a number after %s but found %q", strings.ReplaceAll(op, "_", " "), v.text)
		}
		n.value = v.text
		switch op {
		case "matches":
			re, err := regexp.Compile("(?i)" + v.text)
			if err != nil {
				return nil, fmt.Errorf("bad regular expression %q: %v", v.text, err)
			}
			n.re = re
		case ">", "<", ">=", "<=":
			f, err := strconv.ParseFloat(v.text, 64)
			if err != nil {
				return nil, fmt.Errorf("%s needs a number, not %q", op, v.text)
			}
			n.num = f
		}
	}
	return n, nil
}

// parseOp reads a comparison operator, which may be a symbol or one or two
// words: contains, not contains, starts with, ends with, equals, is, is not,
// matches, in, not in.
func (p *parser) parseOp() (string, error) {
	t := p.next()
	if t.kind == "op" {
		switch t.text {
		case "=", "==":
			return "equals", nil
		case "!=":
			return "not_equals", nil
		default:
			return t.text, nil
		}
	}
	if t.kind != "ident" {
		return "", fmt.Errorf("expected an operator (contains, equals, starts with, matches, in, ==, >) but found %q", t.text)
	}
	w := strings.ToLower(t.text)
	switch w {
	case "contains", "matches", "in", "equals":
		return w, nil
	case "is":
		if p.isWord("not") {
			p.next()
			return "not_equals", nil
		}
		return "equals", nil
	case "not":
		nxt := p.next()
		switch strings.ToLower(nxt.text) {
		case "contains":
			return "not_contains", nil
		case "in":
			return "not_in", nil
		}
		return "", fmt.Errorf("after 'not' expected contains or in, found %q", nxt.text)
	case "starts", "ends":
		if !p.isWord("with") {
			return "", fmt.Errorf("expected 'with' after %q", w)
		}
		p.next()
		return w + "_with", nil
	}
	return "", fmt.Errorf("unknown operator %q", t.text)
}
