package server

import (
	"strings"
	"testing"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// FuzzShQuote proves shQuote's contract with a real shell parser
// (mvdan.cc/sh): whatever bytes go in, the quoted word parses as a single
// shell word made only of inert literal parts — single-quoted strings and
// escaped characters — never a command substitution, parameter expansion,
// glob or extra word, and the shell value of that word equals the input.
//
// This is what the install one-liner relies on: every server-filled value
// (site, URL, token, signing key) is single-quoted so the agent's shell
// treats it as data. A regression in shQuote's '\” escaping would show up
// here as a breakout.
func FuzzShQuote(f *testing.F) {
	for _, s := range []string{
		"", "plain", "a b c", "it's", `$(id)`, "`id`", `a'; id; echo '`, "a\nb",
		`'\''`, `\`, `${PATH}`, "a\tb", "*", "~", "a\"b", "#c", ";|&<>(){}",
		"'; rm -rf /; echo '", `$'\x41'`, strings.Repeat("'", 20), "a\\\nb",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		// NUL cannot survive a shell word and is not a realistic field value.
		// mvdan.cc/sh models a UTF-8 shell and rejects invalid UTF-8 that
		// a byte-oriented shell would keep inside single quotes; the values
		// spliced into the installer (site, URL, token, base64 key) are all
		// UTF-8, so the oracle is exercised over that domain.
		if strings.ContainsRune(value, 0) || !utf8.ValidString(value) || len(value) > 4096 {
			return
		}
		quoted := shQuote(value)
		// Parse "x=<quoted>" so the value is the sole word of an assignment,
		// the position it occupies in the install script (SITE=..., etc.).
		file, err := syntax.NewParser().Parse(strings.NewReader("x="+quoted), "")
		if err != nil {
			t.Fatalf("shQuote output does not parse as a shell word: in=%q quoted=%q: %v", value, quoted, err)
		}
		stmts := file.Stmts
		if len(stmts) != 1 {
			t.Fatalf("shQuote produced %d statements for %q (quoted %q)", len(stmts), value, quoted)
		}
		ce, ok := stmts[0].Cmd.(*syntax.CallExpr)
		if !ok || len(ce.Args) != 0 || len(ce.Assigns) != 1 {
			t.Fatalf("shQuote word did not stay a single assignment for %q (quoted %q)", value, quoted)
		}
		got, err := inertWordValue(ce.Assigns[0].Value)
		if err != nil {
			t.Fatalf("shQuote emitted an active shell construct for %q (quoted %q): %v", value, quoted, err)
		}
		if got != value {
			t.Fatalf("shQuote round-trip mismatch: in=%q out=%q quoted=%q", value, got, quoted)
		}
	})
}

// inertWordValue returns the literal shell value of a word, failing if the
// word contains anything a shell would evaluate (substitution, expansion,
// glob). shQuote must only ever produce single-quoted strings and
// backslash-escaped literals.
func inertWordValue(w *syntax.Word) (string, error) {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.SglQuoted:
			if p.Dollar { // $'...' interprets escapes — not inert
				return "", errActive
			}
			b.WriteString(p.Value)
		case *syntax.Lit:
			v := p.Value
			// A literal part may carry backslash escapes (\' \newline etc.).
			for i := 0; i < len(v); i++ {
				if v[i] == '\\' && i+1 < len(v) {
					i++
					if v[i] == '\n' { // line continuation: removed by the shell
						continue
					}
					b.WriteByte(v[i])
					continue
				}
				// A bare glob metacharacter in a literal would be active.
				if v[i] == '*' || v[i] == '?' || v[i] == '[' {
					return "", errActive
				}
				b.WriteByte(v[i])
			}
		default:
			return "", errActive
		}
	}
	return b.String(), nil
}

var errActive = errShell("active shell construct")

type errShell string

func (e errShell) Error() string { return string(e) }
