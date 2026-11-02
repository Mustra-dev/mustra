// Package reveal is the part of sensitive-data discovery shared by the
// agent and the server: the built-in patterns, the validators that confirm
// a match, and the masking that keeps the data itself on the endpoint.
//
// Go's regexp is RE2 -- no lookahead, no backreferences -- and that is a
// feature here: a pattern from the console cannot be made to run in
// exponential time on an endpoint. What RE2 cannot express (a card number
// that is *valid*, an SSN whose area is not 000) is what the validators
// are for, and they run only by name.
package reveal

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Builtin is the pattern library every deployment starts with. The IDs are
// stable: rules reference them, and a report names them.
func Builtin() []proto.RevealPattern {
	return []proto.RevealPattern{
		// Grouped the way cards are printed (4-4-4-4 with a possible tail,
		// or Amex's 4-6-5), or a bare run of 13-19 digits. A bare run is
		// only confirmed when something nearby says it is a card; a hex
		// dump or a big integer passes Luhn one time in ten by chance.
		{ID: "credit_card", Name: "Payment card number", Regex: `\b(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}(?:[ -]\d{1,3})?|\d{4}[ -]\d{6}[ -]\d{5}|\d{13,19})\b`, Validate: "luhn"},
		// Separators are required: a bare run of nine digits is an ID, a
		// timestamp, a coefficient -- the fleet has millions of them and
		// almost none are SSNs. The same goes for phone numbers.
		{ID: "ssn_us", Name: "US Social Security number", Regex: `\b\d{3}[- ]\d{2}[- ]\d{4}\b`, Validate: "ssn"},
		{ID: "iban", Name: "IBAN", Regex: `\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b`, Validate: "iban"},
		{ID: "email", Name: "Email address", Regex: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`},
		{ID: "phone_us", Name: "US phone number", Regex: `(?:\+?1[ .-]?)?(?:\([2-9]\d{2}\)[ .-]?|\b[2-9]\d{2}[ .-])[2-9]\d{2}[ .-]\d{4}\b`},
		{ID: "aws_access_key", Name: "AWS access key ID", Regex: `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`},
		// The header alone appears in every document that explains keys;
		// a key has base64 on the line after it.
		{ID: "private_key", Name: "Private key", Regex: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----[ \t]*\r?\n[ \t]*[A-Za-z0-9+/=]{20,}`},
		// The value has to look like a literal: quoted, or bare with a
		// digit or punctuation in it. "password=password" in source code is
		// an assignment of a variable, not a secret, and the first real scan
		// found three hundred of those.
		{ID: "password_assignment", Name: "Password or secret in a config", Regex: `(?i)[a-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*(?:["'][^"'\n<>]{6,}["']|[^\s"',;()\[\]{}<>&]{0,48}[0-9!@$%^*+/][^\s"',;()\[\]{}<>&]{0,48})`, Validate: "secret"},
		{ID: "github_token", Name: "GitHub token", Regex: `\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b`},
		{ID: "jwt", Name: "JSON Web Token", Regex: `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`},
	}
}

// Compiled is a pattern ready to run.
type Compiled struct {
	proto.RevealPattern
	Re *regexp.Regexp
}

// Compile turns the patterns of a job into runnable ones, rejecting any
// whose expression does not parse or whose validator is unknown.
func Compile(ps []proto.RevealPattern) ([]Compiled, error) {
	out := make([]Compiled, 0, len(ps))
	for _, p := range ps {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, &PatternError{ID: p.ID, Err: err}
		}
		if _, ok := validators[p.Validate]; !ok {
			return nil, &PatternError{ID: p.ID, Err: errUnknownValidator(p.Validate)}
		}
		out = append(out, Compiled{RevealPattern: p, Re: re})
	}
	return out, nil
}

type PatternError struct {
	ID  string
	Err error
}

func (e *PatternError) Error() string { return "pattern " + e.ID + ": " + e.Err.Error() }
func (e *PatternError) Unwrap() error { return e.Err }

type errUnknownValidator string

func (e errUnknownValidator) Error() string { return "unknown validator " + string(e) }

// Validators confirm a regex match, given the match and a little of the
// text around it. A missing name means "no validation": every match is
// confirmed.
var validators = map[string]func(match, context string) bool{
	"":       func(string, string) bool { return true },
	"luhn":   luhnInContext,
	"ssn":    func(m, _ string) bool { return SSN(m) },
	"iban":   func(m, _ string) bool { return IBAN(m) },
	"secret": func(m, _ string) bool { return Secret(m) },
}

// Valid reports whether a match passes its pattern's validator. Context is
// the text around the match (a line or so); validators that need it use
// it, the rest ignore it.
func (c Compiled) Valid(match, context string) bool {
	return validators[c.Validate](match, context)
}

// cardContext is a word near a bare digit run that makes it a card number
// rather than a number: "card", "visa", "pan", "cvv"... A formatted number
// (4-4-4-4) needs no such help.
var cardContext = regexp.MustCompile(`(?i)\b(?:card|visa|master ?card|amex|american express|discover|diners|jcb|pan|cvv|cvc|expir|payment|credit|debit|cc)\b`)

func luhnInContext(match, context string) bool {
	if !Luhn(match) {
		return false
	}
	if strings.ContainsAny(match, " -") {
		return true
	}
	return cardContext.MatchString(context)
}

// Luhn checks a payment card number: digits only, 13-19 of them, and the
// checksum. It is what separates a card number from a phone number with
// dashes in the wrong places, and it is the reason "credit_card" findings
// are confirmed rather than merely matched.
func Luhn(s string) bool {
	var digits []int
	for _, r := range s {
		if unicode.IsDigit(r) {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	// A run of identical digits passes Luhn for some lengths and is never
	// a real card.
	same := true
	for _, d := range digits[1:] {
		if d != digits[0] {
			same = false
			break
		}
	}
	return sum%10 == 0 && !same
}

// SSN applies the Social Security Administration's structural rules: the
// area is not 000, 666 or 900-999; the group is not 00; the serial is not
// 0000. Plus the well-known advertising number.
func SSN(s string) bool {
	// Only the three shapes the SSA uses: 9 digits, or 3-2-4 with the same
	// separator in both places. Anything else grouped differently is a
	// different kind of number that happens to have nine digits.
	switch len(s) {
	case 9:
	case 11:
		if s[3] != s[6] || (s[3] != '-' && s[3] != ' ') {
			return false
		}
		s = s[:3] + s[4:6] + s[7:]
	default:
		return false
	}
	var d []byte
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d = append(d, s[i])
	}
	area, group, serial := string(d[:3]), string(d[3:5]), string(d[5:])
	if area == "000" || area == "666" || area[0] == '9' || group == "00" || serial == "0000" {
		return false
	}
	return string(d) != "078051120" && string(d) != "219099999"
}

// IBAN checks the mod-97 checksum after moving the country code and check
// digits to the end and replacing letters with their numeric values.
func IBAN(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, r := range rearranged {
		var v int
		switch {
		case r >= '0' && r <= '9':
			v = int(r - '0')
		case r >= 'A' && r <= 'Z':
			v = int(r-'A') + 10
		default:
			return false
		}
		if v >= 10 {
			rem = (rem*100 + v) % 97
		} else {
			rem = (rem*10 + v) % 97
		}
	}
	return rem == 1
}

// Mask keeps the shape of a match and the last four characters, so an
// operator can recognise "that is the test card" without the number
// leaving the machine. Non-alphanumerics are kept; everything else but the
// tail becomes *.
func Mask(s string) string {
	runes := []rune(s)
	keep := 4
	seen := 0
	for i := len(runes) - 1; i >= 0; i-- {
		if unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) {
			if seen >= keep {
				runes[i] = '*'
			}
			seen++
		}
	}
	return string(runes)
}

// Snippet is a little context around a match with the match itself masked:
// enough to tell a real finding from a version string, not enough to be
// the finding.
func Snippet(text string, start, end int, context int) string {
	from := start - context
	if from < 0 {
		from = 0
	}
	to := end + context
	if to > len(text) {
		to = len(text)
	}
	// Do not cut a UTF-8 sequence in half.
	for from > 0 && from < len(text) && !isStart(text[from]) {
		from--
	}
	for to < len(text) && !isStart(text[to]) {
		to++
	}
	out := text[from:start] + Mask(text[start:end]) + text[end:to]
	out = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, out)
	return strings.TrimSpace(out)
}

func isStart(b byte) bool { return b&0xC0 != 0x80 }

// Secret confirms a password assignment: the value is long enough to be
// one and is not the placeholder documentation writes in its place. The
// value is whatever follows the = or :, quotes stripped.
func Secret(match string) bool {
	i := strings.IndexAny(match, "=:")
	if i < 0 {
		return false
	}
	v := strings.TrimSpace(match[i+1:])
	v = strings.Trim(v, `"'`)
	if len(v) < 8 || v[0] == '#' || v[0] == ';' {
		return false
	}
	lower := strings.ToLower(v)
	if lower == "password" || lower == "secret" || lower == "passw0rd" {
		return false
	}
	for _, placeholder := range []string{"changeme", "example", "xxxx", "your_", "<", "${", "%(", "{{", "redacted", "******", "placeholder"} {
		if strings.Contains(lower, placeholder) {
			return false
		}
	}
	return true
}

// PairsHold reports whether any required pair of patterns matched close
// enough together in one file. hits maps a pattern id to the [start,end]
// offsets where it matched.
//
// "Close enough" is measured between the nearest edges of the two matches,
// so order does not matter: a card number before an expiry date and one
// after it are the same finding. A pair naming a pattern that did not
// match at all simply fails, which is the honest reading of "require".
func PairsHold(pairs []proto.RevealPair, hits map[string][][]int) bool {
	for _, p := range pairs {
		if p.A == "" || p.B == "" {
			continue
		}
		within := p.Within
		if within <= 0 {
			within = 200
		}
		as, bs := hits[p.A], hits[p.B]
		if len(as) == 0 || len(bs) == 0 {
			continue
		}
		for _, a := range as {
			for _, b := range bs {
				// Same match cannot pair with itself; two different
				// patterns can legitimately overlap, which counts as zero
				// distance and therefore holds.
				if p.A == p.B && a[0] == b[0] {
					continue
				}
				if gap(a, b) <= within {
					return true
				}
			}
		}
	}
	return false
}

// gap is the distance between two match spans, zero when they overlap.
func gap(a, b []int) int {
	if a[0] > b[0] {
		a, b = b, a
	}
	if b[0] <= a[1] {
		return 0
	}
	return b[0] - a[1]
}
