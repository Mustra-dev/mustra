package reveal

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestValidators(t *testing.T) {
	if !Luhn("4111 1111 1111 1111") || !Luhn("5500-0000-0000-0004") || !Luhn("378282246310005") {
		t.Error("known-good card numbers failed Luhn")
	}
	if Luhn("4111 1111 1111 1112") || Luhn("1234567890123456") || Luhn("0000000000000000") || Luhn("555-123-4567") {
		t.Error("a bad card number passed Luhn")
	}
	if !SSN("123-45-6789") || !SSN("123 45 6789") || !SSN("123456789") {
		t.Error("well-formed SSNs rejected")
	}
	for _, bad := range []string{"000-12-3456", "666-12-3456", "912-12-3456", "123-00-6789", "123-45-0000", "078-05-1120", "12-345-6789"} {
		if SSN(bad) {
			t.Errorf("%s should be rejected", bad)
		}
	}
	if !IBAN("GB82 WEST 1234 5698 7654 32") || !IBAN("DE89370400440532013000") {
		t.Error("valid IBANs rejected")
	}
	if IBAN("GB82 WEST 1234 5698 7654 33") || IBAN("XX00") {
		t.Error("an invalid IBAN passed")
	}
}

func TestBuiltinPatternsCompileAndMatch(t *testing.T) {
	ps, err := Compile(Builtin())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Compiled{}
	for _, p := range ps {
		byID[p.ID] = p
	}
	cases := map[string][]string{
		"credit_card":         {"card: 4111 1111 1111 1111", "cc 5500000000000004", "amex 3782 822463 10005"},
		"ssn_us":              {"ssn 123-45-6789", "ssn 123 45 6789"},
		"email":               {"mail alex@example.com now"},
		"aws_access_key":      {"AKIAIOSFODNN7EXAMPLE"},
		"private_key":         {"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAswOOjh5abcdefghijk\n"},
		"phone_us":            {"call (915) 555-2908", "tel 915-555-2908", "+1 915.555.2908"},
		"password_assignment": {"password = hunter2secret", `db_password: "s3cr3tpass"`, "API_KEY=abcdef123456"},
		"github_token":        {"ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"},
		"iban":                {"GB82 WEST 1234 5698 7654 32"},
	}
	for id, texts := range cases {
		p, ok := byID[id]
		if !ok {
			t.Fatalf("no pattern %s", id)
		}
		for _, text := range texts {
			m := p.Re.FindString(text)
			if m == "" {
				t.Errorf("%s did not match %q", id, text)
				continue
			}
			if !p.Valid(m, text) {
				t.Errorf("%s matched %q but the validator rejected %q", id, text, m)
			}
		}
	}
	// Source code assigning a variable called password is not a secret,
	// and neither is documentation's placeholder.
	pw := byID["password_assignment"]
	for _, text := range []string{"password=password,", "self.password = password", "passwd: passwd", "secret = getSecret()",
		"PAPERLESS_ADMIN_PASSWORD=<password>", ";password = # comment", `password: "${DB_PASSWORD}"`, "password = changeme123"} {
		if m := pw.Re.FindString(text); m != "" && pw.Valid(m, text) {
			t.Errorf("password_assignment confirmed %q as %q", text, m)
		}
	}
	// Bare nine and ten digit runs are IDs, not SSNs or phone numbers;
	// a key header in prose is not a key.
	if m := byID["ssn_us"].Re.FindString("id 123456789 ok"); m != "" {
		t.Errorf("a bare nine-digit run matched as an SSN: %q", m)
	}
	if m := byID["phone_us"].Re.FindString("max 2147483647"); m != "" {
		t.Errorf("a bare ten-digit run matched as a phone number: %q", m)
	}
	if m := byID["private_key"].Re.FindString("It should begin with `-----BEGIN RSA PRIVATE KEY-----` or"); m != "" {
		t.Errorf("a key header in prose matched: %q", m)
	}
	// Things that must not confirm: a bare Luhn-valid run with nothing
	// nearby saying it is a card, and a non-Luhn run that is formatted.
	cc := byID["credit_card"]
	if m := cc.Re.FindString("build id 4111111111111111 ok"); m == "" || cc.Valid(m, "build id 4111111111111111 ok") {
		t.Errorf("a bare digit run with no card context was confirmed: %q", m)
	}
	if m := cc.Re.FindString("card 4111 1111 1111 1112"); m != "" && cc.Valid(m, "card 4111 1111 1111 1112") {
		t.Errorf("a non-Luhn formatted number was confirmed: %q", m)
	}
	if m := cc.Re.FindString("hash 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A"); m != "" {
		t.Errorf("a hex dump matched the card pattern: %q", m)
	}
	if _, err := Compile([]proto.RevealPattern{{ID: "x", Regex: "("}}); err == nil {
		t.Error("an unparseable regex compiled")
	}
	if _, err := Compile([]proto.RevealPattern{{ID: "x", Regex: "a", Validate: "magic"}}); err == nil {
		t.Error("an unknown validator was accepted")
	}
}

func TestMaskAndSnippet(t *testing.T) {
	if got := Mask("4111 1111 1111 1111"); got != "**** **** **** 1111" {
		t.Errorf("mask: %q", got)
	}
	if got := Mask("alex@example.com"); got != "****@******e.com" {
		t.Errorf("mask email: %q", got)
	}
	text := "line one\ncard=4111111111111111 ok\nline three"
	start := 14
	end := start + 16
	got := Snippet(text, start, end, 6)
	if got != "card=************1111 ok li" && got != "card=************1111 ok" {
		t.Errorf("snippet: %q", got)
	}
}

func TestPairsHold(t *testing.T) {
	// "card" at 0-4, "exp" at 10-13, "far" at 500-503.
	hits := map[string][][]int{
		"card": {{0, 4}},
		"exp":  {{10, 13}},
		"far":  {{500, 503}},
	}
	yes := func(a, b string, within int) bool {
		return PairsHold([]proto.RevealPair{{A: a, B: b, Within: within}}, hits)
	}
	if !yes("card", "exp", 10) {
		t.Error("six characters apart should hold within 10")
	}
	if yes("card", "far", 10) {
		t.Error("far apart should not hold")
	}
	if !yes("exp", "card", 10) {
		t.Error("order must not matter")
	}
	// A pattern that never matched cannot satisfy a requirement.
	if yes("card", "missing", 1000) {
		t.Error("a pattern with no matches must fail the pair")
	}
	// No pairs configured is not the same as a pair that fails; callers
	// only consult this when pairs exist.
	if PairsHold(nil, hits) {
		t.Error("no pairs means nothing holds here")
	}
	// Overlapping spans are distance zero.
	over := map[string][][]int{"a": {{10, 20}}, "b": {{15, 25}}}
	if !PairsHold([]proto.RevealPair{{A: "a", B: "b", Within: 0}}, over) {
		t.Error("overlapping matches should hold even at a zero window")
	}
	// The same pattern twice pairs only with a different occurrence.
	twice := map[string][][]int{"a": {{0, 4}, {8, 12}}}
	if !PairsHold([]proto.RevealPair{{A: "a", B: "a", Within: 10}}, twice) {
		t.Error("two occurrences of one pattern should pair")
	}
	once := map[string][][]int{"a": {{0, 4}}}
	if PairsHold([]proto.RevealPair{{A: "a", B: "a", Within: 1000}}, once) {
		t.Error("a single occurrence must not pair with itself")
	}
}
