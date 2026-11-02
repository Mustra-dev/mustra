package agent

import "testing"

func TestReplaceKeyValue(t *testing.T) {
	cases := []struct{ in, key, val, want string }{
		{"a=1\nclient_secret = old\nb=2\n", "client_secret", "new", "a=1\nclient_secret = new\nb=2\n"},
		{"export CLIENT_SECRET=\"old\"\n", "CLIENT_SECRET", "n3w", "export CLIENT_SECRET=\"n3w\"\n"},
		{"oidc:\n  client_secret: 'x'\n", "client_secret", "y$z", "oidc:\n  client_secret: 'y$z'\n"},
	}
	for _, c := range cases {
		got, err := replaceKeyValue(c.in, c.key, c.val)
		if err != nil || got != c.want {
			t.Errorf("%q: got %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := replaceKeyValue("a=1\n", "client_secret", "x"); err == nil {
		t.Error("a missing key must fail")
	}
	if _, err := replaceKeyValue("k=1\nk=2\n", "k", "x"); err == nil {
		t.Error("a key twice must fail")
	}
	if _, err := replaceKeyValue("k=1\n", "k", "a\nb"); err == nil {
		t.Error("a multi-line value must fail")
	}
}
