package server

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The agent accepts only this shape (internal/agent/jit.go); a name the
// server mints outside it would be refused on every endpoint.
var agentJITName = regexp.MustCompile(`^mustra-[a-z0-9]{6,12}$`)

func TestJITUsernameIsWhatTheAgentAccepts(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		n := newJITUsername()
		if !agentJITName.MatchString(n) || len(n) > 20 {
			t.Fatalf("%q: the agent refuses it, or Windows' 20-character limit does", n)
		}
		if seen[n] {
			t.Fatalf("%q minted twice", n)
		}
		seen[n] = true
	}
}

func TestJITPasswordMeetsWindowsComplexity(t *testing.T) {
	for i := 0; i < 500; i++ {
		p := newJITPassword()
		if len(p) != 24 {
			t.Fatalf("length %d", len(p))
		}
		for _, class := range []string{jitLower, jitUpper, jitDigits, jitSymbols} {
			if !strings.ContainsAny(p, class) {
				t.Fatalf("%q lacks a character from %q", p, class)
			}
		}
		if strings.ContainsAny(p, "\"'\\` $") {
			t.Fatalf("%q has a character that needs escaping", p)
		}
	}
}

func TestJITKeyPairIsUsable(t *testing.T) {
	priv, authorized, err := newJITKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(priv))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("guacd needs a PKCS#1 PEM key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ssh.NewPublicKey(&key.PublicKey)
	if !bytes.Equal(pub.Marshal(), want.Marshal()) {
		t.Fatal("the authorized key is not the private key's")
	}
}

func TestUseJIT(t *testing.T) {
	for _, tc := range []struct {
		provider, mode string
		asked, want    bool
	}{
		{"guacamole", "", true, false},
		{"guacamole", "offer", false, false},
		{"guacamole", "offer", true, true},
		{"guacamole", "always", false, true},
		{"beyondtrust", "always", true, false}, // BeyondTrust brings its own credentials
		{"custom", "always", true, false},
	} {
		if got := useJIT(remoteConfig{Provider: tc.provider, JIT: tc.mode}, tc.asked); got != tc.want {
			t.Errorf("useJIT(%s, %q, asked=%v) = %v", tc.provider, tc.mode, tc.asked, got)
		}
	}
}

// guacamoleOpen is the inverse of guacamoleSeal, as Guacamole's JSON auth
// extension does it.
func guacamoleOpen(t *testing.T, key []byte, data string) map[string]any {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	plain := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, raw)
	plain = plain[:len(plain)-int(plain[len(plain)-1])]
	var out map[string]any
	if err := json.Unmarshal(plain[32:], &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGuacamoleTicketCarriesCredentialsAndRecording(t *testing.T) {
	key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = guacamoleOpen(t, key, r.PostForm.Get("data"))
		_ = json.NewEncoder(w).Encode(map[string]string{"authToken": "TOK", "dataSource": "json"})
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL + "/guacamole")
	c := remoteConfig{GuacURL: srv.URL + "/guacamole", guacBaseURL: base, guacKey: key}
	ctx := auth.WithUser(context.Background(), &store.User{Username: "alex"})
	s := &Server{}
	params := func() map[string]any {
		for _, conn := range got["connections"].(map[string]any) {
			return conn.(map[string]any)["parameters"].(map[string]any)
		}
		return nil
	}

	_, token, err := s.guacamoleTicket(ctx, c, store.AgentRecord{Hostname: "ny-01"}, "ssh", "10.0.0.2", "22", "",
		remoteCredentials{Username: "mustra-abcdefgh", PrivateKey: "-----BEGIN RSA PRIVATE KEY-----"}, "rs0123")
	if err != nil || token != "TOK" {
		t.Fatal(err, token)
	}
	p := params()
	for k, want := range map[string]string{"username": "mustra-abcdefgh", "private-key": "-----BEGIN RSA PRIVATE KEY-----",
		"recording-path": guacdRecordingsDir, "recording-name": "rs0123", "create-recording-path": "true",
		"typescript-path": guacdRecordingsDir, "typescript-name": "rs0123.typescript"} {
		if p[k] != want {
			t.Errorf("ssh %s = %v, want %q", k, p[k], want)
		}
	}
	if _, ok := p["password"]; ok {
		t.Error("an SSH key sign-in sent a password")
	}
	if _, ok := p["recording-include-keys"]; ok {
		t.Error("keystrokes would record every password typed")
	}

	if _, _, err = s.guacamoleTicket(ctx, c, store.AgentRecord{Hostname: "win"}, "rdp", "10.0.0.3", "3389", "",
		remoteCredentials{Username: "mustra-abcdefgh", Password: "pw"}, ""); err != nil {
		t.Fatal(err)
	}
	p = params()
	if p["username"] != "mustra-abcdefgh" || p["password"] != "pw" || p["domain"] != nil {
		t.Errorf("rdp params: %v", p)
	}
	if _, ok := p["recording-path"]; ok {
		t.Error("recording off still recorded")
	}

	// Without a temporary account nothing is sent and Guacamole asks.
	if _, _, err = s.guacamoleTicket(ctx, c, store.AgentRecord{Hostname: "win"}, "rdp", "10.0.0.3", "3389", "CORP", remoteCredentials{}, ""); err != nil {
		t.Fatal(err)
	}
	if p = params(); p["username"] != nil || p["password"] != nil || p["domain"] != "CORP" {
		t.Errorf("rdp without JIT: %v", p)
	}
}
