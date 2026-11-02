package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/updatesig"
)

const updAgent = "agt-0123456789abcdef0123456789abcdef"

func signedOffer(t *testing.T, key ed25519.PrivateKey, body []byte, version, url string) *proto.UpdateOffer {
	t.Helper()
	sum := sha256.Sum256(body)
	m, err := updatesig.Sign(updatesig.Manifest{File: "mustra-agent-" + runtime.GOOS + "-" + runtime.GOARCH,
		OS: runtime.GOOS, Arch: runtime.GOARCH, Version: version, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}, key)
	if err != nil {
		t.Fatal(err)
	}
	return &proto.UpdateOffer{BinaryURL: url, Manifest: m}
}

func testUpdateAgent(t *testing.T, pinned ed25519.PublicKey) *Agent {
	t.Helper()
	dir := t.TempDir()
	a := New(Config{DataDir: filepath.Join(dir, "mustra-agent.db"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	a.agentID = updAgent
	a.info.Version = "0.90.0"
	if pinned != nil {
		a.cred = &agentCredential{AgentID: updAgent, Secret: "s", UpdateSigningKey: updatesig.EncodePublicKey(pinned)}
	}
	return a
}

func TestUpdateRefusals(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("new agent build")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()

	cases := map[string]struct {
		agent *Agent
		offer *proto.UpdateOffer
		want  string
	}{
		"no offer":       {testUpdateAgent(t, pub), nil, "no signed update"},
		"nothing pinned": {testUpdateAgent(t, nil), signedOffer(t, priv, body, "0.90.1", srv.URL), "no pinned update signing key"},
		"wrong key":      {testUpdateAgent(t, pub), signedOffer(t, otherPriv, body, "0.90.1", srv.URL), "does not verify"},
		"downgrade":      {testUpdateAgent(t, pub), signedOffer(t, priv, body, "0.89.0", srv.URL), "downgrade"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.agent.startVerifiedUpdate(context.Background(), c.offer)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
			if _, err := os.Stat(filepath.Join(c.agent.dataDir(), updateStateFile)); err == nil {
				t.Fatal("a refused update left state for the updater")
			}
		})
	}
}

// The binary must match the signed digest and size exactly; a substituted
// or truncated download is discarded before anything is replaced.
func TestDownloadVerified(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	good := []byte("the real build")
	served := good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(served) }))
	defer srv.Close()
	offer := signedOffer(t, priv, good, "0.90.1", srv.URL)
	dest := filepath.Join(t.TempDir(), "agent.new")

	if err := downloadVerified(context.Background(), srv.URL, dest, offer.Manifest); err != nil {
		t.Fatalf("good download refused: %v", err)
	}
	served = []byte("the evil build")
	if err := downloadVerified(context.Background(), srv.URL, dest, offer.Manifest); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("substituted binary accepted: %v", err)
	}
	served = good[:4]
	if err := downloadVerified(context.Background(), srv.URL, dest, offer.Manifest); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("truncated binary accepted: %v", err)
	}
	if err := downloadVerified(context.Background(), "file:///etc/passwd", dest, offer.Manifest); err == nil {
		t.Fatal("non-http URL accepted")
	}
}

func TestCredentialFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DACL, not mode bits")
	}
	path := filepath.Join(t.TempDir(), credentialFile)
	if err := saveCredential(path, agentCredential{AgentID: updAgent, Secret: "x"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file mode %v", fi.Mode().Perm())
	}
	c, err := loadCredential(path)
	if err != nil || c == nil || c.AgentID != updAgent {
		t.Fatalf("round trip: %+v %v", c, err)
	}
	if err := os.WriteFile(path, []byte(`{"agent_id":"../x","secret":"y"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredential(path); err == nil {
		t.Fatal("malformed agent id in the credential file accepted")
	}
}

// A download that fails on the network is retried, after jittered waits,
// until it succeeds; one that fails on what was downloaded is not.
func TestDownloadWithRetry(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	good := []byte("the real build")
	failures, served := 2, good
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits <= failures {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write(served)
	}))
	defer srv.Close()
	offer := signedOffer(t, priv, good, "0.90.1", srv.URL)
	dest := filepath.Join(t.TempDir(), "agent.new")
	delays := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute}
	var waited []time.Duration
	sleep := func(_ context.Context, d time.Duration) error { waited = append(waited, d); return nil }

	err := downloadVerified(context.Background(), srv.URL, dest, offer.Manifest)
	if !isTransientDownload(err) {
		t.Fatalf("a 502 is not transient: %v", err)
	}
	if err := downloadWithRetry(context.Background(), srv.URL, dest, offer.Manifest, delays, sleep); err != nil {
		t.Fatalf("retry did not recover: %v", err)
	}
	if len(waited) != 2 || waited[0] < 30*time.Second || waited[0] >= time.Minute || waited[1] < time.Minute || waited[1] >= 2*time.Minute {
		t.Fatalf("waits %v: want one per retry, each in [d/2, d)", waited)
	}

	// The wrong file: no amount of retrying fixes that.
	hits, failures, waited, served = 0, 0, nil, []byte("the evil build")
	err = downloadWithRetry(context.Background(), srv.URL, dest, offer.Manifest, delays, sleep)
	if err == nil || isTransientDownload(err) || len(waited) != 1 {
		t.Fatalf("digest mismatch: err %v after %d tries", err, len(waited))
	}

	// Still failing at the end: the last error comes back.
	hits, failures, waited = 0, 99, nil
	err = downloadWithRetry(context.Background(), srv.URL, dest, offer.Manifest, delays, sleep)
	if !isTransientDownload(err) || len(waited) != len(delays) {
		t.Fatalf("persistent 502: err %v after %d tries", err, len(waited))
	}
	if _, serr := os.Stat(dest); !os.IsNotExist(serr) {
		t.Fatal("a failed download left its file behind")
	}

	// A 404 is a wrong address, not a bad connection.
	nf := httptest.NewServer(http.NotFoundHandler())
	defer nf.Close()
	if err := downloadVerified(context.Background(), nf.URL, dest, offer.Manifest); err == nil || isTransientDownload(err) {
		t.Fatalf("404: %v", err)
	}
}

// Under the Home Assistant add-on the agent downloads and verifies the
// build itself and leaves it as <exe>.verified for run.sh to install, then
// exits. A build that does not match the signed manifest is never staged,
// and the agent stays up.
func TestUpdateByRestartStagesOnlyTheVerifiedBuild(t *testing.T) {
	t.Setenv("MUSTRA_UPDATE_BY_RESTART", "1")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	good := []byte("the signed build")
	served := good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(served) }))
	defer srv.Close()

	exe := filepath.Join(t.TempDir(), "mustra-agent")
	_ = os.WriteFile(exe, []byte("the installed build"), 0o755)
	exits := 0
	defer func(e func(), x func() (string, error)) { exitForUpdate, updateExecutable = e, x }(exitForUpdate, updateExecutable)
	exitForUpdate = func() { exits++ }
	updateExecutable = func() (string, error) { return exe, nil }

	// Same length, different bytes: whoever serves the download, it is not
	// what was signed.
	served = []byte("the forged build")
	a := testUpdateAgent(t, pub)
	if _, err := a.startVerifiedUpdate(context.Background(), signedOffer(t, priv, good, "0.90.1", srv.URL)); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("a forged build was not refused: %v", err)
	}
	if _, err := os.Stat(exe + verifiedSuffix); err == nil || exits != 0 {
		t.Fatalf("a forged build was staged (exits %d)", exits)
	}

	served = good
	msg, err := a.startVerifiedUpdate(context.Background(), signedOffer(t, priv, good, "0.90.1", srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe + verifiedSuffix); string(b) != string(good) || exits != 1 {
		t.Fatalf("staged %q, exits %d (%s)", b, exits, msg)
	}
	if b, _ := os.ReadFile(exe); string(b) != "the installed build" {
		t.Fatal("the agent replaced its own binary; that is run.sh's job")
	}
	if _, err := os.Stat(filepath.Join(a.dataDir(), updateStateFile)); err == nil {
		t.Fatal("left state for a detached updater the add-on does not run")
	}
}
