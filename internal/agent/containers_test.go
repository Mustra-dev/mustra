package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

const (
	digestOld = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestNew = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestParseImageRef(t *testing.T) {
	cases := []struct {
		in                   string
		domain, repo, tag, d string
	}{
		{"nginx", "docker.io", "library/nginx", "latest", ""},
		{"postgres:16.4-alpine", "docker.io", "library/postgres", "16.4-alpine", ""},
		{"linuxserver/plex:1.2", "docker.io", "linuxserver/plex", "1.2", ""},
		{"index.docker.io/library/redis", "docker.io", "library/redis", "latest", ""},
		{"ghcr.io/org/app:v1", "ghcr.io", "org/app", "v1", ""},
		{"registry.local:5000/team/app", "registry.local:5000", "team/app", "latest", ""},
		{"localhost/app:dev", "localhost", "app", "dev", ""},
		{"nginx@" + digestOld, "docker.io", "library/nginx", "latest", digestOld},
		{"nginx:1.27@" + digestOld, "docker.io", "library/nginx", "1.27", digestOld},
	}
	for _, c := range cases {
		got, err := parseImageRef(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if got.domain != c.domain || got.repo != c.repo || got.tag != c.tag || got.digest != c.d {
			t.Errorf("%s: got %+v", c.in, got)
		}
	}
	// None of these may turn into a request.
	for _, bad := range []string{"", "sha256:" + strings.Repeat("a", 64), "ff3f1b244a4c", "<none>@<none>", "Upper/Case", "a/../b", "evil.example/a?x=1", "evil.example/a#b", "a b", "nginx@sha256:short"} {
		if got, err := parseImageRef(bad); err == nil {
			t.Errorf("%q parsed: %+v", bad, got)
		}
	}
}

func TestNewerVersionTags(t *testing.T) {
	cases := []struct {
		current         string
		tags            []string
		newest, inMajor string
	}{
		{"16.4", []string{"16.3", "16.4", "16.5", "17.1", "17.2", "latest"}, "17.2", "16.5"},
		{"16.4", []string{"16.5"}, "16.5", ""},
		{"16.4", []string{"16.3", "15.9"}, "", ""},
		{"16.4-alpine", []string{"16.5", "16.5-alpine", "17-alpine", "16.5.1-alpine", "16.6-bookworm"}, "16.5-alpine", ""},
		{"v1.9.0", []string{"v1.10.0", "1.11.0", "v2.0.0-rc1", "v1.9.1"}, "v1.10.0", ""},
		{"16", []string{"17", "20240101", "16.5"}, "17", ""},
		{"9", []string{"10"}, "10", ""},
		{"1.2.3", []string{"1.2.10", "1.2.9"}, "1.2.10", ""},
		{"latest", []string{"1", "2"}, "", ""},
		{"1.2", []string{"99999999999999999999.1"}, "", ""},
	}
	for _, c := range cases {
		newest, inMajor := newerVersionTags(c.current, c.tags)
		if newest != c.newest || inMajor != c.inMajor {
			t.Errorf("%s in %v: got %q, %q; want %q, %q", c.current, c.tags, newest, inMajor, c.newest, c.inMajor)
		}
	}
}

// fakeRegistry behaves as Docker Hub does: everything needs an anonymous
// token from the realm, and a repository it is not told about is refused.
type fakeRegistry struct {
	*httptest.Server
	manifests  map[string]string // repo:tag -> digest
	tags       map[string][]string
	status     map[string]int // repo -> forced answer
	noHeader   bool
	gets       atomic.Int32
	heads      atomic.Int32
	tagLists   atomic.Int32
	sawAuthGet atomic.Bool
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{manifests: map[string]string{}, tags: map[string][]string{}, status: map[string]int{}}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeRegistry) host() string { return strings.TrimPrefix(f.URL, "https://") }

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		if r.Header.Get("Authorization") != "" {
			f.sawAuthGet.Store(true)
		}
		scope := r.URL.Query().Get("scope")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok " + scope})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v2/")
	repo, what := rest, ""
	for _, sep := range []string{"/manifests/", "/tags/list"} {
		if a, b, ok := strings.Cut(rest, sep); ok {
			repo, what = a, sep+b
		}
	}
	if r.Header.Get("Authorization") != "Bearer tok repository:"+repo+":pull" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fake",scope="repository:%s:pull"`, f.URL, repo))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if code := f.status[repo]; code != 0 {
		if code == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "600")
		}
		w.WriteHeader(code)
		return
	}
	if tag, ok := strings.CutPrefix(what, "/manifests/"); ok {
		digest, found := f.manifests[repo+":"+tag]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodHead {
			f.heads.Add(1)
		} else {
			f.gets.Add(1)
		}
		if !f.noHeader {
			w.Header().Set("Docker-Content-Digest", digest)
		}
		_, _ = w.Write([]byte("manifest"))
		return
	}
	f.tagLists.Add(1)
	all := f.tags[repo]
	last := r.URL.Query().Get("last")
	var page []string
	for _, tag := range all {
		if last == "" || tag > last {
			page = append(page, tag)
		}
		if len(page) == 2 {
			w.Header().Set("Link", fmt.Sprintf(`</v2/%s/tags/list?last=%s&n=2>; rel="next"`, repo, url.QueryEscape(tag)))
			break
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": page})
}

func testChecker(f *fakeRegistry) *imageChecker {
	c := newImageChecker(slog.New(slog.DiscardHandler))
	c.client = f.Client()
	return c
}

// rated runs one container through the checker and returns its row.
func rated(t *testing.T, c *imageChecker, image string, digests ...string) proto.ContainerInfo {
	t.Helper()
	cc := &containerCollector{checker: c, logger: slog.New(slog.DiscardHandler)}
	return cc.rate(context.Background(), []seenContainer{{info: proto.ContainerInfo{Name: "c", Image: image}, digests: digests}})[0]
}

func TestContainerUpdateConclusions(t *testing.T) {
	f := newFakeRegistry(t)
	h := f.host()
	f.manifests["app:latest"] = digestNew
	f.manifests["db:16.4"] = digestOld
	f.manifests["pin:1.0"] = digestOld
	f.manifests["same:2.0"] = digestOld
	f.manifests["moved:1.0"] = digestNew
	f.tags["db"] = []string{"16.3", "16.4", "16.5", "17.1"}
	f.tags["pin"] = []string{"1.0"}
	f.tags["same"] = []string{"2.0"}
	f.tags["moved"] = []string{"1.0", "1.1"}
	f.status["private"] = http.StatusForbidden
	f.status["busted"] = http.StatusInternalServerError

	repoDigest := func(repo, d string) string { return h + "/" + repo + "@" + d }
	cases := []struct {
		name, image string
		digests     []string
		update      string
		newer       string
		inMajor     string
		detail      string
	}{
		{"floating tag moved", h + "/app:latest", []string{repoDigest("app", digestOld)}, proto.ContainerUpdateAvailable, "", "", "different image"},
		{"floating tag current", h + "/app:latest", []string{repoDigest("app", digestNew)}, proto.ContainerUpToDate, "", "", ""},
		{"an older digest kept alongside the current one", h + "/app:latest", []string{repoDigest("app", digestOld), repoDigest("app", digestNew)}, proto.ContainerUpToDate, "", "", ""},
		{"pinned version with newer tags", h + "/db:16.4", []string{repoDigest("db", digestOld)}, proto.ContainerUpdateAvailable, "17.1", "16.5", "newer version tag"},
		{"pinned, nothing newer", h + "/pin:1.0", []string{repoDigest("pin", digestOld)}, proto.ContainerUpToDate, "", "", ""},
		{"pinned tag rebuilt and superseded", h + "/moved:1.0", []string{repoDigest("moved", digestOld)}, proto.ContainerUpdateAvailable, "1.1", "", "different image, and a newer"},
		{"built locally", h + "/app:latest", nil, proto.ContainerNotChecked, "", "", "no registry digest"},
		{"digest from another repository", h + "/app:latest", []string{"nginx@" + digestNew}, proto.ContainerNotChecked, "", "", "no registry digest"},
		{"pinned by digest", h + "/app@" + digestOld, []string{repoDigest("app", digestOld)}, proto.ContainerNotChecked, "", "", "Pinned by digest"},
		{"image ID", "sha256:" + strings.Repeat("c", 64), nil, proto.ContainerNotChecked, "", "", "no name"},
		{"forbidden", h + "/private:latest", []string{repoDigest("private", digestOld)}, proto.ContainerCheckFailed, "", "", "refused an anonymous check"},
		{"missing tag", h + "/app:gone", []string{repoDigest("app", digestOld)}, proto.ContainerCheckFailed, "", "", "does not have this tag"},
		{"registry error", h + "/busted:latest", []string{repoDigest("busted", digestOld)}, proto.ContainerCheckFailed, "", "", "status 500"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rated(t, testChecker(f), c.image, c.digests...)
			if got.Update != c.update || got.NewerTag != c.newer || got.NewerTagInMajor != c.inMajor {
				t.Errorf("got %+v", got)
			}
			if !strings.Contains(got.UpdateDetail, c.detail) {
				t.Errorf("detail %q does not say %q", got.UpdateDetail, c.detail)
			}
		})
	}
	if f.sawAuthGet.Load() {
		t.Error("a credential was sent to the token service")
	}
}

// A digest that matches is not "up to date" when the question that matters
// for a pinned version could not be asked.
func TestContainerTagListFailureIsNotUpToDate(t *testing.T) {
	f := newFakeRegistry(t)
	f.manifests["db:16.4"] = digestOld
	f.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tags/list") && r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.serve(w, r)
	})
	got := rated(t, testChecker(f), f.host()+"/db:16.4", f.host()+"/db@"+digestOld)
	if got.Update != proto.ContainerCheckFailed || !strings.Contains(got.UpdateDetail, "could not be listed") {
		t.Errorf("got %+v", got)
	}
}

func TestContainerManifestDigestFromBodyWithoutHeader(t *testing.T) {
	f := newFakeRegistry(t)
	f.noHeader = true
	f.manifests["app:latest"] = digestOld
	sum := sha256.Sum256([]byte("manifest")) // what the fake serves
	bodyDigest := "sha256:" + hex.EncodeToString(sum[:])
	got := rated(t, testChecker(f), f.host()+"/app:latest", f.host()+"/app@"+bodyDigest)
	if got.Update != proto.ContainerUpToDate || got.LatestDigest != bodyDigest || f.gets.Load() != 1 {
		t.Fatalf("got %+v after %d GETs", got, f.gets.Load())
	}
}

func TestImageCheckerCachesAndRetries(t *testing.T) {
	f := newFakeRegistry(t)
	f.manifests["app:latest"] = digestOld
	c := testChecker(f)
	at := time.Now()
	c.now = func() time.Time { return at }
	ref, _ := parseImageRef(f.host() + "/app:latest")

	// Two containers of one image are one question.
	c.refresh(context.Background(), []imageRef{ref, ref})
	if got := f.heads.Load(); got != 1 {
		t.Fatalf("%d requests for one image", got)
	}
	c.refresh(context.Background(), []imageRef{ref})
	if got := f.heads.Load(); got != 1 {
		t.Fatalf("asked again inside the interval: %d", got)
	}
	at = at.Add(containerCheckEvery + containerCheckSpread)
	c.refresh(context.Background(), []imageRef{ref})
	if got := f.heads.Load(); got != 2 {
		t.Fatalf("did not ask after the interval: %d", got)
	}

	// An image no longer in use is forgotten.
	c.refresh(context.Background(), nil)
	if _, ok := c.result(ref); ok {
		t.Error("kept a result for an image nothing uses")
	}
}

func TestImageCheckerBacksOffOnRateLimit(t *testing.T) {
	f := newFakeRegistry(t)
	f.status["a"] = http.StatusTooManyRequests
	f.manifests["b:latest"] = digestOld
	c := testChecker(f)
	at := time.Now()
	c.now = func() time.Time { return at }
	a, _ := parseImageRef(f.host() + "/a:latest")
	b, _ := parseImageRef(f.host() + "/b:latest")

	c.refresh(context.Background(), []imageRef{a})
	if res, _ := c.result(a); !strings.Contains(res.failure, "rate limit") {
		t.Fatalf("got %+v", res)
	}
	// The whole registry is left alone for as long as it asked.
	c.refresh(context.Background(), []imageRef{a, b})
	if _, ok := c.result(b); ok {
		t.Fatal("asked a registry that said to back off")
	}
	at = at.Add(601 * time.Second)
	c.refresh(context.Background(), []imageRef{a, b})
	if res, ok := c.result(b); !ok || res.digest != digestOld {
		t.Fatalf("did not resume: %+v", res)
	}
}

func TestImageCheckerUnreachableRegistryStopsTrying(t *testing.T) {
	f := newFakeRegistry(t)
	c := testChecker(f)
	ref, _ := parseImageRef(f.host() + "/a:latest")
	ref2, _ := parseImageRef(f.host() + "/b:latest")
	f.Close()
	c.refresh(context.Background(), []imageRef{ref})
	res, ok := c.result(ref)
	if !ok || !strings.Contains(res.failure, "could not reach") {
		t.Fatalf("got %+v", res)
	}
	c.refresh(context.Background(), []imageRef{ref2})
	if _, ok := c.result(ref2); ok {
		t.Error("kept trying a registry that is down")
	}
}

func TestParseBearerChallengeRefusesPlainHTTPRealm(t *testing.T) {
	if _, ok := parseBearerChallenge(`Basic realm="x"`); ok {
		t.Error("took a Basic challenge")
	}
	s := &registrySession{checker: newImageChecker(slog.New(slog.DiscardHandler)), ref: imageRef{repo: "a"}}
	err := s.fetchToken(context.Background(), `Bearer realm="http://attacker.example/token"`)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("got %v", err)
	}
}

// fakeEngine serves the Docker API on a unix socket and fails the test on
// anything but a read.
func fakeEngine(t *testing.T, routes map[string]string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "engine")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("the sensor sent %s %s", r.Method, r.URL)
		}
		body, ok := routes[r.URL.RequestURI()]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestCollectFromEngine(t *testing.T) {
	sock := fakeEngine(t, map[string]string{
		"/containers/json?all=1": `[
			{"Id":"` + strings.Repeat("1", 64) + `","Names":["/web"],"Image":"sha256:` + strings.Repeat("d", 64) + `","ImageID":"sha256:` + strings.Repeat("d", 64) + `","State":"running","Status":"Up 3 days",
			 "Labels":{"com.docker.compose.project":"site","com.docker.compose.service":"web","com.docker.compose.project.config_files":"/srv/site/compose.yml","SECRET":"nope"}},
			{"Id":"` + strings.Repeat("2", 64) + `","Names":["/old"],"Image":"busybox","ImageID":"sha256:` + strings.Repeat("e", 64) + `","State":"exited","Status":"Exited (0)"},
			{"Id":"` + strings.Repeat("3", 64) + `","Names":["/api"],"Image":"mine:dev","ImageID":"sha256:` + strings.Repeat("f", 64) + `","State":"running","Status":"Up"}]`,
		"/containers/" + strings.Repeat("1", 64) + "/json":    `{"Config":{"Image":"nginx:1.27","Env":["SECRET=nope"]}}`,
		"/images/sha256:" + strings.Repeat("d", 64) + "/json": `{"RepoDigests":["nginx@` + digestOld + `"]}`,
		"/images/sha256:" + strings.Repeat("e", 64) + "/json": `{"RepoDigests":[]}`,
	})
	c := &containerCollector{sockets: []string{filepath.Join(filepath.Dir(sock), "absent.sock"), sock}, logger: slog.New(slog.DiscardHandler)}
	got, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != "api" || got[1].Name != "web" || got[2].Name != "old" {
		t.Fatalf("running first, then by name: %+v", got)
	}
	web := got[1]
	// The list showed an ID; the tag moved. The configured reference is
	// what the container is really following.
	if web.Image != "nginx:1.27" || web.ImageDigest != digestOld || web.ComposeProject != "site" || web.ComposeService != "web" || web.ComposeFile != "/srv/site/compose.yml" || web.ID != strings.Repeat("1", 12) {
		t.Errorf("web: %+v", web)
	}
	if web.Update != proto.ContainerNotChecked || !strings.Contains(web.UpdateDetail, "turned off") {
		t.Errorf("checks off: %+v", web)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "nope") {
		t.Errorf("secrets in the snapshot: %s", raw)
	}
}

func TestCollectNoEngineIsEmptyNotNull(t *testing.T) {
	c := &containerCollector{sockets: []string{filepath.Join(t.TempDir(), "absent.sock")}, logger: slog.New(slog.DiscardHandler)}
	got, err := c.collect(context.Background())
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
	if raw, _ := json.Marshal(got); string(raw) != "[]" {
		t.Errorf("published %s", raw)
	}
}

// A socket nothing answers on must not read as "no containers", or a daemon
// restart would empty the fleet view.
func TestCollectDeadEngineIsAnError(t *testing.T) {
	dir, err := os.MkdirTemp("", "engine")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	c := &containerCollector{sockets: []string{sock}, logger: slog.New(slog.DiscardHandler)}
	if _, err := c.collect(context.Background()); err == nil {
		t.Fatal("no error from a dead engine")
	}
}

// TestLiveContainers runs against this machine's engine and the real
// registries. Opt-in: MUSTRA_LIVE_CONTAINERS=1 go test ./internal/agent -run LiveContainers -v
func TestLiveContainers(t *testing.T) {
	if os.Getenv("MUSTRA_LIVE_CONTAINERS") == "" {
		t.Skip("set MUSTRA_LIVE_CONTAINERS=1")
	}
	c := newContainerCollector(true, slog.Default())
	got, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		t.Logf("%-32s %-44s %-16s newer=%q/%q %s", r.Name, r.Image, r.Update, r.NewerTag, r.NewerTagInMajor, r.UpdateDetail)
	}
}
