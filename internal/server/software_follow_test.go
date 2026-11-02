package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionSourceValidation(t *testing.T) {
	for _, ok := range []string{"", "github:cloudflare/cloudflared", "github:prometheus/node_exporter", "github:a.b/c-d.e"} {
		if err := validVersionSource(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"cloudflare/cloudflared", "github:cloudflare", "github:../etc", "gitlab:x/y", "github:a/b/c", "github:a/b?x=1"} {
		if validVersionSource(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSameReleaseVersion(t *testing.T) {
	for _, c := range []struct {
		installed, release string
		want               bool
	}{
		{"2026.10.4", "2026.10.4", true},
		{"1.8.2-1", "1.8.2", true},
		{"1.8.2+ds-3", "1.8.2", true},
		{"1.8.20", "1.8.2", false}, // a later release, not a revision of this one
		{"1.8.1", "1.8.2", false},
		{"", "1.8.2", false},
	} {
		if got := sameReleaseVersion(c.installed, c.release); got != c.want {
			t.Errorf("sameReleaseVersion(%q, %q) = %v", c.installed, c.release, got)
		}
	}
}

func TestLatestRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/cloudflare/cloudflared/releases/latest":
			w.Write([]byte(`{"tag_name":"2026.10.4","prerelease":false}`))
		case "/repos/prometheus/node_exporter/releases/latest":
			w.Write([]byte(`{"tag_name":"v1.9.1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()
	ctx := context.Background()
	if v, err := latestRelease(ctx, "github:cloudflare/cloudflared"); err != nil || v != "2026.10.4" {
		t.Errorf("cloudflared: %q %v", v, err)
	}
	if v, err := latestRelease(ctx, "github:prometheus/node_exporter"); err != nil || v != "1.9.1" {
		t.Errorf("a v-prefixed tag: %q %v", v, err)
	}
	if _, err := latestRelease(ctx, "github:nobody/nothing"); err == nil {
		t.Error("a missing project returned a version")
	}
}
