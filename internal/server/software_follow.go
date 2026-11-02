package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// A software package is out of date on an endpoint when the installed
// version differs from the package's version, so a hand-typed version only
// notices a new release when someone edits it. A package can instead follow
// an upstream project: the server reads the project's latest release every
// few hours, moves the package's version to it, and says so, and every
// endpoint still on the old version becomes eligible for Update.
//
// GitHub releases only, because that is where the projects people run
// (cloudflared, Tailscale's tools, node_exporter…) publish, and its
// "latest release" already excludes drafts and pre-releases.

const softwareFollowEvery = 6 * time.Hour

var versionSourcePattern = regexp.MustCompile(`^github:[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$`)

// githubAPI is GitHub's REST API; tests point it at a stand-in.
var githubAPI = "https://api.github.com"

var followClient = &http.Client{Timeout: 30 * time.Second}

// validVersionSource checks a package's version_source.
func validVersionSource(src string) error {
	if src == "" || versionSourcePattern.MatchString(src) {
		return nil
	}
	return errors.New(`version_source must be empty or "github:<owner>/<repo>"`)
}

// latestRelease returns the newest non-pre-release version of the
// project src names, without a leading "v".
func latestRelease(ctx context.Context, src string) (string, error) {
	repo, ok := strings.CutPrefix(src, "github:")
	if !ok {
		return "", fmt.Errorf("unsupported version source %q", src)
	}
	owner, name, _ := strings.Cut(repo, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		githubAPI+"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mustra")
	resp, err := followClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: GitHub answered %s", repo, resp.Status)
	}
	var rel struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &rel); err != nil || strings.TrimSpace(rel.Tag) == "" {
		return "", fmt.Errorf("%s: no release tag in GitHub's answer", repo)
	}
	v := strings.TrimSpace(rel.Tag)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	if len(v) > 100 {
		return "", fmt.Errorf("%s: release tag too long", repo)
	}
	return v, nil
}

// sameReleaseVersion reports whether an installed version is the release a
// followed package names. Distribution packages add their own revision
// ("1.8.2-1", "1.8.2+ds-3"), which is still that release.
func sameReleaseVersion(installed, release string) bool {
	if installed == release {
		return true
	}
	rest, ok := strings.CutPrefix(installed, release)
	return ok && rest != "" && (rest[0] == '-' || rest[0] == '+' || rest[0] == '~')
}

// followPackageVersion moves one package to its upstream's latest release,
// notifying when it changed (announce: false when an operator's own save
// prompted the read, which is their change, not news). A failed read
// leaves the version as it was.
func (s *Server) followPackageVersion(ctx context.Context, p store.SoftwarePackage, announce bool) {
	if p.VersionSource == "" {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	v, err := latestRelease(rctx, p.VersionSource)
	if err != nil {
		s.logger.Warn("reading a package's upstream release failed", "package", p.Name, "source", p.VersionSource, "error", err)
		return
	}
	changed, err := s.store.SetFollowedVersion(ctx, p.ID, v)
	if err != nil {
		s.logger.Warn("recording a package's upstream release failed", "package", p.Name, "error", err)
		return
	}
	if !changed {
		return
	}
	s.logger.Info("package version follows its upstream", "package", p.Name, "from", p.Version, "to", v)
	s.audit(ctx, auditEvent{Action: "software.version_followed", Actor: "system", Target: p.Name, Severity: "info",
		Detail: map[string]any{"package_id": p.ID, "from": p.Version, "to": v, "source": p.VersionSource}})
	if announce && p.Version != "" {
		s.notify(ctx, "info", "Software", fmt.Sprintf("%s %s is out", p.Name, v),
			fmt.Sprintf("The catalog package now asks for %s (was %s). Endpoints with an older version show Update on the Software page.", v, p.Version),
			"/software?package="+url.QueryEscape(p.Name)+"#catalog")
	}
}

// softwareFollowLoop checks every following package a few minutes after
// start and then every softwareFollowEvery.
func (s *Server) softwareFollowLoop(ctx context.Context) {
	run := func() {
		pkgs, err := s.store.ListSoftwarePackages(ctx)
		if err != nil {
			return
		}
		for _, p := range pkgs {
			if p.VersionSource != "" && ctx.Err() == nil {
				s.followPackageVersion(ctx, p, true)
			}
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Minute):
	}
	run()
	t := time.NewTicker(softwareFollowEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
