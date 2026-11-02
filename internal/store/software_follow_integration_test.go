package store

import (
	"context"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// version_source survives a save, and only a following package's version
// is moved, once per change.
func TestFollowedVersion(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	p := SoftwarePackage{ID: idgen.New("sw-"), Kind: KindSoftware, Name: "cloudflared-test", Version: "2026.10.2",
		Commands: map[string]SoftwareOps{"linux": {Update: "true"}}, Detect: SoftwareDetect{AppName: "cloudflared"},
		Enabled: true, VersionSource: "github:cloudflare/cloudflared"}
	saved, err := s.UpsertSoftwarePackage(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteSoftwarePackage(context.Background(), p.ID) })
	if saved.VersionSource != p.VersionSource {
		t.Fatalf("version_source = %q", saved.VersionSource)
	}
	if changed, err := s.SetFollowedVersion(ctx, p.ID, "2026.10.4"); err != nil || !changed {
		t.Fatalf("first move: %v %v", changed, err)
	}
	if changed, _ := s.SetFollowedVersion(ctx, p.ID, "2026.10.4"); changed {
		t.Fatal("the same version counted as a change")
	}
	got, _ := s.GetSoftwarePackage(ctx, p.ID)
	if got.Version != "2026.10.4" || got.Name != p.Name || got.Commands["linux"].Update != "true" {
		t.Fatalf("after following: %+v", got)
	}
	p.VersionSource = ""
	if _, err := s.UpsertSoftwarePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	if changed, _ := s.SetFollowedVersion(ctx, p.ID, "2027.1.0"); changed {
		t.Fatal("a package typed in by hand was moved")
	}
}
