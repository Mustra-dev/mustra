package agent

import (
	"path/filepath"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func brandingTestAgent(t *testing.T, path string) *Agent {
	t.Helper()
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := New(Config{DataDir: path})
	a.store = st
	return a
}

func TestBrandingCacheSurvivesRestartAndOutage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")
	a := brandingTestAgent(t, path)

	b := proto.SelfServiceBranding{OrgName: "Example Health"}
	a.applyBranding(proto.SelfServiceReply{OK: true, BrandingVersion: "v1", Branding: &b})
	if a.brandingVersion() != "v1" || a.brandingForWindow().OrgName != "Example Health" {
		t.Fatalf("branding not applied: %q %+v", a.brandingVersion(), a.brandingForWindow())
	}

	// A timeout carries no version. Reading that as "reset" would strip the
	// branding from every window opened while the server is down.
	a.applyBranding(proto.SelfServiceReply{Error: "the mustra server didn't answer"})
	if a.brandingVersion() != "v1" {
		t.Fatal("an error reply cleared the cached branding")
	}

	// Same version, no body: the server is saying "you already have it".
	a.applyBranding(proto.SelfServiceReply{OK: true, BrandingVersion: "v1"})
	if a.brandingForWindow() == nil {
		t.Fatal("an unchanged version dropped the branding")
	}

	a.store.Close()
	b2 := brandingTestAgent(t, path)
	b2.loadBranding()
	if b2.brandingVersion() != "v1" || b2.brandingForWindow().OrgName != "Example Health" {
		t.Fatal("branding did not survive a restart")
	}

	// A real reply with no version is the operator resetting to default.
	b2.applyBranding(proto.SelfServiceReply{OK: true})
	if b2.brandingVersion() != "" || b2.brandingForWindow() != nil {
		t.Fatal("reset to default was ignored")
	}
	b2.loadBranding()
	if b2.brandingForWindow() != nil {
		t.Fatal("reset was not persisted")
	}
}
