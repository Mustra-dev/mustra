package store

import (
	"context"
	"os"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
)

// GetAgentOSArch and GetAgentHostname are the one-row lookups per-agent
// paths use instead of reading the whole agents table.
func TestGetAgentOSArch(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := idgen.New("agt-osarch-")
	if err := s.UpsertOnRegister(ctx, id, proto.AgentInfo{Hostname: "osarch", OS: "darwin", Arch: "arm64", Site: "lab"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(ctx, id) })
	osName, arch, err := s.GetAgentOSArch(ctx, id)
	if err != nil || osName != "darwin" || arch != "arm64" {
		t.Fatalf("GetAgentOSArch = %q, %q, %v; want darwin, arm64", osName, arch, err)
	}
	if h, err := s.GetAgentHostname(ctx, id); err != nil || h != "osarch" {
		t.Fatalf("GetAgentHostname = %q, %v; want osarch", h, err)
	}
	if h, err := s.GetAgentHostname(ctx, "agt-nosuchagent"); err != nil || h != "" {
		t.Fatalf("unknown agent hostname: %q, %v; want empty and no error", h, err)
	}
	osName, arch, err = s.GetAgentOSArch(ctx, "agt-nosuchagent")
	if err != nil || osName != "" || arch != "" {
		t.Fatalf("unknown agent: %q, %q, %v; want empty and no error", osName, arch, err)
	}
}
