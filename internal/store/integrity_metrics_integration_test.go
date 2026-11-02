package store

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// A week with no unexpected change sends "by_endpoint": [], not null
// (issue #92).
func TestIntegrityMetricsByEndpointIsNeverNull(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to disposable Postgres")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Nothing can have been detected after now.
	m, err := s.IntegrityMetricsSince(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"by_endpoint":[]`) {
		t.Fatalf("metrics: %s, want by_endpoint []", b)
	}
}
