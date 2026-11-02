package store

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The vault's list is a JSON array even when it is empty: a client reads
// "credentials": [], not null.
func TestListDeployCredentialsIsNeverNull(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to disposable Postgres")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	got, err := s.ListDeployCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > 0 {
		t.Skip("needs a database with no deploy credentials")
	}
	blob, _ := json.Marshal(got)
	if !strings.HasPrefix(string(blob), "[") {
		t.Fatalf("credentials marshal as %s, want an array", blob)
	}
}
