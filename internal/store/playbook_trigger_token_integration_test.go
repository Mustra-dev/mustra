package store

import (
	"context"
	"os"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// Webhook tokens are stored hashed. A token minted before hashing is
// hashed in place by the schema and still opens its trigger; a new one is
// never written in the clear.
func TestPlaybookWebhookTokensAreHashedAtRest(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to disposable Postgres")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close) // first registered, last run: the row cleanup needs the pool

	pbID := idgen.New("pb-token-test-")
	if _, err = s.pool.Exec(ctx, `INSERT INTO playbooks (id, name) VALUES ($1, 'token test')`, pbID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM playbooks WHERE id = $1`, pbID) })

	// A row as an older server wrote it: raw token, not marked hashed.
	legacyID, legacyToken := idgen.New("pbt-"), "legacy"+idgen.New("tok")
	if _, err = s.pool.Exec(ctx, `INSERT INTO playbook_triggers (id, playbook_id, kind, token, token_hashed)
VALUES ($1,$2,'webhook',$3,false)`, legacyID, pbID, legacyToken); err != nil {
		t.Fatal(err)
	}
	// The next start applies the schema again, which hashes it.
	s2, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var stored string
	var hashed bool
	if err = s2.pool.QueryRow(ctx, `SELECT token, token_hashed FROM playbook_triggers WHERE id = $1`, legacyID).Scan(&stored, &hashed); err != nil {
		t.Fatal(err)
	}
	if !hashed || stored != HashTriggerToken(legacyToken) {
		t.Fatalf("legacy token not hashed in place: hashed=%v stored=%q", hashed, stored)
	}
	got, err := s2.GetPlaybookTriggerByToken(ctx, legacyToken)
	if err != nil || got == nil || got.ID != legacyID {
		t.Fatalf("legacy webhook URL stopped working: %v %v", got, err)
	}
	// Applying the schema a third time must not hash the hash.
	s3, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if got, _ = s3.GetPlaybookTriggerByToken(ctx, legacyToken); got == nil {
		t.Fatal("a repeated upgrade re-hashed an already hashed token")
	}

	newToken := "new" + idgen.New("tok")
	created, err := s3.CreatePlaybookTrigger(ctx, PlaybookTrigger{ID: idgen.New("pbt-"), PlaybookID: pbID,
		Kind: TriggerWebhook, Enabled: true, Token: newToken, MinIntervalSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	if created.Token == newToken || created.Token != HashTriggerToken(newToken) {
		t.Fatalf("new token stored as %q", created.Token)
	}
	if got, _ = s3.GetPlaybookTriggerByToken(ctx, newToken); got == nil || got.ID != created.ID {
		t.Fatal("new token does not open its trigger")
	}
	if got, _ = s3.GetPlaybookTriggerByToken(ctx, created.Token); got != nil {
		t.Fatal("the stored hash itself must not work as a token")
	}
}

// An update gives a trigger a token when it becomes a webhook, keeps the
// one a webhook has, takes it away when it stops being one, and never
// creates a trigger (#57).
func TestPlaybookTriggerTokenFollowsKind(t *testing.T) {
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
	pbID := idgen.New("pb-kind-test-")
	if _, err = s.pool.Exec(ctx, `INSERT INTO playbooks (id, name) VALUES ($1, 'kind test')`, pbID); err != nil {
		t.Fatal(err)
	}
	// Deleting the playbook deletes its triggers.
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM playbooks WHERE id = $1`, pbID) })

	tr := PlaybookTrigger{ID: idgen.New("pbt-"), PlaybookID: pbID, Kind: TriggerEvent, MinIntervalSeconds: 300}
	created, err := s.CreatePlaybookTrigger(ctx, tr)
	if err != nil || created.Token != "" {
		t.Fatalf("event trigger: %+v %v", created, err)
	}
	update := func(kind, token string) (*PlaybookTrigger, bool) {
		t.Helper()
		tr.Kind = kind
		out, issued, err := s.UpdatePlaybookTrigger(ctx, tr, token)
		if err != nil || out == nil {
			t.Fatalf("update to %s: %v %v", kind, out, err)
		}
		return out, issued
	}
	opens := func(token string) bool {
		got, err := s.GetPlaybookTriggerByToken(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		return got != nil && got.ID == tr.ID
	}

	first := "first" + idgen.New("tok")
	if _, issued := update(TriggerWebhook, first); !issued || !opens(first) {
		t.Fatalf("a trigger made a webhook got no working token (issued %v)", issued)
	}
	unused := "unused" + idgen.New("tok")
	if _, issued := update(TriggerWebhook, unused); issued || opens(unused) || !opens(first) {
		t.Fatal("an update of a webhook replaced its token")
	}
	if out, issued := update(TriggerEvent, ""); issued || out.Token != "" || opens(first) {
		t.Fatalf("a trigger no longer a webhook kept its token: %q", out.Token)
	}
	second := "second" + idgen.New("tok")
	if _, issued := update(TriggerWebhook, second); !issued || !opens(second) || opens(first) {
		t.Fatal("a trigger made a webhook again did not get a new token")
	}

	ghost := tr
	ghost.ID = idgen.New("pbt-ghost-")
	out, issued, err := s.UpdatePlaybookTrigger(ctx, ghost, "ghost"+idgen.New("tok"))
	if err != nil || out != nil || issued {
		t.Fatalf("an update of an unknown trigger: %v %v %v", out, issued, err)
	}
	if got, _ := s.GetPlaybookTrigger(ctx, ghost.ID); got != nil {
		t.Fatal("an update created a trigger")
	}
}
