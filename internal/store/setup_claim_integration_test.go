package store

import (
	"context"
	"os"
	"sync"
	"testing"
)

// First-run setup decides who owns a deployment with one write, so the
// question worth testing against a real database is what happens when two
// people answer the page at the same moment. sync.Map and a mutex would
// prove nothing here: the guarantee is Postgres's, and it only holds if the
// statement is what we think it is.
//
// Opt in with a disposable database:
//
//	MUSTRA_TEST_SETUP_DSN=postgres://... go test ./internal/store/ -run SetupClaim
func TestSetupClaimHasExactlyOneWinner(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_SETUP_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_SETUP_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if n, err := st.CountUsers(ctx); err != nil {
		t.Fatalf("count users: %v", err)
	} else if n != 0 {
		t.Fatalf("this database is not empty (%d users); point the test at a disposable one", n)
	}

	const racers = 8
	var wg sync.WaitGroup
	won := make([]bool, racers)
	errs := make([]error, racers)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // line them up so the writes genuinely overlap
			won[i], errs[i] = st.ClaimSetting(ctx, "setup.completed", "true", "claimer")
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i := range won {
		if errs[i] != nil {
			t.Fatalf("racer %d failed: %v", i, errs[i])
		}
		if won[i] {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly one winner out of %d, got %d", racers, winners)
	}

	// And it stays claimed: a later attempt must not be able to take it.
	if again, err := st.ClaimSetting(ctx, "setup.completed", "true", "later"); err != nil {
		t.Fatal(err)
	} else if again {
		t.Fatal("a second claim succeeded after the deployment was already set up")
	}

	// The value the winner wrote is the one that survived, not a later one.
	got, err := st.GetSetting(ctx, "setup.completed")
	if err != nil {
		t.Fatal(err)
	}
	if got != "true" {
		t.Fatalf("setup.completed = %q, want \"true\"", got)
	}
}
