package store

import "testing"

// The pool is sized for the control plane's concurrency unless the operator
// chose a size in the DSN, which always wins.
func TestPoolConfigSize(t *testing.T) {
	cases := []struct {
		dsn  string
		want int32
	}{
		{"postgres://u:p@db:5432/mustra?sslmode=disable", defaultMaxConns},
		{"postgres://u:p@db:5432/mustra?sslmode=disable&pool_max_conns=5", 5},
		{"postgres://u:p@db:5432/mustra?pool_max_conns=64", 64},
		{"host=db user=u dbname=mustra pool_max_conns=3", 3},
	}
	for _, c := range cases {
		cfg, err := poolConfig(c.dsn)
		if err != nil {
			t.Fatalf("%s: %v", c.dsn, err)
		}
		if cfg.MaxConns != c.want {
			t.Errorf("%s: MaxConns %d, want %d", c.dsn, cfg.MaxConns, c.want)
		}
	}
	if _, err := poolConfig("postgres://u:p@db:5432/mustra?pool_max_conns=lots"); err == nil {
		t.Error("an invalid pool_max_conns must be an error, not silently replaced")
	}
}
