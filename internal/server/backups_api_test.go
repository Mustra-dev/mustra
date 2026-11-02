package server

import (
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestRateBackup(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	at := func(h int) string { return now.Add(-time.Duration(h) * time.Hour).Format(time.RFC3339) }
	cases := []struct {
		g    proto.BackupGuest
		want string
	}{
		{proto.BackupGuest{Covered: true, LastBackup: at(10)}, "ok"},
		{proto.BackupGuest{Covered: true, LastBackup: at(40)}, "overdue"},
		{proto.BackupGuest{Covered: true}, "never"},
		{proto.BackupGuest{Covered: false, LastBackup: at(1)}, "not_covered"},
		{proto.BackupGuest{Covered: false}, "not_covered"},
	}
	for _, c := range cases {
		var age *float64
		if got := rateBackup(c.g, 36, now, &age); got != c.want {
			t.Errorf("%+v: got %s want %s", c.g, got, c.want)
		}
	}
}
