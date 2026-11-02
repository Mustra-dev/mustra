package server

import (
	"reflect"
	"testing"
	"time"
)

func TestExpiryThresholds(t *testing.T) {
	th := parseThresholds("7, 60,30,abc,30,400,1")
	if !reflect.DeepEqual(th, []int{60, 30, 7, 1, 0}) {
		t.Fatalf("parsed %v", th)
	}
	cases := []struct {
		left int
		want []int
	}{
		{90, nil},
		{60, []int{60}},
		{20, []int{60, 30}},
		{1, []int{60, 30, 7, 1}},
		{0, []int{60, 30, 7, 1, 0}}, // days round up: 0 left has just expired
		{-2, []int{60, 30, 7, 1, 0}},
	}
	for _, c := range cases {
		if got := crossedThresholds(th, c.left); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%d days left: crossed %v, want %v", c.left, got, c.want)
		}
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if d := daysLeft(now.Add(29*24*time.Hour+time.Hour), now); d != 30 {
		t.Errorf("29 days and an hour counts as 30, got %d", d)
	}
	if expirySeverity(5) != "critical" || expirySeverity(20) != "warning" || expirySeverity(45) != "notice" {
		t.Error("severity by days left")
	}
}

func TestExpiryIntegrationFilter(t *testing.T) {
	ev := integrationEvent{Type: "expiry", Detail: map[string]any{"thresholds": []int{60, 30}}}
	if !expiryWanted("", ev) || !expiryWanted("60", ev) || !expiryWanted("7,30", ev) || expiryWanted("7", ev) {
		t.Error("an integration takes the event when it newly crossed one of its thresholds")
	}
	if got, err := parseExpiryFilter("60, expired 7 60"); err != nil || got != "60,0,7" {
		t.Errorf("parsed %q %v", got, err)
	}
	if _, err := parseExpiryFilter("soon"); err == nil {
		t.Error("words other than expired are refused")
	}
	it := expiringItem{Type: "app_credential_rotation", Name: "Grafana · Client secret"}
	if got := expiryTitle(it, 30); got != "App credential rotation due in 30 day(s): Grafana · Client secret" {
		t.Errorf("title %q", got)
	}
}
