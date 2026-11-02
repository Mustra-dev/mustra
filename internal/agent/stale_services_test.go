package agent

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseSystemctlServices(t *testing.T) {
	out := "Id=cloudflared.service\nMainPID=812\nActiveState=active\n\n" +
		"Id=oneshot.service\nMainPID=0\nActiveState=active\n\n" +
		"Id=failed.service\nMainPID=99\nActiveState=failed\n\n" +
		"Id=grafana-server.service\nMainPID=1203\nActiveState=active\n"
	got := parseSystemctlServices(out)
	want := []systemdService{{"cloudflared.service", 812}, {"grafana-server.service", 1203}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestStaleRestartExclude(t *testing.T) {
	for unit, excluded := range map[string]bool{
		"cloudflared.service":             false,
		"prometheus-pve-exporter.service": false,
		"grafana-server.service":          false,
		"prometheus.service":              true,
		"ssh.service":                     true,
		"docker.service":                  true,
		"postgresql@15-main.service":      true,
		"pvedaemon.service":               true,
		"systemd-journald.service":        true,
		"user@0.service":                  true,
		"mustra-agent.service":            true,
	} {
		if got := staleRestartExclude.MatchString(unit); got != excluded {
			t.Errorf("%s: excluded=%v, want %v", unit, got, excluded)
		}
	}
}

func TestStaleServiceSummary(t *testing.T) {
	if s := (staleServiceResult{}).summary(); s != "" {
		t.Fatalf("empty result should add nothing, got %q", s)
	}
	s := staleServiceResult{Restarted: []string{"cloudflared.service"}, Skipped: []string{"docker.service"}}.summary()
	if !strings.Contains(s, "restarted: cloudflared.service") || !strings.Contains(s, "docker.service") {
		t.Fatalf("summary missing services: %q", s)
	}
}
