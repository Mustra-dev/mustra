package server

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/server/directory"
	"github.com/mustra-dev/mustra/internal/store"
)

// LDAP and syslog destinations get the webhook rule: an internal address
// only when an administrator allowlisted the host, and the connection
// goes to the address that was checked.
func TestGuardedDialRefusesInternalUnlessAllowlisted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ctx := context.Background()
	if _, err := guardedDial(ctx, "tcp", ln.Addr().String(), nil, time.Second); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("loopback without an allowlist entry: %v, want refused", err)
	}
	for _, addr := range []string{"169.254.169.254:80", "10.0.0.31:636", "[::1]:389"} {
		if _, err := guardedDial(ctx, "tcp", addr, nil, time.Second); err == nil || !strings.Contains(err.Error(), "internal address") {
			t.Errorf("%s: %v, want refused as internal", addr, err)
		}
	}
	c, err := guardedDial(ctx, "tcp", ln.Addr().String(), map[string]bool{"127.0.0.1": true}, time.Second)
	if err != nil {
		t.Fatalf("allowlisted: %v", err)
	}
	c.Close()
}

// Connect's syslog exports go through the same check.
func TestConnectSyslogExportIsGuarded(t *testing.T) {
	err := deliverSyslog(context.Background(), store.ExportConfig{Target: "tcp://127.0.0.1:6514"}, []byte("x"), nil)
	if err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("syslog export to loopback: %v, want refused", err)
	}
}

// The stored bind password goes only to the server, and with the
// transport security, it was saved for: anything that would send it
// elsewhere, or less safely, needs it typed again.
func TestDirectoryPasswordStaysWithItsServer(t *testing.T) {
	stored := directory.Config{URL: "ldaps://10.0.0.31:636", CAPEM: "PEM", BindPassword: "secret"}
	str := func(v string) *string { return &v }
	yes, no := true, false
	for _, c := range []struct {
		name string
		req  directoryUpdate
		want bool // refused
	}{
		{"nothing changed", directoryUpdate{URL: str("ldaps://10.0.0.31"), CAPEM: str("PEM\n"), StartTLS: &no, AllowInsecure: &no}, false},
		{"another server", directoryUpdate{URL: str("ldap://attacker.example:389")}, true},
		{"another port", directoryUpdate{URL: str("ldaps://10.0.0.31:6360")}, true},
		{"plain LDAP allowed", directoryUpdate{AllowInsecure: &yes}, true},
		{"verification off", directoryUpdate{InsecureSkipVerify: &yes}, true},
		{"another CA", directoryUpdate{CAPEM: str("OTHER")}, true},
		{"another server with the password", directoryUpdate{URL: str("ldaps://dc02.example:636"), BindPassword: str("secret")}, false},
		{"base DN only", directoryUpdate{BaseDN: str("DC=x")}, false},
	} {
		if got := directoryPasswordMoves(stored, c.req) != ""; got != c.want {
			t.Errorf("%s: refused=%v, want %v", c.name, got, c.want)
		}
	}
}

// A directory and a syslog collector already configured on internal
// addresses keep working after the upgrade: their hosts are allowlisted
// once, and an external one is not.
func TestExistingInternalDestinationsAreAllowlistedOnce(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()
	for k, v := range map[string]string{
		settingInternalDestinationsMigrated: "",
		settingWebhookAllowedHosts:          "siem.example",
		settingDirectoryURL:                 "ldaps://10.0.0.31:636",
		"log_forward_target":                "tcp://192.168.1.20:6514",
	} {
		if err := st.SetSetting(ctx, k, v, "t"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, k := range []string{settingWebhookAllowedHosts, settingDirectoryURL, "log_forward_target", settingInternalDestinationsMigrated} {
			_ = st.SetSetting(context.Background(), k, "", "t")
		}
	})
	s.allowlistExistingInternalDestinations(ctx)
	got := s.webhookAllowedHosts(ctx)
	if !got["10.0.0.31"] || !got["192.168.1.20"] || !got["siem.example"] {
		t.Fatalf("allowlist %v, want the directory and syslog hosts added to siem.example", got)
	}
	_ = st.SetSetting(ctx, settingDirectoryURL, "ldaps://10.99.0.1:636", "t")
	s.allowlistExistingInternalDestinations(ctx)
	if s.webhookAllowedHosts(ctx)["10.99.0.1"] {
		t.Fatal("ran again: a host configured after the migration was allowlisted without an administrator")
	}
}
