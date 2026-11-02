package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestSignInDomain(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    proto.DirectoryInfo
		want string
	}{
		{"joined to the synced domain: short name", proto.DirectoryInfo{Joined: true, Kind: "ad", Domain: "AD.example.com"}, "EXAMPLE"},
		{"hybrid counts as joined", proto.DirectoryInfo{Joined: true, Kind: "hybrid", Domain: "ad.example.com"}, "EXAMPLE"},
		{"another domain: its DNS name", proto.DirectoryInfo{Joined: true, Kind: "ad", Domain: "corp.example.com"}, "corp.example.com"},
		{"workgroup: none", proto.DirectoryInfo{Joined: false, Kind: "workgroup", Domain: "WORKGROUP"}, ""},
		{"Entra only: none", proto.DirectoryInfo{Joined: true, Kind: "entra"}, ""},
	} {
		if got := pickSignInDomain(tc.d, "ad.example.com", "example"); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	// Before any directory sync there is no short name to offer.
	if got := pickSignInDomain(proto.DirectoryInfo{Joined: true, Kind: "ad", Domain: "ad.example.com"}, "", ""); got != "ad.example.com" {
		t.Errorf("unsynced: got %q", got)
	}
}
