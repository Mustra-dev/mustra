package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestUsefulDeviceName(t *testing.T) {
	for name, want := range map[string]bool{
		"iPhone": true, "Living-room.lan": true, "USW-Flex-Mini": true,
		"0017886c54c1": false, "0017886c54c1.lan": false, "10.0.0.5": false, "": false, "5.0.0.10.in-addr.arpa": false,
	} {
		if got := usefulDeviceName(name); got != want {
			t.Errorf("%q: got %v", name, got)
		}
	}
}

func TestRandomizedMAC(t *testing.T) {
	for mac, want := range map[string]bool{"2a:70:4e:85:41:62": true, "76:7b:22:af:16:05": true, "28:70:4e:c5:b9:a5": false, "50:de:06:60:5d:c9": false} {
		if randomizedMAC(mac) != want {
			t.Errorf("%s: want %v", mac, want)
		}
	}
}

func TestVendorFallsBackToRegistry(t *testing.T) {
	if vendorForMAC("bc:24:11:00:00:01") != "Proxmox" {
		t.Error("the short built-in name should win")
	}
	if vendorForMAC("28:70:4e:c5:b9:a5") != "Ubiquiti" {
		t.Error("the IEEE registry should name prefixes the built-in table lacks")
	}
	if vendorForMAC("2a:70:4e:85:41:62") != "randomized MAC" {
		t.Error("randomized MACs are labelled as such")
	}
}

func TestHostInternalNeighbors(t *testing.T) {
	for _, c := range []struct {
		n    proto.NeighborInfo
		want bool
	}{
		{proto.NeighborInfo{IP: "172.18.0.2", MAC: "e6:e4:4a:17:df:d4", Interface: "br-a9293e729f67"}, true},
		{proto.NeighborInfo{IP: "172.17.0.2", MAC: "02:42:ac:11:00:02"}, true},
		{proto.NeighborInfo{IP: "10.0.0.1", MAC: "2a:70:4e:85:41:62", Interface: "vmbr0"}, false},
		{proto.NeighborInfo{IP: "10.0.0.1", MAC: "2a:70:4e:85:41:62", Interface: "eth0"}, false},
	} {
		if got := hostInternalNeighbor(c.n); got != c.want {
			t.Errorf("%+v: got %v", c.n, got)
		}
	}
}
