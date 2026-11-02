package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/oui"
	"github.com/mustra-dev/mustra/internal/store"
)

// Discover answers "what is on my network that mustra doesn't manage?".
//
// It is built on the neighbours sensor rather than a scan, which is the
// whole point: every endpoint already keeps an ARP/NDP table of the hosts
// it has talked to, so reading those tables costs nothing and puts no
// packets on the wire. The union across a fleet covers a network well,
// and it finds the devices a scan is worst at — a printer or a camera
// that ignores ping still appears in the table of whatever it last spoke
// to.
//
// Correlation is by MAC first and address second. MAC is the stabler
// identity: a device that changes address is the same device, and an
// address that changes device is not.

type discoveredHost struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Vendor    string    `json:"vendor,omitempty"`
	SeenBy    []string  `json:"seen_by"` // hostnames of agents that know it
	SeenCount int       `json:"seen_count"`
	LastSeen  time.Time `json:"last_seen"`
	Managed   bool      `json:"managed"`
	AgentID   string    `json:"agent_id,omitempty"` // set when managed
	Hostname  string    `json:"hostname,omitempty"` // set when managed
	Subnet    string    `json:"subnet,omitempty"`
	// From the server's memory (network_devices).
	Name      string     `json:"name,omitempty"`
	Label     string     `json:"label,omitempty"`
	Ignored   bool       `json:"ignored,omitempty"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	New       bool       `json:"new,omitempty"`    // first seen in the last day
	Absent    bool       `json:"absent,omitempty"` // in no endpoint's table now
}

func (h *discoveredHost) applyMemory(d store.NetworkDevice) {
	h.Name, h.Label, h.Ignored = d.Name, d.Label, d.Ignored
	first := d.FirstSeen
	h.FirstSeen = &first
	h.New = !d.Baseline && time.Since(first) < 24*time.Hour
	if h.Absent {
		h.SeenCount = 0
	}
}

// discoverHosts builds the union of every endpoint's neighbour table.
func (s *Server) discoverHosts(ctx context.Context) ([]discoveredHost, int, int, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, 0, 0, err
	}
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorNeighbors))
	if err != nil {
		return nil, 0, 0, err
	}

	managedByIP, managedByAgent := managedAddresses(agents)

	hosts := map[string]*discoveredHost{} // keyed by MAC
	for _, row := range rows {
		var neighbors []proto.NeighborInfo
		if err := json.Unmarshal(row.Data, &neighbors); err != nil {
			s.logger.Warn("neighbours snapshot not usable", "agent_id", row.AgentID, "error", err)
			continue
		}
		for _, n := range neighbors {
			if n.MAC == "" || hostInternalNeighbor(n) {
				continue
			}
			h, ok := hosts[n.MAC]
			if !ok {
				h = &discoveredHost{IP: n.IP, MAC: n.MAC, Vendor: vendorForMAC(n.MAC),
					Subnet: subnetOf(n.IP)}
				hosts[n.MAC] = h
			}
			// Prefer a routable address if we later see one for the same
			// device, so a link-local entry doesn't win the display.
			if h.IP == "" {
				h.IP = n.IP
			}
			h.SeenBy = appendUnique(h.SeenBy, row.Hostname)
			h.SeenCount = len(h.SeenBy)
			if row.CollectedAt.After(h.LastSeen) {
				h.LastSeen = row.CollectedAt
			}
			if agentID, ok := managedByIP[n.IP]; ok {
				h.Managed = true
				h.AgentID = agentID
				h.Hostname = managedByAgent[agentID]
			}
		}
	}

	out := make([]discoveredHost, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, *h)
	}
	return out, len(rows), len(agents), nil
}

// discoverResponse is what GET /api/discover answers.
type discoverResponse struct {
	AlertNew        bool             `json:"alert_new"`
	DNSServers      string           `json:"dns_servers"`
	FleetSize       int              `json:"fleet_size"`
	Hosts           []discoveredHost `json:"hosts"`
	New             int              `json:"new"`
	ReportingAgents int              `json:"reporting_agents"`
	Total           int              `json:"total"`
	Unmanaged       int              `json:"unmanaged"`
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	out, reporting, fleet, err := s.discoverHosts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// What the server remembers: names, labels, first sighting. A device
	// no endpoint currently lists is still known, and shown as gone quiet.
	known, err := s.store.ListNetworkDevices(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	byMAC := map[string]store.NetworkDevice{}
	for _, d := range known {
		byMAC[d.MAC] = d
	}
	present := map[string]bool{}
	for i := range out {
		present[out[i].MAC] = true
		if d, ok := byMAC[out[i].MAC]; ok {
			out[i].applyMemory(d)
		}
	}
	for _, d := range known {
		if present[d.MAC] {
			continue
		}
		h := discoveredHost{IP: d.IP, MAC: d.MAC, Vendor: vendorForMAC(d.MAC), Subnet: subnetOf(d.IP), SeenBy: d.SeenBy, LastSeen: d.LastSeen, Absent: true}
		h.applyMemory(d)
		out = append(out, h)
	}
	// Unmanaged first — that's the actionable half — then by how many
	// endpoints have seen it, which is a decent proxy for how real it is.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Managed != out[j].Managed {
			return !out[i].Managed
		}
		if out[i].SeenCount != out[j].SeenCount {
			return out[i].SeenCount > out[j].SeenCount
		}
		return ipLess(out[i].IP, out[j].IP)
	})

	unmanaged, fresh := 0, 0
	for _, h := range out {
		if !h.Managed && !h.Ignored && !h.Absent {
			unmanaged++
		}
		if h.New && !h.Ignored {
			fresh++
		}
	}
	settings, _ := s.store.GetAllSettings(r.Context())
	writeJSONResponse(w, discoverResponse{
		Hosts: out, Total: len(out), Unmanaged: unmanaged, New: fresh,
		ReportingAgents: reporting, FleetSize: fleet,
		DNSServers: settings[settingDiscoverDNS], AlertNew: settings[settingDiscoverAlerts] != "off",
	})
}

// containerBridge matches interfaces that only reach containers or VMs on
// the same host (Docker's docker0 and br-<id>, CNI, Podman, libvirt, LXC,
// veth pairs). What sits behind them is not on the network; container
// addresses and MACs also change on every restart, which would read as a
// stream of new devices. Proxmox's vmbr bridges are the LAN and stay.
var containerBridge = regexp.MustCompile(`^(docker\d*|hassio|br-[0-9a-f]{12}|veth|cni|flannel|cali|weave|podman\d*|virbr\d*|lxcbr\d*|lxdbr\d*|kube)`)

func hostInternalNeighbor(n proto.NeighborInfo) bool {
	if containerBridge.MatchString(n.Interface) {
		return true
	}
	// Docker's own MAC prefix, for agents that do not report the interface.
	return strings.HasPrefix(strings.ToLower(n.MAC), "02:42:")
}

// managedAddresses indexes every address mustra already manages, so a
// neighbour that is one of our own endpoints is labelled rather than
// reported as a discovery.
func managedAddresses(agents []store.AgentRecord) (byIP map[string]string, hostnames map[string]string) {
	byIP = map[string]string{}
	hostnames = map[string]string{}
	for _, a := range agents {
		hostnames[a.AgentID] = a.Hostname
		for _, ip := range a.IPs {
			byIP[ip] = a.AgentID
		}
	}
	return byIP, hostnames
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func subnetOf(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	v4[3] = 0
	return (&net.IPNet{IP: v4, Mask: net.CIDRMask(24, 32)}).String()
}

func ipLess(a, b string) bool {
	ipa, ipb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ipa == nil || ipb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ipa[i] != ipb[i] {
			return ipa[i] < ipb[i]
		}
	}
	return false
}

// vendorForMAC resolves the OUI to a manufacturer: a few short, familiar
// names first, then the embedded IEEE registry (package oui), so the
// server never needs the internet to answer about the local network.
var ouiVendors = map[string]string{
	"00:0c:29": "VMware", "00:50:56": "VMware", "00:1c:14": "VMware",
	"00:15:5d": "Microsoft Hyper-V", "52:54:00": "QEMU/KVM", "08:00:27": "VirtualBox",
	"bc:24:11": "Proxmox", "00:16:3e": "Xen",
	"b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
	"2c:cf:67": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi",
	"00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
	"18:b4:30": "Nest", "64:16:66": "Nest",
	"74:e2:f5": "Apple", "ac:de:48": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
	"3c:22:fb": "Apple", "90:9c:4a": "Apple", "d0:81:7a": "Apple",
	"00:1a:11": "Google", "f4:f5:d8": "Google", "da:a1:19": "Google",
	"18:e8:29": "Ubiquiti", "24:5a:4c": "Ubiquiti", "78:8a:20": "Ubiquiti",
	"e0:63:da": "Ubiquiti", "74:83:c2": "Ubiquiti", "68:d7:9a": "Ubiquiti",
	"00:1d:d8": "Microsoft", "50:1a:c5": "Microsoft",
	"cc:32:e5": "Samsung", "78:bd:bc": "Samsung", "5c:49:7d": "Samsung",
	"b0:be:76": "TP-Link", "50:c7:bf": "TP-Link",
	"00:11:32": "Synology", "00:1b:21": "Intel", "3c:fd:fe": "Intel",
	"00:e0:4c": "Realtek", "d8:3b:bf": "Intel",
	"ac:63:be": "Amazon", "fc:65:de": "Amazon", "68:37:e9": "Amazon",
	"00:04:20": "Roku", "b0:a7:37": "Roku", "cc:6d:a0": "Roku",
	"48:d6:d5": "Google Nest", "d4:f5:47": "Google Nest",
}

func vendorForMAC(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToLower(mac[:8])
	if v, ok := ouiVendors[prefix]; ok {
		return v
	}
	if v := oui.Lookup(prefix); v != "" {
		return v
	}
	// Locally-administered addresses are randomized privacy MACs, which is
	// worth saying rather than leaving blank — it explains why a device
	// keeps reappearing as "new".
	if len(mac) >= 2 {
		if b := mac[1]; b == '2' || b == '6' || b == 'a' || b == 'e' {
			return "randomized MAC"
		}
	}
	return ""
}
