package server

// Network discovery memory: a pass every few minutes records what the
// endpoints' neighbour tables show (network_devices), looks up names by
// reverse DNS, and raises an alert for a device never seen before. The
// first pass on an empty table is the baseline and alerts on nothing.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	// Comma-separated DNS servers asked for reverse lookups (the router
	// that hands out DHCP leases knows the names); empty: the server's own
	// resolver.
	settingDiscoverDNS = "discover.dns_servers"
	// "off" silences new-device alerts.
	settingDiscoverAlerts = "discover.alert_new"

	discoverEvery        = 5 * time.Minute
	discoverNameRefresh  = 24 * time.Hour
	discoverNamesPerPass = 60
)

func (s *Server) discoverLoop(ctx context.Context) {
	ticker := time.NewTicker(discoverEvery)
	defer ticker.Stop()
	for {
		s.discoverPass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) discoverPass(ctx context.Context) {
	hosts, _, _, err := s.discoverHosts(ctx)
	if err != nil {
		s.logger.Warn("discovery pass failed", "error", err)
		return
	}
	before, err := s.store.CountNetworkDevices(ctx)
	if err != nil {
		return
	}
	seen := make([]store.NetworkDevice, 0, len(hosts))
	managed := map[string]bool{}
	for _, h := range hosts {
		seen = append(seen, store.NetworkDevice{MAC: h.MAC, IP: h.IP, Vendor: h.Vendor, SeenBy: h.SeenBy, LastSeen: h.LastSeen})
		managed[h.MAC] = h.Managed
	}
	created, err := s.store.ObserveNetworkDevices(ctx, seen)
	if err != nil {
		s.logger.Warn("recording discovered devices failed", "error", err)
	}
	s.lookupDeviceNames(ctx)
	if len(created) == 0 {
		return
	}
	if before == 0 {
		// Baseline: everything already on the network is not news.
		_ = s.store.MarkNetworkBaseline(ctx, created)
		return
	}
	s.alertNewDevices(ctx, created, managed)
}

// alertNewDevices notifies once per device that appeared for the first
// time, skipping devices Mustra manages and randomized (private) MACs,
// which phones rotate and which would otherwise alert every few days.
func (s *Server) alertNewDevices(ctx context.Context, macs []string, managed map[string]bool) {
	settings, _ := s.store.GetAllSettings(ctx)
	devices, err := s.store.ListNetworkDevices(ctx)
	if err != nil {
		return
	}
	isNew := map[string]bool{}
	for _, m := range macs {
		isNew[m] = true
	}
	var done []string
	for _, d := range devices {
		if !isNew[d.MAC] {
			continue
		}
		done = append(done, d.MAC)
		if managed[d.MAC] || d.Ignored || settings[settingDiscoverAlerts] == "off" || randomizedMAC(d.MAC) {
			continue
		}
		what := firstNonEmpty(d.Name, d.Vendor, "unknown device")
		s.notify(ctx, "warning", "Discover", "New device on the network: "+what,
			strings.Join(nonEmpty(d.IP, d.MAC, d.Vendor, "seen by "+strings.Join(d.SeenBy, ", ")), " · "), "/discover")
		s.audit(ctx, auditEvent{Action: "discover.new_device", Actor: "system", Target: firstNonEmpty(d.Name, d.IP), Severity: "notice",
			Detail: map[string]any{"mac": d.MAC, "ip": d.IP, "vendor": d.Vendor, "seen_by": d.SeenBy}})
	}
	_ = s.store.SetNetworkDeviceAlerted(ctx, done)
}

func nonEmpty(v ...string) []string {
	var out []string
	for _, x := range v {
		if strings.TrimSpace(x) != "" && x != "seen by " {
			out = append(out, x)
		}
	}
	return out
}

// randomizedMAC: the locally-administered bit, which privacy MACs set.
func randomizedMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	b := strings.ToLower(mac)[1]
	return b == '2' || b == '6' || b == 'a' || b == 'e'
}

// lookupDeviceNames asks DNS for the names of devices not looked up in a
// day, a bounded number per pass.
func (s *Server) lookupDeviceNames(ctx context.Context) {
	devices, err := s.store.ListNetworkDevices(ctx)
	if err != nil {
		return
	}
	settings, _ := s.store.GetAllSettings(ctx)
	resolvers := discoverResolvers(settings[settingDiscoverDNS])
	n := 0
	for _, d := range devices {
		if d.IP == "" || (d.NameAt != nil && time.Since(*d.NameAt) < discoverNameRefresh) {
			continue
		}
		if n++; n > discoverNamesPerPass {
			break
		}
		name := reverseName(ctx, resolvers, d.IP)
		_ = s.store.SetNetworkDeviceName(ctx, d.MAC, name)
	}
}

func discoverResolvers(list string) []*net.Resolver {
	var out []*net.Resolver
	for _, srv := range strings.Split(list, ",") {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(srv); err != nil {
			srv = net.JoinHostPort(srv, "53")
		}
		addr := srv
		out = append(out, &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp", addr)
		}})
	}
	if len(out) == 0 {
		out = append(out, net.DefaultResolver)
	}
	return out
}

// reverseName returns the first PTR answer that looks like a name. Some
// routers answer with the MAC in hex for clients that sent no hostname;
// that is not a name.
func reverseName(ctx context.Context, resolvers []*net.Resolver, ip string) string {
	for _, r := range resolvers {
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		names, err := r.LookupAddr(lctx, ip)
		cancel()
		if err != nil {
			continue
		}
		for _, n := range names {
			n = strings.TrimSuffix(n, ".")
			if usefulDeviceName(n) {
				return n
			}
		}
	}
	return ""
}

func usefulDeviceName(n string) bool {
	if n == "" || net.ParseIP(n) != nil {
		return false
	}
	first, _, _ := strings.Cut(n, ".")
	if len(first) == 12 && strings.Trim(strings.ToLower(first), "0123456789abcdef") == "" {
		return false // a MAC address spelled as a name
	}
	return !strings.HasSuffix(n, ".in-addr.arpa")
}

// updateNetworkDeviceRequest is the body of PUT /api/discover/devices/{mac}.
type updateNetworkDeviceRequest struct {
	Label   *string `json:"label"`
	Ignored *bool   `json:"ignored"`
}

// PUT /api/discover/devices/{mac} {"label":"…","ignored":true}
func (s *Server) handleUpdateNetworkDevice(w http.ResponseWriter, r *http.Request) {
	mac := strings.ToLower(r.PathValue("mac"))
	var body updateNetworkDeviceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.Label != nil {
		v := strings.TrimSpace(*body.Label)
		if len(v) > 120 {
			http.Error(w, "the label is too long", http.StatusBadRequest)
			return
		}
		body.Label = &v
	}
	ok, err := s.store.UpdateNetworkDevice(r.Context(), mac, body.Label, body.Ignored)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "no such device", http.StatusNotFound)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "discover.device", Actor: auth.CurrentUser(r.Context()).Username, Target: mac, Severity: "info",
		Detail: map[string]any{"label": body.Label, "ignored": body.Ignored}})
	w.WriteHeader(http.StatusNoContent)
}

// discoverSettingsRequest is the body of POST /api/discover/settings.
type discoverSettingsRequest struct {
	DNSServers *string `json:"dns_servers"`
	AlertNew   *bool   `json:"alert_new"`
}

// POST /api/discover/settings {"dns_servers":"10.0.0.1","alert_new":true}
func (s *Server) handleDiscoverSettings(w http.ResponseWriter, r *http.Request) {
	var body discoverSettingsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	ctx, who := r.Context(), auth.CurrentUser(r.Context()).Username
	if body.DNSServers != nil {
		var clean []string
		for _, srv := range strings.Split(*body.DNSServers, ",") {
			srv = strings.TrimSpace(srv)
			if srv == "" {
				continue
			}
			host := srv
			if h, _, err := net.SplitHostPort(srv); err == nil {
				host = h
			}
			if net.ParseIP(host) == nil {
				http.Error(w, "DNS servers are IP addresses, comma separated (optionally with :port)", http.StatusBadRequest)
				return
			}
			clean = append(clean, srv)
		}
		if err := s.store.SetSetting(ctx, settingDiscoverDNS, strings.Join(clean, ","), who); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// New servers: look every name up again on the next pass.
		_ = s.store.ResetNetworkDeviceNames(ctx)
	}
	if body.AlertNew != nil {
		_ = s.store.SetSetting(ctx, settingDiscoverAlerts, map[bool]string{true: "", false: "off"}[*body.AlertNew], who)
	}
	s.audit(ctx, auditEvent{Action: "settings.discover", Actor: who, Target: "discover", Severity: "notice",
		Detail: map[string]any{"dns_servers": body.DNSServers, "alert_new": body.AlertNew}})
	go s.discoverPass(context.WithoutCancel(ctx))
	w.WriteHeader(http.StatusNoContent)
}
