package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ScanResult is one host found reachable during a subnet scan.
// AgentInstalled/AgentVersion are filled in by the caller (see
// deploy_api.go's annotateWithKnownAgents), not scanSubnet itself — this
// package only does the TCP-22 sweep and has no store access.
type ScanResult struct {
	IP             string `json:"ip"`
	SSHOpen        bool   `json:"ssh_open"`
	Hostname       string `json:"hostname,omitempty"`
	AgentInstalled bool   `json:"agent_installed"`
	AgentVersion   string `json:"agent_version,omitempty"`
}

// scanSubnet does a bounded-concurrency TCP connect scan of port 22 across
// every host in cidr. Deliberately opt-in and explicit (POST
// /api/deploy/scan) — this never runs on a schedule or automatically; a
// human asks for one CIDR at a time.
func scanSubnet(ctx context.Context, cidr string) ([]ScanResult, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR: %w", err)
	}

	var targets []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
		targets = append(targets, cur.String())
		if len(targets) > 1024 {
			return nil, fmt.Errorf("subnet too large (over 1024 addresses) — scan a /22 or smaller")
		}
	}

	results := make([]ScanResult, 0, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)

	for _, host := range targets {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			d := net.Dialer{Timeout: 800 * time.Millisecond}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "22"))
			if err != nil {
				return
			}
			conn.Close()

			hostname := ""
			if names, err := net.DefaultResolver.LookupAddr(ctx, host); err == nil {
				hostname = scanHostname(names)
			}
			mu.Lock()
			results = append(results, ScanResult{IP: host, SSHOpen: true, Hostname: hostname})
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return results, nil
}

// scanHostname is the name a scanned host is shown and pushed under: the
// first PTR answer that is a name (see usefulDeviceName), without the
// root's trailing dot, which the console would otherwise send as the
// push's hostname and the deployment history would keep.
func scanHostname(names []string) string {
	for _, n := range names {
		if n = strings.TrimSuffix(n, "."); usefulDeviceName(n) {
			return n
		}
	}
	return ""
}

// detectLocalCIDR guesses the subnet to scan when the admin clicks "Auto
// scan" instead of typing a CIDR. Prefers the host out of agentNATSURL
// (BEACON_AGENT_NATS_URL) when it's configured: that's an address the
// operator already told mustra is on the real LAN agents connect through,
// which matters because the server usually runs inside a container on its
// own bridge network (e.g. docker-compose's default bridge) — the
// container's own interfaces reflect that bridge subnet, not the LAN, so
// guessing from them would scan the wrong network entirely. Falls back to
// a UDP-dial route guess (assumed /24 regardless of the interface's actual
// prefix, since a bridge network's real prefix, if wider, would produce a
// useless multi-thousand-host "subnet") only if agentNATSURL isn't set.
func detectLocalCIDR(agentNATSURL string) (string, error) {
	if agentNATSURL != "" {
		if u, err := url.Parse(agentNATSURL); err == nil {
			if ip := net.ParseIP(u.Hostname()); ip != nil && ip.To4() != nil {
				return fmt.Sprintf("%s/24", ip.Mask(net.CIDRMask(24, 32))), nil
			}
		}
	}

	conn, err := net.Dial("udp", "10.255.255.255:1")
	if err != nil {
		return "", fmt.Errorf("determine local outbound address (and MUSTRA_AGENT_NATS_URL isn't set to use as a hint instead): %w", err)
	}
	defer conn.Close()
	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	return fmt.Sprintf("%s/24", localIP.Mask(net.CIDRMask(24, 32))), nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
