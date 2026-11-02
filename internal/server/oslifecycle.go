package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Operating-system end of life. A host on a release its vendor no longer
// supports shows as hundreds of vulnerability findings that will never be
// fixed for that release (Ubuntu marks them "ignored: end of life"), which
// reads as a patching backlog when the remedy is upgrading the release.
// So the release's support dates are tracked and the host is flagged as
// such, on the Risk page's levels and in the Guide.
//
// Dates come from endoflife.date, refreshed daily and kept in settings so
// a restart or an outage of that site does not lose them. "eol" there is
// the end of security support: Debian's includes its LTS years, so a
// Debian release past its regular support but still under LTS is not
// flagged.

const osLifecycleBase = "https://endoflife.date/api/"

// osLifecycleProducts maps an agent's platform to the endoflife.date
// product its releases are listed under.
var osLifecycleProducts = map[string]string{
	"ubuntu": "ubuntu", "debian": "debian", "raspbian": "debian", "alpine": "alpine-linux", "darwin": "macos",
}

var osLifecycleHTTP = &http.Client{Timeout: 30 * time.Second}

// osCycle is one release of one product.
type osCycle struct {
	Cycle    string
	Codename string
	// EOL is when security support ends; zero when the vendor has not
	// announced it. Ended covers a cycle listed as ended without a date.
	EOL   time.Time
	Ended bool
}

type osLifecycleCache struct {
	mu       sync.Mutex
	products map[string][]osCycle
}

func newOSLifecycleCache() *osLifecycleCache {
	return &osLifecycleCache{products: map[string][]osCycle{}}
}

// parseOSCycles reads endoflife.date's product JSON. Its "eol" is a date,
// false (no end announced) or true (ended, date unknown).
func parseOSCycles(raw []byte) ([]osCycle, error) {
	var in []struct {
		Cycle    json.RawMessage `json:"cycle"`
		Codename any             `json:"codename"`
		EOL      json.RawMessage `json:"eol"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]osCycle, 0, len(in))
	for _, c := range in {
		var cy osCycle
		// The cycle is a string, but a few products list it as a number.
		if err := json.Unmarshal(c.Cycle, &cy.Cycle); err != nil {
			var n json.Number
			if json.Unmarshal(c.Cycle, &n) != nil {
				continue
			}
			cy.Cycle = n.String()
		}
		if s, ok := c.Codename.(string); ok {
			cy.Codename = s
		}
		var date string
		var flag bool
		switch {
		case json.Unmarshal(c.EOL, &date) == nil:
			if t, err := time.Parse("2006-01-02", date); err == nil {
				cy.EOL = t
			}
		case json.Unmarshal(c.EOL, &flag) == nil:
			cy.Ended = flag
		}
		out = append(out, cy)
	}
	return out, nil
}

func osLifecycleSetting(product string) string { return "os_lifecycle." + product }

// loadOSLifecycle fills the cache from settings, for the time before the
// first refresh after a restart.
func (s *Server) loadOSLifecycle(ctx context.Context) {
	for _, product := range uniqueProducts() {
		raw, err := s.store.GetSetting(ctx, osLifecycleSetting(product))
		if err != nil || raw == "" {
			continue
		}
		if cycles, err := parseOSCycles([]byte(raw)); err == nil {
			s.osLifecycle.mu.Lock()
			s.osLifecycle.products[product] = cycles
			s.osLifecycle.mu.Unlock()
		}
	}
}

func uniqueProducts() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range osLifecycleProducts {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// refreshOSLifecycle downloads every product's releases. A product that
// fails keeps what it had.
func (s *Server) refreshOSLifecycle(ctx context.Context) {
	for _, product := range uniqueProducts() {
		raw, err := fetchOSLifecycle(ctx, product)
		if err == nil {
			var cycles []osCycle
			if cycles, err = parseOSCycles(raw); err == nil && len(cycles) > 0 {
				s.osLifecycle.mu.Lock()
				s.osLifecycle.products[product] = cycles
				s.osLifecycle.mu.Unlock()
				_ = s.store.SetSetting(ctx, osLifecycleSetting(product), string(raw), "system")
				continue
			}
		}
		s.logger.Warn("refresh OS end-of-life dates failed", "product", product, "error", err)
	}
}

func fetchOSLifecycle(ctx context.Context, product string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osLifecycleBase+product+".json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mustra")
	resp, err := osLifecycleHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endoflife.date %s: %s", product, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// osLifecycleLoop refreshes the dates daily; vendors announce them months
// ahead.
func (s *Server) osLifecycleLoop(ctx context.Context) {
	s.loadOSLifecycle(ctx)
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
	}
	s.refreshOSLifecycle(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshOSLifecycle(ctx)
		}
	}
}

// osSupport is where one endpoint's OS release stands.
type osSupport struct {
	Release string    // "Ubuntu 25.10"
	EOL     time.Time // zero when not announced
	Ended   bool
}

// osCycleFor names the cycle a platform version belongs to in its
// product's list: Ubuntu and Alpine by major.minor, Debian by major, macOS
// by major (10.x by major.minor).
func osCycleFor(platform, version string) string {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	switch platform {
	case "debian", "raspbian":
		return parts[0]
	case "darwin":
		if parts[0] == "10" && len(parts) > 1 {
			return "10." + parts[1]
		}
		return parts[0]
	}
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

var osProductLabel = map[string]string{"ubuntu": "Ubuntu", "debian": "Debian", "raspbian": "Raspberry Pi OS", "alpine": "Alpine", "darwin": "macOS"}

// osSupportFor reports an endpoint's release support, false when its
// platform or release is not tracked.
func (s *Server) osSupportFor(platform, version string, now time.Time) (osSupport, bool) {
	platform = strings.ToLower(platform)
	product, ok := osLifecycleProducts[platform]
	if !ok {
		return osSupport{}, false
	}
	cycle := osCycleFor(platform, version)
	if cycle == "" {
		return osSupport{}, false
	}
	s.osLifecycle.mu.Lock()
	cycles := s.osLifecycle.products[product]
	s.osLifecycle.mu.Unlock()
	for _, c := range cycles {
		if c.Cycle != cycle {
			continue
		}
		sup := osSupport{Release: osProductLabel[platform] + " " + cycle, EOL: c.EOL, Ended: c.Ended}
		if !c.EOL.IsZero() && !now.Before(c.EOL) {
			sup.Ended = true
		}
		return sup, true
	}
	return osSupport{}, false
}

// eolReason says what an ended release means for its findings.
func (o osSupport) eolReason() string {
	when := ""
	if !o.EOL.IsZero() {
		when = " on " + o.EOL.Format("2006-01-02")
	}
	return o.Release + " reached end of life" + when + ": its vulnerabilities will not be fixed for this release. Upgrade the OS release."
}

// daysLeft is how many days of support remain, or -1 when unknown.
func (o osSupport) daysLeft(now time.Time) int {
	if o.EOL.IsZero() {
		return -1
	}
	return int(o.EOL.Sub(now).Hours() / 24)
}
