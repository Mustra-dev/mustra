package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Certificate Manager, server half.
//
// Certificates fail on a date, silently, usually on the host nobody
// remembers owning. So the useful shape is not "here are your
// certificates" but "here is what breaks next, and where it lives" —
// sorted by time remaining, with the same certificate deployed to five
// machines shown once with its five locations rather than as five
// unrelated rows.

type certLocation struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Path     string `json:"path"`
}

type certificateRow struct {
	Fingerprint  string   `json:"fingerprint"`
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	DNSNames     []string `json:"dns_names,omitempty"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	DaysLeft     int      `json:"days_left"`
	Status       string   `json:"status"`
	IsCA         bool     `json:"is_ca"`
	SelfSigned   bool     `json:"self_signed"`
	TrustStore   bool     `json:"trust_store"`
	KeyAlgorithm string   `json:"key_algorithm,omitempty"`
	SigAlgorithm string   `json:"sig_algorithm,omitempty"`
	// Omitted when empty, which is how the list drops it. Locations are
	// only ever read by the drawer for one certificate, and a CA present on
	// every endpoint carries a location per host — 1.4 MB of them shipped
	// on every page load to draw a table that does not use them.
	Locations   []certLocation `json:"locations,omitempty"`
	Deployments int            `json:"deployments"`
}

// Thresholds chosen around how long renewal actually takes: a week is
// "drop what you're doing", a month is "schedule it", ninety days is the
// horizon worth watching at all.
const (
	certCritical = 7
	certWarning  = 30
	certNotice   = 90
)

func certStatus(daysLeft int) string {
	switch {
	case daysLeft < 0:
		return "expired"
	case daysLeft <= certCritical:
		return "critical"
	case daysLeft <= certWarning:
		return "warning"
	case daysLeft <= certNotice:
		return "notice"
	default:
		return "ok"
	}
}

// certificateRows builds the fleet's certificate inventory from cached
// sensor snapshots: grouped by fingerprint, sorted soonest-to-break-first,
// with each certificate's locations attached. Both the list and the
// single-certificate view read it, so there is one definition of what a
// certificate row means.
func (s *Server) certificateRows(ctx context.Context) ([]certificateRow, error) {
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorCertificates))
	if err != nil {
		return nil, err
	}

	// Group by fingerprint: the same certificate on five hosts is one
	// certificate with five locations, and one renewal.
	byFingerprint := map[string]*certificateRow{}
	for _, row := range rows {
		var certs []proto.CertificateInfo
		if err := json.Unmarshal(row.Data, &certs); err != nil {
			s.logger.Warn("certificate snapshot not usable", "agent_id", row.AgentID, "error", err)
			continue
		}
		for _, c := range certs {
			existing, ok := byFingerprint[c.Fingerprint]
			if !ok {
				existing = &certificateRow{
					Fingerprint: c.Fingerprint, Subject: c.Subject, Issuer: c.Issuer,
					DNSNames: c.DNSNames, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
					DaysLeft: c.DaysLeft, IsCA: c.IsCA, SelfSigned: c.SelfSigned,
					TrustStore:   c.TrustStore,
					KeyAlgorithm: c.KeyAlgorithm, SigAlgorithm: c.SigAlgorithm,
				}
				byFingerprint[c.Fingerprint] = existing
			}
			// Keep the smallest days-left across reporters: if one host's
			// clock says it's already expired, that host is broken now, and
			// the optimistic reading would hide it.
			if c.DaysLeft < existing.DaysLeft {
				existing.DaysLeft = c.DaysLeft
			}
			// Any reporter calling this a trust-store certificate settles
			// it. First-wins was wrong: a fleet mid-upgrade has agents that
			// don't set the flag at all, and one of them arriving first
			// would promote 150 vendor roots back into the findings list.
			if c.TrustStore {
				existing.TrustStore = true
			}
			existing.Locations = append(existing.Locations, certLocation{
				AgentID: row.AgentID, Hostname: row.Hostname, Path: c.Path,
			})
		}
	}

	out := make([]certificateRow, 0, len(byFingerprint))
	for _, c := range byFingerprint {
		c.Status = certStatus(c.DaysLeft)
		// Distinct endpoints, not locations: the same certificate at two
		// paths on one host is one host to go and fix, and counting it
		// twice overstates the blast radius of every finding.
		hosts := map[string]bool{}
		for _, l := range c.Locations {
			hosts[l.AgentID] = true
		}
		c.Deployments = len(hosts)
		sort.Slice(c.Locations, func(i, j int) bool { return c.Locations[i].Hostname < c.Locations[j].Hostname })
		out = append(out, *c)
	}
	// Soonest to break first — that is the only order this list is for.
	sort.Slice(out, func(i, j int) bool {
		if out[i].DaysLeft != out[j].DaysLeft {
			return out[i].DaysLeft < out[j].DaysLeft
		}
		return out[i].Subject < out[j].Subject
	})

	return out, nil
}

// certificatesResponse is what GET /api/certificates answers.
type certificatesResponse struct {
	Certificates []certificateRow       `json:"certificates"`
	Counts       map[string]int         `json:"counts"`
	ExpiringCAs  int                    `json:"expiring_cas"`
	GeneratedAt  string                 `json:"generated_at"`
	Reporting    int                    `json:"reporting"`
	ServiceCerts int                    `json:"service_certs"`
	Thresholds   certificatesThresholds `json:"thresholds"`
	Total        int                    `json:"total"`
	TrustStore   int                    `json:"trust_store"`
}

// certificatesThresholds are the days before expiry at which a
// certificate counts as critical, warning and notice.
type certificatesThresholds struct {
	Critical int `json:"critical"`
	Notice   int `json:"notice"`
	Warning  int `json:"warning"`
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	out, err := s.certificateRows(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	reporting, err := s.store.ListSensorDataForSensor(r.Context(), string(proto.SensorCertificates))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Counts cover the certificates an operator can act on. A vendor's CA
	// bundle is inventory, not a to-do list, and counting ~150 healthy
	// roots per host as "ok" makes the summary meaningless.
	counts := map[string]int{"expired": 0, "critical": 0, "warning": 0, "notice": 0, "ok": 0}
	trustStore := 0
	// The chain a CA anchors matters more than a leaf, so surface roots
	// and intermediates that expire inside the horizon separately.
	expiringCAs := 0
	// The list does not render locations; the drawer fetches the one
	// certificate it opens. See handleCertificate.
	list := make([]certificateRow, len(out))
	for i, c := range out {
		if c.TrustStore {
			trustStore++
		} else {
			counts[c.Status]++
		}
		if c.IsCA && !c.TrustStore && c.DaysLeft <= certNotice {
			expiringCAs++
		}
		list[i] = c
		list[i].Locations = nil
	}

	writeJSONResponse(w, certificatesResponse{
		Certificates: list,
		Counts:       counts,
		Total:        len(out),
		ServiceCerts: len(out) - trustStore,
		TrustStore:   trustStore,
		ExpiringCAs:  expiringCAs,
		Reporting:    len(reporting),
		Thresholds: certificatesThresholds{
			Critical: certCritical, Warning: certWarning, Notice: certNotice,
		},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// certificateResponse is what GET /api/certificates/{fingerprint} answers.
type certificateResponse struct {
	Certificate certificateRow `json:"certificate"`
}

// handleCertificate returns one certificate with the endpoints it is
// installed on. Split from the list because that is where the bulk lives:
// a root CA sits on every endpoint, so its locations alone are larger than
// the entire list of certificates without them.
//
// It re-aggregates from the same cached sensor data rather than reading a
// stored row, because there is no stored row — the certificate inventory is
// derived, and deriving it twice is cheaper than keeping a second copy of
// it correct.
func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	want := r.PathValue("fingerprint")
	all, err := s.certificateRows(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, c := range all {
		if strings.EqualFold(c.Fingerprint, want) {
			writeJSONResponse(w, certificateResponse{Certificate: c})
			return
		}
	}
	http.Error(w, "no certificate with that fingerprint is reported by any endpoint", http.StatusNotFound)
}

// certCoverageRow is an entry of what GET /api/certificates/coverage
// answers.
type certCoverageRow struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Count    int    `json:"count"`
	Reported bool   `json:"reported"`
}

// certificateCoverageResponse is what GET /api/certificates/coverage
// answers.
type certificateCoverageResponse struct {
	Coverage []certCoverageRow `json:"coverage"`
}

// handleCertificateHosts answers "which endpoints have not reported any
// certificates?" — the blind spots. An endpoint missing from the
// inventory is not the same as an endpoint with no certificates, and
// treating them alike is how a expiring cert goes unseen.
func (s *Server) handleCertificateCoverage(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := s.store.ListSensorDataForSensor(r.Context(), string(proto.SensorCertificates))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	reported := map[string]int{}
	for _, row := range rows {
		var certs []proto.CertificateInfo
		if err := json.Unmarshal(row.Data, &certs); err != nil {
			continue
		}
		reported[row.AgentID] = len(certs)
	}

	out := make([]certCoverageRow, 0, len(agents))
	for _, a := range agents {
		count, ok := reported[a.AgentID]
		out = append(out, certCoverageRow{
			AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS,
			Count: count, Reported: ok,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reported != out[j].Reported {
			return !out[i].Reported // blind spots first
		}
		return strings.ToLower(out[i].Hostname) < strings.ToLower(out[j].Hostname)
	})
	writeJSONResponse(w, certificateCoverageResponse{Coverage: out})
}
