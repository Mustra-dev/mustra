package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Compliance by control: the same results the Findings view shows, turned
// around to answer an assessor's question — for NIST SP 800-53 (or 800-171,
// CMMC, HIPAA…), which controls have evidence, and where it fails. The
// mapping comes from the benchmark itself (the CIS content's `compliance:`
// block); mustra does not invent one, so a control with no mapped check is
// simply not in the report rather than reported as met.

// frameworkLabels names the frameworks CIS content maps to. Anything else a
// file carries is still reported, under its own key.
var frameworkLabels = map[string]string{
	"nist_800_53":       "NIST SP 800-53 Rev. 5",
	"nist_800_171":      "NIST SP 800-171",
	"cmmc":              "CMMC 2.0",
	"fedramp":           "FedRAMP",
	"hipaa":             "HIPAA Security Rule",
	"gdpr":              "GDPR",
	"iso_27001":         "ISO/IEC 27001:2022",
	"nis2":              "NIS2",
	"pci_dss":           "PCI DSS",
	"cis":               "CIS Benchmark",
	"cis_csc":           "CIS Controls",
	"cis_csc_v7":        "CIS Controls v7",
	"cis_csc_v8":        "CIS Controls v8",
	"soc_2":             "SOC 2",
	"tsc":               "SOC 2 Trust Services Criteria",
	"mitre_mitigations": "MITRE ATT&CK mitigations",
}

// nist80053Families are the twenty control families of SP 800-53 Rev. 5.
var nist80053Families = map[string]string{
	"AC": "Access Control", "AT": "Awareness and Training", "AU": "Audit and Accountability",
	"CA": "Assessment, Authorization, and Monitoring", "CM": "Configuration Management",
	"CP": "Contingency Planning", "IA": "Identification and Authentication", "IR": "Incident Response",
	"MA": "Maintenance", "MP": "Media Protection", "PE": "Physical and Environmental Protection",
	"PL": "Planning", "PM": "Program Management", "PS": "Personnel Security",
	"PT": "PII Processing and Transparency", "RA": "Risk Assessment",
	"SA": "System and Services Acquisition", "SC": "System and Communications Protection",
	"SI": "System and Information Integrity", "SR": "Supply Chain Risk Management",
}

// nist800171Families are SP 800-171's requirement families (3.1–3.14 in
// Rev. 2; Rev. 3 adds 3.15–3.17).
var nist800171Families = map[string]string{
	"3.1": "Access Control", "3.2": "Awareness and Training", "3.3": "Audit and Accountability",
	"3.4": "Configuration Management", "3.5": "Identification and Authentication",
	"3.6": "Incident Response", "3.7": "Maintenance", "3.8": "Media Protection",
	"3.9": "Personnel Security", "3.10": "Physical Protection", "3.11": "Risk Assessment",
	"3.12": "Security Assessment", "3.13": "System and Communications Protection",
	"3.14": "System and Information Integrity", "3.15": "Planning",
	"3.16": "System and Services Acquisition", "3.17": "Supply Chain Risk Management",
}

// controlFamily is the family a control belongs to, and its name when the
// framework is one mustra knows: "AC-6(1)" is AC, "3.1.5" is 3.1,
// "CM.L2-3.4.7" is CM.
func controlFamily(framework, id string) (string, string) {
	switch framework {
	case "nist_800_53", "fedramp":
		fam, _, _ := strings.Cut(id, "-")
		fam = strings.ToUpper(strings.TrimSpace(fam))
		return fam, nist80053Families[fam]
	case "nist_800_171":
		parts := strings.SplitN(id, ".", 3)
		if len(parts) >= 2 {
			fam := parts[0] + "." + parts[1]
			return fam, nist800171Families[fam]
		}
	case "cmmc":
		fam, _, _ := strings.Cut(id, ".")
		return fam, nist80053Families[fam]
	}
	if i := strings.IndexAny(id, ".-_"); i > 0 {
		return id[:i], ""
	}
	return id, ""
}

// controlOrder sorts control IDs the way they are printed in their
// catalogue: AC-2 before AC-11, 3.1.2 before 3.1.10.
func controlLess(a, b string) bool {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '.' || r == '(' || r == ')' || r == '_' })
	}
	pa, pb := split(a), split(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		switch {
		case ea == nil && eb == nil && na != nb:
			return na < nb
		case (ea != nil || eb != nil) && pa[i] != pb[i]:
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

// controlCheck is one benchmark check that provides evidence for a
// control, with its results across the fleet.
type controlCheck struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	CheckID    string `json:"check_id"`
	Title      string `json:"title"`
	Severity   string `json:"severity,omitempty"`
	Pass       int    `json:"pass"`
	Fail       int    `json:"fail"`
	Unknown    int    `json:"unknown"`
	Excepted   int    `json:"excepted"`
}

// complianceControl is one control and the evidence for it. State is
// "fail" when a mapped check fails anywhere, "unknown" when none fails
// but one could not be evaluated, "pass" when every result passed, and
// "untested" when its checks have not run on any endpoint yet. An
// exception neither passes nor fails a control.
type complianceControl struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// EndpointsFailing and EndpointsAssessed count endpoints, not results:
	// one endpoint failing three checks for the control counts once.
	EndpointsFailing  int            `json:"endpoints_failing"`
	EndpointsAssessed int            `json:"endpoints_assessed"`
	Checks            []controlCheck `json:"checks"`
}

// complianceFamily groups controls the way the catalogue does.
type complianceFamily struct {
	ID       string              `json:"id"`
	Name     string              `json:"name,omitempty"`
	Fail     int                 `json:"fail"`
	Unknown  int                 `json:"unknown"`
	Pass     int                 `json:"pass"`
	Untested int                 `json:"untested"`
	Controls []complianceControl `json:"controls"`
}

// complianceFramework is one framework the loaded benchmarks map to.
type complianceFramework struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Controls int    `json:"controls"`
}

// complianceControlsResponse is what GET /api/compliance/controls answers.
type complianceControlsResponse struct {
	Framework  string                `json:"framework"`
	Label      string                `json:"label"`
	Frameworks []complianceFramework `json:"frameworks"`
	Families   []complianceFamily    `json:"families"`
	// UnmappedPolicies are benchmarks whose checks carry no mapping at
	// all, most likely imported before mustra read them; importing the
	// file again adds them.
	UnmappedPolicies []string  `json:"unmapped_policies"`
	GeneratedAt      time.Time `json:"generated_at"`
}

func (s *Server) complianceControls(ctx context.Context, framework, policyFilter string) (complianceControlsResponse, error) {
	out := complianceControlsResponse{Framework: framework, Frameworks: []complianceFramework{}, Families: []complianceFamily{},
		UnmappedPolicies: []string{}, GeneratedAt: time.Now().UTC()}
	policies, err := s.store.ListCompliancePolicies(ctx)
	if err != nil {
		return out, err
	}
	results, err := s.store.ListComplianceResults(ctx)
	if err != nil {
		return out, err
	}
	s.loadExceptions(ctx).apply(results)

	type key struct{ policy, check string }
	byCheck := map[key][]store.ComplianceResult{}
	for _, r := range results {
		byCheck[key{r.PolicyID, r.CheckID}] = append(byCheck[key{r.PolicyID, r.CheckID}], r)
	}

	frameworkControls := map[string]map[string]bool{}
	controls := map[string]*complianceControl{}
	failing := map[string]map[string]bool{}
	assessed := map[string]map[string]bool{}
	for _, lp := range policies {
		if policyFilter != "" && lp.ID != policyFilter {
			continue
		}
		p, err := s.store.GetCompliancePolicy(ctx, lp.ID)
		if err != nil || p == nil {
			continue
		}
		var checks []proto.ComplianceCheck
		if json.Unmarshal(p.Checks, &checks) != nil {
			continue
		}
		mapped := false
		for _, c := range checks {
			for fw, ids := range c.Controls {
				mapped = true
				if frameworkControls[fw] == nil {
					frameworkControls[fw] = map[string]bool{}
				}
				for _, id := range ids {
					frameworkControls[fw][id] = true
				}
			}
			for _, id := range c.Controls[framework] {
				ctl := controls[id]
				if ctl == nil {
					ctl = &complianceControl{ID: id}
					controls[id], failing[id], assessed[id] = ctl, map[string]bool{}, map[string]bool{}
				}
				cc := controlCheck{PolicyID: p.ID, PolicyName: p.Name, CheckID: c.ID, Title: c.Title, Severity: c.Severity}
				for _, r := range byCheck[key{p.ID, c.ID}] {
					switch r.State {
					case "pass":
						cc.Pass++
					case "fail":
						cc.Fail++
						failing[id][r.AgentID] = true
					case "unknown":
						cc.Unknown++
					default:
						cc.Excepted++
					}
					if r.State == "pass" || r.State == "fail" || r.State == "unknown" {
						assessed[id][r.AgentID] = true
					}
				}
				ctl.Checks = append(ctl.Checks, cc)
			}
		}
		if !mapped && len(checks) > 0 {
			out.UnmappedPolicies = append(out.UnmappedPolicies, p.Name)
		}
	}

	for fw, ids := range frameworkControls {
		label := frameworkLabels[fw]
		if label == "" {
			label = fw
		}
		out.Frameworks = append(out.Frameworks, complianceFramework{ID: fw, Label: label, Controls: len(ids)})
	}
	// NIST first, as the reason this report exists; then by name.
	rank := func(k string) int {
		switch k {
		case "nist_800_53":
			return 0
		case "nist_800_171":
			return 1
		}
		return 2
	}
	sort.Slice(out.Frameworks, func(i, j int) bool {
		a, b := out.Frameworks[i], out.Frameworks[j]
		if rank(a.ID) != rank(b.ID) {
			return rank(a.ID) < rank(b.ID)
		}
		return a.Label < b.Label
	})
	if out.Label = frameworkLabels[framework]; out.Label == "" {
		out.Label = framework
	}

	families := map[string]*complianceFamily{}
	for id, ctl := range controls {
		var f, p, u int
		for _, c := range ctl.Checks {
			f, p, u = f+c.Fail, p+c.Pass, u+c.Unknown
		}
		switch {
		case f > 0:
			ctl.State = "fail"
		case u > 0:
			ctl.State = "unknown"
		case p > 0:
			ctl.State = "pass"
		default:
			ctl.State = "untested"
		}
		ctl.EndpointsFailing, ctl.EndpointsAssessed = len(failing[id]), len(assessed[id])
		sort.Slice(ctl.Checks, func(i, j int) bool {
			if ctl.Checks[i].Fail != ctl.Checks[j].Fail {
				return ctl.Checks[i].Fail > ctl.Checks[j].Fail
			}
			return ctl.Checks[i].Title < ctl.Checks[j].Title
		})
		famID, famName := controlFamily(framework, id)
		fam := families[famID]
		if fam == nil {
			fam = &complianceFamily{ID: famID, Name: famName}
			families[famID] = fam
		}
		switch ctl.State {
		case "fail":
			fam.Fail++
		case "unknown":
			fam.Unknown++
		case "pass":
			fam.Pass++
		default:
			fam.Untested++
		}
		fam.Controls = append(fam.Controls, *ctl)
	}
	for _, fam := range families {
		sort.Slice(fam.Controls, func(i, j int) bool { return controlLess(fam.Controls[i].ID, fam.Controls[j].ID) })
		out.Families = append(out.Families, *fam)
	}
	sort.Slice(out.Families, func(i, j int) bool { return controlLess(out.Families[i].ID, out.Families[j].ID) })
	return out, nil
}

// controlsQuery reads the framework (default NIST SP 800-53) and an
// optional policy filter.
func controlsQuery(r *http.Request) (string, string) {
	fw := normalizeFramework(r.URL.Query().Get("framework"))
	if fw == "" {
		fw = "nist_800_53"
	}
	return fw, r.URL.Query().Get("policy_id")
}

func (s *Server) handleComplianceControls(w http.ResponseWriter, r *http.Request) {
	fw, policy := controlsQuery(r)
	out, err := s.complianceControls(r.Context(), fw, policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, out)
}

// handleComplianceControlsCSV is the same report as a spreadsheet: one
// row per control and check, for an assessor's evidence binder.
func (s *Server) handleComplianceControlsCSV(w http.ResponseWriter, r *http.Request) {
	fw, policy := controlsQuery(r)
	out, err := s.complianceControls(r.Context(), fw, policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="controls-%s-%s.csv"`, fw, out.GeneratedAt.Format("2006-01-02")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"framework", "family", "family_name", "control", "control_state", "endpoints_failing", "endpoints_assessed",
		"benchmark", "check", "title", "severity", "pass", "fail", "unknown", "excepted"})
	for _, fam := range out.Families {
		for _, c := range fam.Controls {
			for _, ch := range c.Checks {
				_ = cw.Write([]string{out.Label, fam.ID, fam.Name, c.ID, c.State, strconv.Itoa(c.EndpointsFailing), strconv.Itoa(c.EndpointsAssessed),
					csvSafe(ch.PolicyName), ch.CheckID, csvSafe(ch.Title), ch.Severity,
					strconv.Itoa(ch.Pass), strconv.Itoa(ch.Fail), strconv.Itoa(ch.Unknown), strconv.Itoa(ch.Excepted)})
			}
		}
	}
	cw.Flush()
}
