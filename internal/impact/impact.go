// Package impact answers the lateral-movement question: if this account,
// group or endpoint were compromised, what else could an attacker reach?
//
// It joins two things mustra already knows. From the directory: who is a
// member of what, nested as deep as it goes. From each endpoint: who can
// administer it (the local_admins sensor) and who is signed in (the users
// sensor). Together they form one graph -- a session on an endpoint exposes
// that user's credentials, the user's groups grant administration of other
// endpoints, and those endpoints have sessions of their own -- and every
// answer here is a walk over it.
//
// The package is pure: no store, no HTTP, so the graph can be tested
// against a fleet that fits in a test file.
package impact

import (
	"sort"
	"strings"
	"time"
)

// Principal is a user, a group, or a local account. Local accounts are
// scoped to one endpoint ("local:<agent>:<name>") because Alice on one
// machine and Alice on another are different accounts -- unless the finding
// about repeated local account names says otherwise.
type Principal struct {
	ID         string
	Kind       string // user | group | local | local_group
	Name       string
	Domain     string
	Display    string
	Enabled    bool
	AdminCount bool // AD's adminCount: a protected, privileged object
}

// Endpoint is a managed machine. Criticality comes from Risk & Compliance;
// a domain controller is treated as critical whether or not somebody said
// so, because it is.
type Endpoint struct {
	AgentID          string
	Hostname         string
	OS               string
	Online           bool
	Criticality      string
	DomainController bool
}

// Grant is one administrator entry on an endpoint and how it is held.
type Grant struct {
	PrincipalID string
	Via         string
}

// Input is the whole picture, keyed by ID.
type Input struct {
	Principals map[string]Principal
	Members    map[string][]string // group ID -> direct member IDs
	Admins     map[string][]Grant  // agent ID -> grants
	Sessions   map[string][]string // agent ID -> principal IDs signed in
	Endpoints  map[string]Endpoint
}

// Rating is one row of the Users, Groups or Endpoints tables. A row
// carries only its own kind's fields: a user's or a group's row those of
// a principal, an endpoint's row those of an endpoint.
type Rating struct {
	ID     string  `json:"id"`
	Kind   string  `json:"kind"`
	Name   string  `json:"name"`
	Domain string  `json:"domain,omitempty"`
	Level  string  `json:"level"` // critical | high | medium | low | none
	Score  float64 `json:"score"`

	// One of the two is set; encoding/json leaves out a nil one, so an
	// endpoint is not sent as "enabled": false.
	*PrincipalRating
	*EndpointRating
}

// PrincipalRating is what a user's or a group's row adds.
type PrincipalRating struct {
	// Only on a user's or a group's row.
	Controls         int  `json:"controls"`          // endpoints this can administer, directly or through groups
	DirectControls   int  `json:"direct_controls"`   // of those, held by name rather than through a group
	ControlsCritical int  `json:"controls_critical"` // of those, critical or a domain controller
	Sessions         int  `json:"sessions"`          // endpoints where this user is signed in
	MemberUsers      int  `json:"member_users"`      // groups: users inside it, nested
	Enabled          bool `json:"enabled"`
	AdminCount       bool `json:"admin_count"`
}

// EndpointRating is what an endpoint's row adds.
type EndpointRating struct {
	// Only on an endpoint's row.
	Hostname         string `json:"hostname"`
	Criticality      string `json:"criticality,omitempty"`
	DomainController bool   `json:"domain_controller"`
	Online           bool   `json:"online"`
	Admins           int    `json:"admins"`   // users who can administer it, nested groups resolved
	Outbound         int    `json:"outbound"` // endpoints reachable from here through sessions and rights
	Inbound          int    `json:"inbound"`  // endpoints from which this one is reachable
}

// Finding is one of the categories used to locate excessive rights,
// with the object it is about.
type Finding struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"` // critical | high | medium | low
	SubjectID   string `json:"subject_id"`
	SubjectKind string `json:"subject_kind"`
	SubjectName string `json:"subject_name"`
	Count       int    `json:"count"`
	Detail      string `json:"detail"`
}

// Analysis is the computed graph plus the tables read off it.
type Analysis struct {
	Users      []Rating  `json:"users"`
	Groups     []Rating  `json:"groups"`
	Endpoints  []Rating  `json:"endpoints"`
	Findings   []Finding `json:"findings"`
	ComputedAt time.Time `json:"computed_at"`
	Coverage   Coverage  `json:"coverage"`

	in             Input
	groupsOf       map[string]map[string]bool   // principal -> every group it is in, nested
	usersIn        map[string]map[string]bool   // group -> every user in it, nested
	controls       map[string]map[string]string // principal -> endpoint -> how ("Administrators", "via Domain Admins")
	endpointAdmins map[string]map[string]string // endpoint -> user/local principal -> how
	sessionsOf     map[string][]string          // principal -> endpoints with a session
	outbound       map[string]map[string]int    // endpoint -> endpoint -> hops
	inbound        map[string]map[string]int
}

// Coverage says how much of the fleet the analysis could actually see.
type Coverage struct {
	Endpoints      int `json:"endpoints"`
	ReportingAdmin int `json:"reporting_admins"` // endpoints that have published local_admins
	WithSessions   int `json:"with_sessions"`
	DirectoryUsers int `json:"directory_users"`
	Unresolved     int `json:"unresolved_grants"` // admin entries that matched nothing in the directory
}

const maxHops = 6

// Analyze builds the graph and every table.
func Analyze(in Input) *Analysis {
	a := &Analysis{in: in, ComputedAt: time.Now().UTC()}
	a.expandGroups()
	a.computeControls()
	a.computeSessions()
	a.computeReach()
	a.rate()
	a.findings()
	// Empty lists serialise as [] rather than null, so a page never has to
	// special-case "no findings" against "no field".
	if a.Users == nil {
		a.Users = []Rating{}
	}
	if a.Groups == nil {
		a.Groups = []Rating{}
	}
	if a.Endpoints == nil {
		a.Endpoints = []Rating{}
	}
	if a.Findings == nil {
		a.Findings = []Finding{}
	}
	return a
}

// expandGroups: for every principal, the transitive set of groups it is
// in; for every group, the transitive set of users. Cycles in AD group
// nesting exist in real domains, so both walks carry a visited set.
func (a *Analysis) expandGroups() {
	memberOf := map[string][]string{}
	for group, members := range a.in.Members {
		for _, m := range members {
			memberOf[m] = append(memberOf[m], group)
		}
	}
	a.groupsOf = map[string]map[string]bool{}
	for id := range a.in.Principals {
		seen := map[string]bool{}
		stack := append([]string{}, memberOf[id]...)
		for len(stack) > 0 {
			g := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[g] {
				continue
			}
			seen[g] = true
			stack = append(stack, memberOf[g]...)
		}
		a.groupsOf[id] = seen
	}
	a.usersIn = map[string]map[string]bool{}
	for id, p := range a.in.Principals {
		if p.Kind == "group" || p.Kind == "local_group" {
			continue
		}
		for g := range a.groupsOf[id] {
			if a.usersIn[g] == nil {
				a.usersIn[g] = map[string]bool{}
			}
			a.usersIn[g][id] = true
		}
	}
}

// computeControls: who administers which endpoint. A grant to a group is a
// grant to everything nested inside it; the "how" records the path so the
// detail view can say "via Domain Admins" rather than just "yes".
func (a *Analysis) computeControls() {
	a.controls = map[string]map[string]string{}
	a.endpointAdmins = map[string]map[string]string{}
	set := func(p, e, how string) {
		if a.controls[p] == nil {
			a.controls[p] = map[string]string{}
		}
		if _, exists := a.controls[p][e]; !exists {
			a.controls[p][e] = how
		}
	}
	for agent, grants := range a.in.Admins {
		if _, ok := a.in.Endpoints[agent]; !ok {
			continue
		}
		for _, g := range grants {
			p, ok := a.in.Principals[g.PrincipalID]
			if !ok {
				continue
			}
			set(p.ID, agent, g.Via)
			if p.Kind == "group" {
				for u := range a.usersIn[p.ID] {
					set(u, agent, "via "+p.Name)
				}
				// Nested groups control it too, through this one.
				for gid := range a.in.Principals {
					if a.in.Principals[gid].Kind == "group" && a.groupsOf[gid][p.ID] {
						set(gid, agent, "via "+p.Name)
					}
				}
			}
		}
	}
	for p, eps := range a.controls {
		if k := a.in.Principals[p].Kind; k == "group" || k == "local_group" {
			continue
		}
		for e, how := range eps {
			if a.endpointAdmins[e] == nil {
				a.endpointAdmins[e] = map[string]string{}
			}
			a.endpointAdmins[e][p] = how
		}
	}
}

func (a *Analysis) computeSessions() {
	a.sessionsOf = map[string][]string{}
	for agent, ps := range a.in.Sessions {
		if _, ok := a.in.Endpoints[agent]; !ok {
			continue
		}
		for _, p := range ps {
			if _, ok := a.in.Principals[p]; ok {
				a.sessionsOf[p] = append(a.sessionsOf[p], agent)
			}
		}
	}
}

// computeReach: from each endpoint, breadth-first through "a session here
// exposes this user" and "this user administers that endpoint", counting
// hops. Inbound is the transpose.
func (a *Analysis) computeReach() {
	a.outbound = map[string]map[string]int{}
	a.inbound = map[string]map[string]int{}
	for start := range a.in.Endpoints {
		reach := map[string]int{}
		frontier := []string{start}
		for hop := 1; hop <= maxHops && len(frontier) > 0; hop++ {
			var next []string
			for _, e := range frontier {
				for _, u := range a.in.Sessions[e] {
					for target := range a.controls[u] {
						if target == start {
							continue
						}
						if _, seen := reach[target]; !seen {
							reach[target] = hop
							next = append(next, target)
						}
					}
				}
			}
			frontier = next
		}
		a.outbound[start] = reach
		for target, hop := range reach {
			if a.inbound[target] == nil {
				a.inbound[target] = map[string]int{}
			}
			a.inbound[target][start] = hop
		}
	}
}

func weight(e Endpoint) float64 {
	if e.DomainController {
		return 8
	}
	switch strings.ToLower(e.Criticality) {
	case "critical":
		return 8
	case "high":
		return 4
	case "medium":
		return 2
	}
	return 1
}

func (a *Analysis) isCritical(id string) bool {
	e := a.in.Endpoints[id]
	return e.DomainController || strings.EqualFold(e.Criticality, "critical")
}

// level turns a share of the fleet into a word. The thresholds are
// deliberately coarse: an account that can administer a fifth of the
// fleet is a problem whether the fleet is forty machines or forty
// thousand, and a domain controller in reach is critical at any share.
func (a *Analysis) level(count, critical int) string {
	total := len(a.in.Endpoints)
	if total == 0 || count == 0 {
		return "none"
	}
	share := float64(count) / float64(total)
	switch {
	case critical > 0 && (share >= 0.2 || critical >= 2):
		return "critical"
	case share >= 0.5:
		return "critical"
	case share >= 0.2 || critical > 0:
		return "high"
	case share >= 0.05 || count >= 3:
		return "medium"
	default:
		return "low"
	}
}

// byScore sorts rows highest score first, then by name. The ID settles
// the rest: map iteration feeds rows in a different order each analysis,
// and the local "admin" groups of many servers, all at one score, would
// otherwise come back reshuffled, changing which the overview's top rows
// hold.
func byScore(rs []Rating) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Score != rs[j].Score {
			return rs[i].Score > rs[j].Score
		}
		if a, b := strings.ToLower(rs[i].Name), strings.ToLower(rs[j].Name); a != b {
			return a < b
		}
		return rs[i].ID < rs[j].ID
	})
}

func (a *Analysis) rate() {
	for id, p := range a.in.Principals {
		r := Rating{ID: id, Kind: p.Kind, Name: p.Name, Domain: p.Domain,
			PrincipalRating: &PrincipalRating{Enabled: p.Enabled, AdminCount: p.AdminCount}}
		for e, how := range a.controls[id] {
			r.Controls++
			if !strings.HasPrefix(how, "via ") {
				r.DirectControls++
			}
			if a.isCritical(e) {
				r.ControlsCritical++
			}
			r.Score += weight(a.in.Endpoints[e])
		}
		r.Sessions = len(a.sessionsOf[id])
		r.MemberUsers = len(a.usersIn[id])
		r.Level = a.level(r.Controls, r.ControlsCritical)
		if p.Kind == "group" || p.Kind == "local_group" {
			// A group with nobody in it grants nothing to anyone. A local
			// group's membership is reported as its users, not as the
			// group, so it always reads as empty here.
			if r.MemberUsers == 0 {
				r.Level = "none"
			}
			a.Groups = append(a.Groups, r)
		} else {
			a.Users = append(a.Users, r)
		}
	}
	for id, e := range a.in.Endpoints {
		r := Rating{ID: id, Kind: "endpoint", Name: e.Hostname, EndpointRating: &EndpointRating{
			Hostname: e.Hostname, Criticality: e.Criticality, DomainController: e.DomainController, Online: e.Online}}
		r.Admins = len(a.endpointAdmins[id])
		r.Outbound = len(a.outbound[id])
		r.Inbound = len(a.inbound[id])
		crit := 0
		for t := range a.outbound[id] {
			r.Score += weight(a.in.Endpoints[t])
			if a.isCritical(t) {
				crit++
			}
		}
		r.Level = a.level(r.Outbound, crit)
		a.Endpoints = append(a.Endpoints, r)
	}
	byScore(a.Users)
	byScore(a.Groups)
	byScore(a.Endpoints)

	a.Coverage.Endpoints = len(a.in.Endpoints)
	for e := range a.in.Endpoints {
		if _, ok := a.in.Admins[e]; ok {
			a.Coverage.ReportingAdmin++
		}
		if len(a.in.Sessions[e]) > 0 {
			a.Coverage.WithSessions++
		}
	}
	for _, p := range a.in.Principals {
		if p.Kind == "user" {
			a.Coverage.DirectoryUsers++
		}
	}
}

// findings are the categories: the shapes of excessive rights that an
// analyst would look for by hand, each attached to the object to fix.
func (a *Analysis) findings() {
	total := len(a.in.Endpoints)
	share := func(n int) float64 {
		if total == 0 {
			return 0
		}
		return float64(n) / float64(total)
	}
	add := func(f Finding) { a.Findings = append(a.Findings, f) }

	// Privileged credentials exposed on ordinary machines: a member of a
	// protected group (adminCount) signed in somewhere that is not a
	// domain controller. Whoever administers that machine can take the
	// credential, and with it everything the group can reach.
	for _, u := range a.Users {
		if u.Kind != "user" {
			continue
		}
		privileged := u.AdminCount
		for g := range a.groupsOf[u.ID] {
			if a.in.Principals[g].AdminCount {
				privileged = true
			}
		}
		if !privileged {
			continue
		}
		n := 0
		var where []string
		for _, e := range a.sessionsOf[u.ID] {
			if !a.in.Endpoints[e].DomainController {
				n++
				where = append(where, a.in.Endpoints[e].Hostname)
			}
		}
		if n > 0 {
			sort.Strings(where)
			add(Finding{Category: "Privileged account signed in outside the domain controllers", Severity: "critical",
				SubjectID: u.ID, SubjectKind: "user", SubjectName: u.Name, Count: n,
				Detail: "Signed in on " + strings.Join(where, ", ") + "; anyone who administers those machines can take this credential."})
		}
	}

	// Broad administration: one account that can administer a large share
	// of the fleet -- or, a different thing, the machines that matter most.
	for _, u := range a.Users {
		if u.Kind != "user" {
			continue
		}
		switch {
		case share(u.Controls) >= 0.2:
			sev := "high"
			if share(u.Controls) >= 0.5 {
				sev = "critical"
			}
			add(Finding{Category: "Account administers a large share of the fleet", Severity: sev,
				SubjectID: u.ID, SubjectKind: "user", SubjectName: u.Name, Count: u.Controls,
				Detail: describeShare(u.Controls, total, u.ControlsCritical)})
		case u.ControlsCritical >= 2:
			add(Finding{Category: "Account administers more than one critical endpoint", Severity: "high",
				SubjectID: u.ID, SubjectKind: "user", SubjectName: u.Name, Count: u.ControlsCritical,
				Detail: describeShare(u.Controls, total, u.ControlsCritical) + ". One credential reaches every one of them."})
		}
	}
	for _, g := range a.Groups {
		if share(g.Controls) >= 0.2 && g.MemberUsers > 0 {
			sev := "medium"
			if share(g.Controls) >= 0.5 && g.MemberUsers >= 3 {
				sev = "high"
			}
			add(Finding{Category: "Group grants administration broadly", Severity: sev,
				SubjectID: g.ID, SubjectKind: "group", SubjectName: g.Name, Count: g.Controls,
				Detail: describeShare(g.Controls, total, g.ControlsCritical) + "; " + itoa(g.MemberUsers) + " user(s) inherit that."})
		}
	}

	// Disabled accounts that still hold rights: nobody signs in as them,
	// but the grant is still there for whoever re-enables the account.
	for _, u := range a.Users {
		if u.Kind == "user" && !u.Enabled && u.Controls > 0 {
			add(Finding{Category: "Disabled account still administers endpoints", Severity: "medium",
				SubjectID: u.ID, SubjectKind: "user", SubjectName: u.Name, Count: u.Controls,
				Detail: "The account is disabled in the directory but is still an administrator on " + itoa(u.Controls) + " endpoint(s)."})
		}
	}

	// The same local account name on many endpoints: usually the same
	// password too, which makes one machine's admin every machine's.
	byName := map[string][]string{}
	for _, p := range a.in.Principals {
		// Accounts only: a local group named sudo on every Linux machine
		// is how distributions work, not a shared password.
		if p.Kind == "local" && a.controls[p.ID] != nil && !strings.EqualFold(p.Name, "root") && !strings.EqualFold(p.Name, "Administrator") {
			byName[strings.ToLower(p.Name)] = append(byName[strings.ToLower(p.Name)], p.ID)
		}
	}
	for name, ids := range byName {
		if len(ids) >= 3 {
			sort.Strings(ids)
			add(Finding{Category: "Local administrator name repeated across endpoints", Severity: "medium",
				SubjectID: ids[0], SubjectKind: "local", SubjectName: name, Count: len(ids),
				Detail: "A local account called " + name + " administers " + itoa(len(ids)) + " endpoints. If the password is shared, so is the access."})
		}
	}

	// Endpoints that many others can reach.
	for _, e := range a.Endpoints {
		if share(e.Inbound) >= 0.2 && (e.DomainController || strings.EqualFold(e.Criticality, "critical") || strings.EqualFold(e.Criticality, "high")) {
			add(Finding{Category: "Critical endpoint reachable from much of the fleet", Severity: "high",
				SubjectID: e.ID, SubjectKind: "endpoint", SubjectName: e.Hostname, Count: e.Inbound,
				Detail: "A compromise of any of " + itoa(e.Inbound) + " endpoints leads here through sessions and administrative rights."})
		}
	}

	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(a.Findings, func(i, j int) bool {
		if order[a.Findings[i].Severity] != order[a.Findings[j].Severity] {
			return order[a.Findings[i].Severity] < order[a.Findings[j].Severity]
		}
		return a.Findings[i].Count > a.Findings[j].Count
	})
}

func describeShare(n, total, critical int) string {
	s := "Administers " + itoa(n) + " of " + itoa(total) + " endpoints"
	if critical > 0 {
		s += ", " + itoa(critical) + " of them critical or a domain controller"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ---- detail and paths ----

// ControlRow is one edge in a detail view.
type ControlRow struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Hostname    string `json:"hostname,omitempty"`
	How         string `json:"how"`
	Criticality string `json:"criticality,omitempty"`
	DC          bool   `json:"domain_controller,omitempty"`
}

// Reach is an endpoint reachable in N hops.
type Reach struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	Hops        int    `json:"hops"`
	Criticality string `json:"criticality,omitempty"`
	DC          bool   `json:"domain_controller,omitempty"`
}

// Detail is everything about one object, across its tabs.
type Detail struct {
	Rating          Rating       `json:"rating"`
	DirectControl   []ControlRow `json:"direct_control"`   // principals: endpoints by name; endpoints: principals by name
	IndirectControl []ControlRow `json:"indirect_control"` // through groups
	Outbound        []Reach      `json:"outbound"`
	Inbound         []Reach      `json:"inbound"`
	Sessions        []ControlRow `json:"sessions"` // principals: where signed in; endpoints: who is signed in
	Members         []Rating     `json:"members"`  // groups
	MemberOf        []Rating     `json:"member_of"`
}

func (a *Analysis) ratingOf(id string) (Rating, bool) {
	for _, list := range [][]Rating{a.Users, a.Groups, a.Endpoints} {
		for _, r := range list {
			if r.ID == id {
				return r, true
			}
		}
	}
	return Rating{}, false
}

func (a *Analysis) endpointRow(e string, how string) ControlRow {
	ep := a.in.Endpoints[e]
	return ControlRow{ID: e, Kind: "endpoint", Name: ep.Hostname, Hostname: ep.Hostname, How: how, Criticality: ep.Criticality, DC: ep.DomainController}
}

func (a *Analysis) principalRow(p string, how string) ControlRow {
	pr := a.in.Principals[p]
	return ControlRow{ID: p, Kind: pr.Kind, Name: pr.Name, How: how}
}

func sortRows(rows []ControlRow) {
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name) })
}

// Detail assembles the tabs for a user, group or endpoint.
func (a *Analysis) Detail(id string) (Detail, bool) {
	r, ok := a.ratingOf(id)
	if !ok {
		return Detail{}, false
	}
	d := Detail{Rating: r, DirectControl: []ControlRow{}, IndirectControl: []ControlRow{}, Outbound: []Reach{}, Inbound: []Reach{}, Sessions: []ControlRow{}, Members: []Rating{}, MemberOf: []Rating{}}
	reachList := func(m map[string]int) []Reach {
		out := make([]Reach, 0, len(m))
		for e, hops := range m {
			ep := a.in.Endpoints[e]
			out = append(out, Reach{ID: e, Hostname: ep.Hostname, Hops: hops, Criticality: ep.Criticality, DC: ep.DomainController})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Hops != out[j].Hops {
				return out[i].Hops < out[j].Hops
			}
			return strings.ToLower(out[i].Hostname) < strings.ToLower(out[j].Hostname)
		})
		return out
	}
	if r.Kind == "endpoint" {
		for p, how := range a.endpointAdmins[id] {
			if strings.HasPrefix(how, "via ") {
				d.IndirectControl = append(d.IndirectControl, a.principalRow(p, how))
			} else {
				d.DirectControl = append(d.DirectControl, a.principalRow(p, how))
			}
		}
		// Groups that hold the grant by name, so the fix is visible.
		for _, g := range a.in.Admins[id] {
			if p, ok := a.in.Principals[g.PrincipalID]; ok && p.Kind == "group" {
				d.DirectControl = append(d.DirectControl, a.principalRow(p.ID, g.Via))
			}
		}
		for _, p := range a.in.Sessions[id] {
			if _, ok := a.in.Principals[p]; ok {
				d.Sessions = append(d.Sessions, a.principalRow(p, "signed in"))
			}
		}
		d.Outbound = reachList(a.outbound[id])
		d.Inbound = reachList(a.inbound[id])
	} else {
		for e, how := range a.controls[id] {
			if strings.HasPrefix(how, "via ") {
				d.IndirectControl = append(d.IndirectControl, a.endpointRow(e, how))
			} else {
				d.DirectControl = append(d.DirectControl, a.endpointRow(e, how))
			}
		}
		for _, e := range a.sessionsOf[id] {
			d.Sessions = append(d.Sessions, a.endpointRow(e, "signed in"))
		}
		// What a compromise of this principal reaches: its own controls,
		// then onward through sessions there. Computed as a BFS from a
		// virtual start so the hop counts line up with the endpoint view.
		reach := map[string]int{}
		frontier := []string{}
		for e := range a.controls[id] {
			reach[e] = 1
			frontier = append(frontier, e)
		}
		for hop := 2; hop <= maxHops && len(frontier) > 0; hop++ {
			var next []string
			for _, e := range frontier {
				for _, u := range a.in.Sessions[e] {
					for t := range a.controls[u] {
						if _, seen := reach[t]; !seen {
							reach[t] = hop
							next = append(next, t)
						}
					}
				}
			}
			frontier = next
		}
		d.Outbound = reachList(reach)
		if r.Kind == "group" {
			for u := range a.usersIn[id] {
				if ur, ok := a.ratingOf(u); ok {
					d.Members = append(d.Members, ur)
				}
			}
		}
		for g := range a.groupsOf[id] {
			if gr, ok := a.ratingOf(g); ok {
				d.MemberOf = append(d.MemberOf, gr)
			}
		}
		byScore(d.Members)
		byScore(d.MemberOf)
	}
	sortRows(d.DirectControl)
	sortRows(d.IndirectControl)
	sortRows(d.Sessions)
	return d, true
}

// PathStep is one node on a shortest path, with the edge that led to it.
type PathStep struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Edge string `json:"edge,omitempty"` // "signed in on" | "member of" | "administers" | "contains"
}

// ShortestPath walks the full graph -- endpoints, users, groups -- from
// one object to another. Edges: an endpoint exposes its signed-in users;
// a principal is a member of its groups; a principal or group administers
// endpoints it holds a grant on. The path is what an attacker would
// actually do, one step at a time.
func (a *Analysis) ShortestPath(from, to string) []PathStep {
	if from == to {
		return nil
	}
	type edge struct {
		to, label string
	}
	next := func(id string) []edge {
		var out []edge
		if _, ok := a.in.Endpoints[id]; ok {
			for _, u := range a.in.Sessions[id] {
				if _, ok := a.in.Principals[u]; ok {
					out = append(out, edge{u, "signed in on"})
				}
			}
			return out
		}
		for group, members := range a.in.Members {
			for _, m := range members {
				if m == id {
					if _, ok := a.in.Principals[group]; ok {
						out = append(out, edge{group, "member of"})
					}
				}
			}
		}
		for agent, grants := range a.in.Admins {
			if _, ok := a.in.Endpoints[agent]; !ok {
				continue
			}
			for _, g := range grants {
				if g.PrincipalID == id {
					out = append(out, edge{agent, "administers"})
				}
			}
		}
		return out
	}
	prev := map[string]edge{}
	seen := map[string]bool{from: true}
	queue := []string{from}
	found := false
	for len(queue) > 0 && !found {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range next(cur) {
			if seen[e.to] {
				continue
			}
			seen[e.to] = true
			prev[e.to] = edge{cur, e.label}
			if e.to == to {
				found = true
				break
			}
			queue = append(queue, e.to)
		}
	}
	if !found {
		return nil
	}
	var rev []PathStep
	for cur := to; ; {
		rev = append(rev, a.step(cur, prev[cur].label))
		if cur == from {
			break
		}
		cur = prev[cur].to
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	rev[0].Edge = ""
	return rev
}

func (a *Analysis) step(id, edge string) PathStep {
	if e, ok := a.in.Endpoints[id]; ok {
		return PathStep{ID: id, Kind: "endpoint", Name: e.Hostname, Edge: edge}
	}
	p := a.in.Principals[id]
	return PathStep{ID: id, Kind: p.Kind, Name: p.Name, Edge: edge}
}
