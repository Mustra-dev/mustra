package server

// /approve: one request that is waiting on a decision, opened from a chat
// message's Approve or Deny button. The page shows what is being asked and
// whether it is still undecided, and decides through the request's own
// API, so the same permissions, self-approval rules and audit apply as in
// the console. Opening the link never decides anything by itself.

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

type approveInfo struct {
	Kind        string      `json:"kind"`
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Facts       [][2]string `json:"facts"`
	State       string      `json:"state"`
	Pending     bool        `json:"pending"`
	CanDeny     bool        `json:"can_deny"`
	RequestedBy string      `json:"requested_by,omitempty"`
	// How the page decides: POST to DecideURL with ApproveBody or DenyBody.
	DecideURL   string `json:"decide_url"`
	ApproveBody string `json:"approve_body"`
	DenyBody    string `json:"deny_body,omitempty"`
	ConsoleLink string `json:"console_link"`
}

var approvePermission = map[string]string{
	"jump": auth.PermJumpApprove, "approval": auth.PermApprovalsDecide,
	"playbook": auth.PermApprovalsDecide, "cert": auth.PermDeployManage,
}

func fmtWhen(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// GET /api/approve-info?kind=&id=
func (s *Server) handleApproveInfo(w http.ResponseWriter, r *http.Request) {
	kind, id := r.URL.Query().Get("kind"), r.URL.Query().Get("id")
	need, ok := approvePermission[kind]
	if !ok || id == "" {
		http.Error(w, "kind must be jump, approval, playbook or cert, with an id", http.StatusBadRequest)
		return
	}
	// The request's details are for those who may decide it.
	u := auth.CurrentUser(r.Context())
	if allowed, err := s.auth.HasPermission(r.Context(), u, need); err != nil || !allowed {
		http.Error(w, "forbidden: deciding this needs the \""+need+"\" permission", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	var info approveInfo
	switch kind {
	case "jump":
		g, err := s.store.GetJumpGrant(ctx, id)
		if err != nil || g == nil {
			http.Error(w, "no such access request", http.StatusNotFound)
			return
		}
		info = approveInfo{Title: g.RequestedBy + " is asking for access to " + g.Hostname, State: g.State, Pending: g.State == "pending",
			CanDeny: true, RequestedBy: g.RequestedBy, DecideURL: "/api/jump/grants/" + g.ID + "/decide",
			ApproveBody: `{"decision":"approve"}`, DenyBody: `{"decision":"deny"}`, ConsoleLink: "/access#jump",
			Facts: [][2]string{{"Endpoint", g.Hostname}, {"Reason", firstNonEmpty(g.Reason, "—")}, {"Policy", g.PolicyName},
				{"Window", strconv.Itoa(g.MaxMinutes) + " minutes from approval"}, {"Requested", fmtWhen(&g.RequestedAt)}}}
	case "approval":
		a, err := s.store.GetApprovalRequest(ctx, id)
		if err != nil || a == nil {
			http.Error(w, "no such approval request", http.StatusNotFound)
			return
		}
		pending := a.State == "pending" && (a.ExpiresAt == nil || time.Now().Before(*a.ExpiresAt))
		info = approveInfo{Title: a.RequestedBy + " is asking for approval: " + a.Summary, State: a.State, Pending: pending,
			CanDeny: true, RequestedBy: a.RequestedBy, DecideURL: "/api/approvals/" + a.ID + "/decide",
			ApproveBody: `{"decision":"approve"}`, DenyBody: `{"decision":"deny"}`, ConsoleLink: "/access#approvals",
			Facts: [][2]string{{"What", a.Summary}, {"Module", a.Module}, {"Endpoints", strconv.Itoa(a.DeviceCount)},
				{"Policy", a.PolicyName}, {"Requested", fmtWhen(&a.RequestedAt)}, {"Expires", fmtWhen(a.ExpiresAt)}}}
	case "playbook":
		p, err := s.store.GetPlaybookPause(ctx, id)
		if err != nil || p == nil {
			http.Error(w, "no such parked playbook run", http.StatusNotFound)
			return
		}
		info = approveInfo{Title: firstNonEmpty(p.PlaybookRun, "A playbook") + " is waiting at “" + p.StepName + "”", State: p.State,
			Pending: p.State == "pending", CanDeny: true, RequestedBy: p.RequestedBy, DecideURL: "/api/playbook-approvals/" + p.RunID,
			ApproveBody: `{"approve":true}`, DenyBody: `{"approve":false}`, ConsoleLink: "/playbooks#approvals",
			Facts: [][2]string{{"Step", p.StepName}, {"Endpoints", strconv.Itoa(len(p.AgentIDs))}, {"Reason", firstNonEmpty(p.Reason, "—")},
				{"Started by", p.RequestedBy}, {"Expires", fmtWhen(p.ExpiresAt)}}}
	case "cert":
		mc, err := s.store.GetManagedCert(ctx, id)
		if err != nil || mc == nil {
			http.Error(w, "no such managed certificate", http.StatusNotFound)
			return
		}
		info = approveInfo{Title: "Renew the certificate " + mc.Name, State: mc.State, Pending: mc.State == "awaiting_approval",
			DecideURL: "/api/certificates/managed/" + mc.ID + "/renew", ApproveBody: `{}`, ConsoleLink: "/certificates#renewal",
			Facts: [][2]string{{"Endpoint", mc.Hostname}, {"Names", strings.Join(mc.Names, ", ")}, {"Certificate authority", certCAs[mc.CA]},
				{"File", mc.CertPath}, {"Expires", fmtWhen(mc.ExpiresAt)}}}
	}
	info.Kind, info.ID = kind, id
	if info.RequestedBy != "" && info.RequestedBy == u.Username {
		info.Facts = append(info.Facts, [2]string{"Note", "you made this request; somebody else has to decide it"})
	}
	writeJSONResponse(w, info)
}
