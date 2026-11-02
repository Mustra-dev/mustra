package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Console notifications. See internal/store/notifications.go for why these
// exist alongside the audit log rather than instead of it.

// notify raises a notification. It never returns an error and never blocks
// the thing that raised it: a deployment must not fail because the console
// could not tell somebody about it.
func (s *Server) notify(ctx context.Context, severity, source, title, body, link string) {
	s.notifyWithActions(ctx, severity, source, title, body, link, nil)
}

// notifyRequest raises a notification for something waiting on a
// decision, with Approve and Deny buttons for chat integrations that open
// /approve for that one request.
func (s *Server) notifyRequest(ctx context.Context, severity, source, title, body, link, kind, id string, canDeny bool) {
	base := "/approve?kind=" + url.QueryEscape(kind) + "&id=" + url.QueryEscape(id)
	actions := []eventAction{{Label: "Approve", Link: base + "&decision=approve", Style: "primary"}}
	if canDeny {
		actions = append(actions, eventAction{Label: "Deny", Link: base + "&decision=deny", Style: "danger"})
	}
	actions = append(actions, eventAction{Label: "Details", Link: base})
	s.notifyWithActions(ctx, severity, source, title, body, link, actions)
}

func (s *Server) notifyWithActions(ctx context.Context, severity, source, title, body, link string, actions []eventAction) {
	n := store.Notification{
		ID: idgen.New("ntf-"), Severity: severity, Title: title,
		Body: body, Source: source, Link: link,
	}
	if err := s.store.CreateNotification(ctx, n); err != nil {
		s.logger.Warn("could not raise notification", "title", title, "error", err)
		return
	}
	// Anything that can start a playbook hangs off this one call, because
	// this is the one place a Guide item is raised. Detached and
	// best-effort: a trigger that cannot start must never stop the operator
	// being told, which is the part that always matters.
	go s.fireEventTriggers(context.WithoutCancel(ctx), n)
	s.emitEvent(integrationEvent{Type: "alert", Title: title, Body: body, Severity: severity, Link: link,
		Detail: map[string]any{"source": source}, Actions: actions})
}

// listNotificationsResponse is what GET /api/notifications answers.
type listNotificationsResponse struct {
	Notifications []store.Notification `json:"notifications"`
	Unread        int                  `json:"unread"`
}

func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r.Context())
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	items, unread, err := s.store.ListNotifications(r.Context(), u.ID, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if items == nil {
		items = []store.Notification{}
	}
	writeJSONResponse(w, listNotificationsResponse{Notifications: items, Unread: unread})
}

// notificationCountResponse is what GET /api/notifications/count answers.
type notificationCountResponse struct {
	Unread int `json:"unread"`
}

// handleNotificationCount backs the badge, which is polled. Kept separate
// from the list so refreshing a number does not fetch fifty rows.
func (s *Server) handleNotificationCount(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r.Context())
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	n, err := s.store.UnreadNotificationCount(r.Context(), u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, notificationCountResponse{Unread: n})
}

func (s *Server) handleReadNotification(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r.Context())
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var err error
	if id == "all" {
		err = s.store.MarkAllNotificationsRead(r.Context(), u.ID)
	} else {
		err = s.store.MarkNotificationRead(r.Context(), u.ID, id)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
