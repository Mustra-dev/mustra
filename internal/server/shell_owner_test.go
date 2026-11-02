package server

import (
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

func TestShellSessionBoundToOpener(t *testing.T) {
	s := &Server{logger: slog.Default(), syslog: &syslogSink{}}
	sess := &store.ShellSession{ID: "sh-1", AgentID: "agt-1", Hostname: "h", OpenedBy: "alice", OpenedByID: "usr-alice"}
	call := func(u *store.User, takeover bool, tok *auth.TokenInfo) (bool, bool, int) {
		r := httptest.NewRequest("POST", "/api/shell/sessions/sh-1/exec", nil)
		ctx := auth.WithUser(r.Context(), u)
		if tok != nil {
			ctx = auth.WithToken(ctx, []string{auth.PermDeployManage}, tok)
		}
		rec := httptest.NewRecorder()
		tk, ok := s.authorizeShellSession(rec, r.WithContext(ctx), sess, takeover)
		return tk, ok, rec.Code
	}
	if tk, ok, _ := call(&store.User{ID: "usr-alice", Username: "alice"}, false, nil); !ok || tk {
		t.Fatal("the opener was refused")
	}
	// Same username, different account (a rename, or an IdP collision).
	if _, ok, code := call(&store.User{ID: "usr-other", Username: "alice"}, false, nil); ok || code != 403 {
		t.Fatalf("a different account with the opener's username got in (code %d)", code)
	}
	if _, ok, _ := call(&store.User{ID: "usr-bob", Username: "bob"}, true, nil); ok {
		t.Fatal("a non-admin took a session over")
	}
	if _, ok, _ := call(&store.User{ID: "usr-root", Username: "root", IsAdmin: true}, false, nil); ok {
		t.Fatal("an admin got in without asking for a takeover")
	}
	// Tokens all share one synthetic user id; one token must not reach a
	// session another opened.
	sess.OpenedByID = "tok:tok-a"
	if _, ok, _ := call(&store.User{ID: auth.APITokenUserID, Username: "token:b"}, false, &auth.TokenInfo{ID: "tok-b"}); ok {
		t.Fatal("token b used token a's session")
	}
	if _, ok, _ := call(&store.User{ID: auth.APITokenUserID, Username: "token:a"}, false, &auth.TokenInfo{ID: "tok-a"}); !ok {
		t.Fatal("token a was refused its own session")
	}
}
