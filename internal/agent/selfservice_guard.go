package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"html"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/mustra-dev/mustra/internal/selfservice"
)

// Guarding the loopback Self Service API.
//
// "It listens on loopback, so whoever reaches it is at the machine" missed
// the browser. Any web page the user visits can send a form-encoded or
// text/plain POST to 127.0.0.1 without a CORS preflight, and a DNS
// rebinding page can even read the answers — and these endpoints install
// software and start an agent update as root. So, on every request:
//
//   - Host must name this listener (127.0.0.1:<port> or localhost:<port>):
//     a rebinding page arrives with its own hostname in Host.
//   - A POST must carry the per-launch token in X-Mustra-Token. The token
//     is minted when the agent starts, embedded in the window it serves,
//     and available from GET /api/session to local processes (the tray,
//     the menu bar helper). A cross-origin page can neither read the window
//     nor that response, so it cannot learn it.
//   - A POST's Origin, when the browser sends one, must be this listener.
//   - A POST's body must be declared application/json, which a page cannot
//     send cross-origin without a preflight this server never answers.
//
// What this does not stop is another program running as a local user —
// which could equally run the window itself; Self Service is for whoever
// is at the machine, and the server still decides what any request may do.

const selfServiceTokenHeader = "X-Mustra-Token"

func newSelfServiceToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

type selfServiceGuard struct {
	token string
	hosts map[string]bool // acceptable Host header values
	next  http.Handler
}

func newSelfServiceGuard(addr, token string, next http.Handler) *selfServiceGuard {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		port = "8137"
	}
	return &selfServiceGuard{token: token, next: next, hosts: map[string]bool{
		"127.0.0.1:" + port: true, "localhost:" + port: true, "[::1]:" + port: true,
	}}
}

func (g *selfServiceGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	if !g.hosts[strings.ToLower(r.Host)] {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if origin := r.Header.Get("Origin"); origin != "" {
			o := strings.TrimPrefix(strings.ToLower(origin), "http://")
			if !g.hosts[o] {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(selfServiceTokenHeader)), []byte(g.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	}
	g.next.ServeHTTP(w, r)
}

// withSelfServiceToken embeds the token in the window and makes every POST
// the window's script sends carry it, with a JSON content type, without the
// page itself (internal/selfservice) having to know about either.
func withSelfServiceToken(page []byte, token string) []byte {
	inject := []byte(`<meta name="mustra-session" content="` + html.EscapeString(token) + `">` +
		`<script>(function(){var t=document.querySelector('meta[name="mustra-session"]').content;var f=window.fetch;` +
		`window.fetch=function(u,o){o=o||{};var m=(o.method||'GET').toUpperCase();if(m!=='GET'&&m!=='HEAD'){` +
		`var h=new Headers(o.headers||{});h.set('X-Mustra-Token',t);if(!h.has('Content-Type')){h.set('Content-Type','application/json');}` +
		`o.headers=h;}return f.call(this,u,o);};})();</script>`)
	if i := bytes.Index(bytes.ToLower(page), []byte("<head>")); i >= 0 {
		i += len("<head>")
		out := make([]byte, 0, len(page)+len(inject))
		out = append(out, page[:i]...)
		out = append(out, inject...)
		return append(out, page[i:]...)
	}
	return append(inject, page...)
}

// selfServiceCSP is the window's policy; see selfservice.CSP.
func selfServiceCSP(nonce string) string { return selfservice.CSP(nonce, "'none'") }

// withScriptNonce marks every script and style element with the nonce.
func withScriptNonce(page []byte, nonce string) []byte { return selfservice.WithNonce(page, nonce) }
