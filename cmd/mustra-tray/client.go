// Command mustra-tray is the helper that lives in the logged-in user's
// session, next to the clock.
//
// It exists because of session 0 isolation. The agent is a LocalSystem
// service, and Windows will not let a service draw in somebody's desktop --
// that restriction is the whole point of session 0. So the agent's toast
// has always been msg.exe, which is a grey box from 1999, and nothing
// richer was available to it at any price.
//
// A process in the user's own session has no such problem. This one polls
// the agent over loopback and renders the message as a real Windows toast:
// the product's icon, the operator's own buttons, and the notification
// centre keeping it after it fades.
//
// It is deliberately not a second source of truth. The agent still owns the
// message and the answer; if this helper is not running, the Self Service
// window still has both, exactly as before.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// agentAddr is where the agent's Self Service server listens. Same default
// as the agent's --self-service-addr flag; loopback only, so nothing off
// this machine can reach it.
const agentAddr = "127.0.0.1:8137"

type button struct {
	Label   string `json:"label"`
	Action  string `json:"action"`
	Minutes int    `json:"minutes"`
	Primary bool   `json:"primary"`
}

type notification struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Title           string   `json:"title"`
	Body            string   `json:"body"`
	AllowPostpone   bool     `json:"allow_postpone"`
	PostponeMinutes []int    `json:"postpone_minutes"`
	Buttons         []button `json:"buttons"`
	MinutesLeft     *int     `json:"minutes_left"`
}

type agentState struct {
	Notification *notification `json:"notification"`
	AgentVersion string        `json:"agent_version"`
	Hostname     string        `json:"hostname"`
	Connected    bool          `json:"connected"`
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// The agent requires its per-launch token on every POST (see
// internal/agent/selfservice_guard.go). The tray is a local program, so it
// asks for it; a web page cannot read that answer.
var (
	sessionMu    sync.Mutex
	sessionToken string
)

func agentSession(refresh bool) (string, error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if sessionToken != "" && !refresh {
		return sessionToken, nil
	}
	resp, err := httpClient.Get("http://" + agentAddr + "/api/session")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil || out.Token == "" {
		return "", fmt.Errorf("agent did not hand out a session token (%s)", resp.Status)
	}
	sessionToken = out.Token
	return sessionToken, nil
}

// postLocal POSTs JSON to the agent with the session token, fetching a new
// token once if the agent has restarted since the last one.
func postLocal(path string, body []byte) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := agentSession(attempt > 0)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(http.MethodPost, "http://"+agentAddr+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Mustra-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusForbidden && attempt == 0 {
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("agent refused the request")
}

func fetchState() (*agentState, error) {
	resp, err := httpClient.Get("http://" + agentAddr + "/api/notification")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent returned %s", resp.Status)
	}
	var out agentState
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// answer sends the person's choice back to the agent, which is what records
// it against the deployment. The toast is only ever the surface it was
// clicked on.
func answer(action string, minutes int) error {
	body, err := json.Marshal(map[string]any{"action": action, "postpone_minutes": minutes})
	if err != nil {
		return err
	}
	resp, err := postLocal("/api/notification-response", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var reply struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return err
	}
	if !reply.OK {
		return fmt.Errorf("%s", reply.Error)
	}
	return nil
}

// choices is what the toast offers, and it mirrors the Self Service window
// exactly: the operator's buttons when they defined any, otherwise the
// defaults for the kind. Two surfaces disagreeing about what a message
// offers would be worse than one surface being plain.
func (n *notification) choices() []button {
	if len(n.Buttons) > 0 {
		return n.Buttons
	}
	var out []button
	if n.Kind == "restart" {
		out = append(out, button{Label: "Restart now", Action: "restart_now", Primary: true})
	} else {
		out = append(out, button{Label: "Got it", Action: "acknowledged", Primary: true})
	}
	if n.AllowPostpone {
		for _, m := range n.PostponeMinutes {
			out = append(out, button{Label: postponeLabel(m), Action: "postponed", Minutes: m})
		}
	}
	return out
}

func postponeLabel(m int) string {
	if m >= 60 {
		return fmt.Sprintf("Remind me in %dh", (m+30)/60)
	}
	return fmt.Sprintf("Remind me in %dm", m)
}

// activationURI is what a toast button carries. Windows activates the
// registered handler for the scheme with this string, which is this same
// executable -- see registerProtocol.
func (b button) activationURI() string {
	q := url.Values{}
	q.Set("action", b.Action)
	if b.Action == "postponed" && b.Minutes > 0 {
		q.Set("minutes", fmt.Sprint(b.Minutes))
	}
	return protocolScheme + "://answer?" + q.Encode()
}

// parseActivation reads back what activationURI wrote. Anything it does not
// recognise is ignored rather than guessed at: this arrives from the shell
// as a command-line argument, and acting on a half-understood one would
// mean answering a prompt on the person's behalf.
func parseActivation(arg string) (action string, minutes int, ok bool) {
	u, err := url.Parse(arg)
	if err != nil || u.Scheme != protocolScheme || u.Host != "answer" {
		return "", 0, false
	}
	action = u.Query().Get("action")
	switch action {
	case "acknowledged", "restart_now":
		return action, 0, true
	case "postponed":
		fmt.Sscanf(u.Query().Get("minutes"), "%d", &minutes)
		if minutes <= 0 {
			minutes = 60
		}
		return action, minutes, true
	}
	return "", 0, false
}
