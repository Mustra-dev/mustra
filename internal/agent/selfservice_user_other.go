//go:build !darwin && !windows

package agent

import (
	"context"
	"strings"
	"time"
)

// interactiveUser is the person at a graphical or local session, from the
// login records: a display (":0") or local console terminal first, then
// any non-root login. The agent itself runs as root.
func interactiveUser() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	users, err := collectLoggedInUsers(ctx)
	if err != nil {
		return ""
	}
	pick := ""
	for _, u := range users {
		if u.User == "" || u.User == "root" {
			continue
		}
		if strings.HasPrefix(u.Terminal, ":") || strings.HasPrefix(u.Terminal, "tty") || strings.HasPrefix(u.Terminal, "seat") {
			return u.User
		}
		if pick == "" {
			pick = u.User
		}
	}
	return pick
}
