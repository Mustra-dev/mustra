//go:build linux

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Linux: logons from the journal. sshd, login, su and sudo all log through
// it on every systemd distribution, and journalctl's cursor makes "only
// what is new since last time" exact rather than time-window guesswork.
// No registry; no DNS without eBPF.
func startRecorderPlatform(ctx context.Context, r *recorder) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return
	}
	r.setSource("logon", "journal")
	go r.journalLogons(ctx)
}

var (
	sshAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	sshFailed   = regexp.MustCompile(`^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	sshInvalid  = regexp.MustCompile(`^Invalid user (\S+) from (\S+)`)
	pamOpened   = regexp.MustCompile(`session opened for user (\S+?)(?:\(uid=\d+\))? by (\S+)?`)
	sudoCommand = regexp.MustCompile(`^\s*(\S+) : .*COMMAND=(.*)$`)
)

func (r *recorder) journalLogons(ctx context.Context) {
	cursor := ""
	tick := time.NewTicker(recorderPollInterval)
	defer tick.Stop()
	for {
		args := []string{"-o", "json", "-q", "--no-pager", "_COMM=sshd", "_COMM=sudo", "_COMM=su", "_COMM=login"}
		if cursor == "" {
			args = append(args, "--since", "-10s")
		} else {
			args = append(args, "--after-cursor="+cursor)
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, err := exec.CommandContext(cctx, "journalctl", args...).Output()
		cancel()
		if err == nil {
			sc := bufio.NewScanner(strings.NewReader(string(out)))
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for sc.Scan() {
				var entry struct {
					Cursor   string `json:"__CURSOR"`
					Comm     string `json:"_COMM"`
					Message  any    `json:"MESSAGE"`
					Realtime string `json:"__REALTIME_TIMESTAMP"`
				}
				if json.Unmarshal(sc.Bytes(), &entry) != nil {
					continue
				}
				cursor = entry.Cursor
				msg, _ := entry.Message.(string)
				if ev, ok := logonFromJournal(entry.Comm, msg); ok {
					r.emit(ev)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func logonFromJournal(comm, msg string) (proto.RecorderEvent, bool) {
	ev := proto.RecorderEvent{Kind: "logon", Process: comm}
	switch comm {
	case "sshd":
		if m := sshAccepted.FindStringSubmatch(msg); m != nil {
			ev.Op, ev.User, ev.Source, ev.LogonType = "success", m[2], m[3], "ssh-"+m[1]
			ev.Summary = "ssh " + m[2] + " from " + m[3] + " (" + m[1] + ")"
			return ev, true
		}
		if m := sshFailed.FindStringSubmatch(msg); m != nil {
			ev.Op, ev.User, ev.Source, ev.LogonType, ev.Reason = "failure", m[2], m[3], "ssh-"+m[1], "failed "+m[1]
			ev.Summary = "ssh failure for " + m[2] + " from " + m[3]
			return ev, true
		}
		if m := sshInvalid.FindStringSubmatch(msg); m != nil {
			ev.Op, ev.User, ev.Source, ev.LogonType, ev.Reason = "failure", m[1], m[2], "ssh", "invalid user"
			ev.Summary = "ssh invalid user " + m[1] + " from " + m[2]
			return ev, true
		}
	case "sudo":
		if m := sudoCommand.FindStringSubmatch(msg); m != nil {
			ev.Op, ev.User, ev.LogonType, ev.Source = "success", m[1], "sudo", "local"
			ev.Summary = "sudo by " + m[1] + ": " + strings.TrimSpace(m[2])
			return ev, true
		}
		if strings.Contains(msg, "incorrect password attempt") || strings.Contains(msg, "authentication failure") {
			user := ""
			if i := strings.Index(msg, " : "); i > 0 {
				user = strings.TrimSpace(msg[:i])
			}
			ev.Op, ev.User, ev.LogonType, ev.Source, ev.Reason = "failure", user, "sudo", "local", "bad password"
			ev.Summary = "sudo failure by " + user
			return ev, true
		}
	case "su", "login":
		if m := pamOpened.FindStringSubmatch(msg); m != nil {
			ev.Op, ev.User, ev.LogonType, ev.Source = "success", m[1], comm, "local"
			ev.Summary = comm + " session for " + m[1]
			if len(m) > 2 && m[2] != "" {
				ev.Summary += " by " + m[2]
			}
			return ev, true
		}
		if strings.Contains(msg, "FAILED") || strings.Contains(msg, "authentication failure") {
			ev.Op, ev.LogonType, ev.Source, ev.Reason = "failure", comm, "local", "authentication failure"
			ev.Summary = comm + " authentication failure"
			return ev, true
		}
	}
	return ev, false
}
