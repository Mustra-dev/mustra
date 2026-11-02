package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
)

// Cutting off a revoked agent at once.
//
// Revoking an agent's credential stops the broker admitting it, but the
// broker only asks again when the connection's JWT expires: up to an hour.
// The broker's system account can list connections ($SYS.REQ.SERVER.PING.
// CONNZ, answered by every server in a cluster) and close one
// ($SYS.REQ.SERVER.<id>.KICK). The server reaches it as mustra-sys
// (deploy/nats/nats.conf) only when it needs to, and closes the connection
// again. The kicked agent reconnects at once, and the callout refuses it.

var errNoSysAccount = errors.New("MUSTRA_NATS_SYS_PASSWORD is not set: the agent is refused when its current authorization expires (within an hour)")

// kickAgentConnections closes every broker connection authorized as
// agentID and reports how many it closed.
func (s *Server) kickAgentConnections(ctx context.Context, agentID string) (int, error) {
	creds := s.cfg.NATSSysCreds
	if creds.Password == "" {
		return 0, errNoSysAccount
	}
	nc, err := bnats.ConnectWithCreds(s.cfg.NATSURL, "server-sys", creds, s.logger, gonats.MaxReconnects(0), gonats.Timeout(5*time.Second))
	if err != nil {
		return 0, fmt.Errorf("reach the broker's system account: %w", err)
	}
	defer nc.Close()
	targets, err := agentConnections(ctx, nc, agentID)
	if err != nil {
		return 0, err
	}
	kicked := 0
	for _, t := range targets {
		body, _ := json.Marshal(map[string]uint64{"cid": t.cid})
		msg, err := nc.RequestWithContext(ctx, "$SYS.REQ.SERVER."+t.server+".KICK", body)
		if err != nil {
			return kicked, fmt.Errorf("disconnect connection %d: %w", t.cid, err)
		}
		var resp struct {
			Error *struct {
				Description string `json:"description"`
			} `json:"error"`
		}
		if json.Unmarshal(msg.Data, &resp) == nil && resp.Error != nil {
			return kicked, fmt.Errorf("disconnect connection %d: %s", t.cid, resp.Error.Description)
		}
		kicked++
	}
	return kicked, nil
}

type brokerConn struct {
	server string
	cid    uint64
}

// connzPage is the part of a CONNZ answer kicking needs.
type connzPage struct {
	Server struct {
		ID string `json:"id"`
	} `json:"server"`
	Data struct {
		Total       int `json:"total"`
		Offset      int `json:"offset"`
		Connections []struct {
			CID     uint64 `json:"cid"`
			User    string `json:"authorized_user"`
			NameTag string `json:"name_tag"`
		} `json:"connections"`
	} `json:"data"`
	Error *struct {
		Description string `json:"description"`
	} `json:"error"`
}

// agentConnections asks every broker for its open connections and keeps
// those authorized as agentID: the callout admits an agent under its own
// ID as the user name, and names its JWT after it.
func agentConnections(ctx context.Context, nc *gonats.Conn, agentID string) ([]brokerConn, error) {
	const pageSize = 1024
	var out []brokerConn
	for offset := 0; ; offset += pageSize {
		pages, err := gatherConnz(ctx, nc, offset, pageSize)
		if err != nil {
			return nil, err
		}
		more := false
		for _, p := range pages {
			if p.Error != nil {
				return nil, fmt.Errorf("list broker connections: %s", p.Error.Description)
			}
			for _, c := range p.Data.Connections {
				if c.User == agentID || c.NameTag == agentID {
					out = append(out, brokerConn{server: p.Server.ID, cid: c.CID})
				}
			}
			if p.Data.Offset+len(p.Data.Connections) < p.Data.Total {
				more = true
			}
		}
		if !more {
			return out, nil
		}
	}
}

// gatherConnz sends one CONNZ ping and collects the answers that arrive
// within a short window: one per server.
func gatherConnz(ctx context.Context, nc *gonats.Conn, offset, limit int) ([]connzPage, error) {
	inbox := nc.NewRespInbox()
	sub, err := nc.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer sub.Unsubscribe()
	body, _ := json.Marshal(map[string]any{"auth": true, "offset": offset, "limit": limit})
	if err := nc.PublishRequest("$SYS.REQ.SERVER.PING.CONNZ", inbox, body); err != nil {
		return nil, err
	}
	var pages []connzPage
	wait := 3 * time.Second // the first answer
	for {
		wctx, cancel := context.WithTimeout(ctx, wait)
		msg, err := sub.NextMsgWithContext(wctx)
		cancel()
		if err != nil {
			if len(pages) == 0 {
				return nil, fmt.Errorf("list broker connections: no answer from the system account: %w", err)
			}
			return pages, nil
		}
		var p connzPage
		if err := json.Unmarshal(msg.Data, &p); err != nil {
			return nil, fmt.Errorf("list broker connections: %w", err)
		}
		pages = append(pages, p)
		wait = 500 * time.Millisecond // the rest of a cluster
	}
}
