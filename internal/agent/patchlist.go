package agent

import (
	"context"
	"encoding/json"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// fetchPatchListOverride asks the server whether this agent has a Scan
// Management patch list assigned to it. A short timeout and a silent
// fall-through to (no override) on any failure is deliberate: this must
// never block or break the ordinary patches sensor collection just because
// the server is briefly unreachable — the agent already handles that
// gracefully everywhere else (see internal/agent/agent.go's register
// retry/backoff).
func fetchPatchListOverride(ctx context.Context, nc *gonats.Conn, agentID string) proto.PatchListReply {
	if noRemoteCodeActive.Load() {
		return proto.PatchListReply{}
	}
	if nc == nil || agentID == "" {
		return proto.PatchListReply{}
	}
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	payload, err := json.Marshal(proto.PatchListQuery{})
	if err != nil {
		return proto.PatchListReply{}
	}
	msg, err := nc.RequestWithContext(rctx, bnats.PatchListQuery(agentID), payload)
	if err != nil {
		return proto.PatchListReply{}
	}
	var reply proto.PatchListReply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return proto.PatchListReply{}
	}
	return reply
}
