package agent

import (
	"context"
	"path/filepath"
	"time"

	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/proto"
)

func (a *Agent) queryActionLogs(ctx context.Context, job string) proto.AgentCommandResult {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, e := deploylog.Read(ctx, filepath.Join(filepath.Dir(a.cfg.DataDir), "deploy", "logs"), deploylog.ReadOptions{JobID: job, Limit: 500, Bytes: 256 << 10})
	if e != nil {
		return proto.AgentCommandResult{Error: e.Error()}
	}
	return proto.AgentCommandResult{OK: true, ActionLogs: out.Events, LogsTruncated: out.Truncated}
}
