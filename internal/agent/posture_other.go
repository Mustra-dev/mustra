//go:build !windows && !linux && !darwin

package agent

import (
	"context"

	"github.com/mustra-dev/mustra/internal/proto"
)

func collectPosturePlatform(context.Context) proto.SecurityPosture {
	return proto.SecurityPosture{FirewallEngine: "unknown", EncryptionEngine: "unknown", AntivirusEngine: "unknown", AppControlEngine: "unknown"}
}
