//go:build !linux

package agent

import (
	"context"
	"fmt"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Windows and macOS have no equivalent mustra can use without a great deal
// more machinery — ETW needs a session and a manifest, and macOS's
// EndpointSecurity needs an entitlement Apple grants to a developer account,
// not to a binary. Both fall back to sampling the process table, and the
// batch says so, because "poll" and "netlink" mean different things about
// what an empty feed proves.
func startProcessConnector(context.Context, chan<- proto.ProcessEvent, func(error)) (bool, func(), error) {
	return false, nil, fmt.Errorf("no kernel process-event interface on this platform")
}
