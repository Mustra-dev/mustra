//go:build !linux && !windows && !darwin

package agent

import (
	"context"
	"errors"
)

func trustRootOS(context.Context, rootCert, bool) (string, error) {
	return "", errors.New("unsupported: no trust store support on this platform")
}
