//go:build !windows

package agent

import (
	"context"
	"errors"

	"github.com/mustra-dev/mustra/internal/proto"
)

var errNotWindows = errors.New("the Windows certificate store exists only on Windows endpoints")

func winStoreCSR(proto.CertJob) (string, error) { return "", errNotWindows }

func winStoreInstall(context.Context, proto.CertJob) (string, error) { return "", errNotWindows }
