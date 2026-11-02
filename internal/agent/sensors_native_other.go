//go:build !windows

package agent

import (
	"context"
	"errors"

	"github.com/mustra-dev/mustra/internal/proto"
)

var errWindowsOnly = errors.New("windows only")

func collectServicesNative(context.Context) ([]proto.ServiceInfo, error) { return nil, errWindowsOnly }

type installedAppRaw struct {
	DisplayName, DisplayVersion, Publisher, InstallDate, DisplayIcon string
}

func collectAppsNative(context.Context) ([]installedAppRaw, error) { return nil, errWindowsOnly }
