//go:build !linux && !darwin && !windows

package agent

import (
	"context"
	"errors"

	"github.com/mustra-dev/mustra/internal/proto"
)

func jitCreateAccountOS(context.Context, proto.JITAccountJob) (string, error) {
	return "", errors.New("temporary accounts are not supported on this platform")
}

func jitDeleteAccountOS(context.Context, string) (string, error) {
	return "", errors.New("temporary accounts are not supported on this platform")
}

// jitDeleteProfileOS: the home directory goes with the account here, so
// there is never a profile left to retry.
func jitDeleteProfileOS(string) (bool, error) { return true, nil }

func jitOrphanProfilesOS() []string { return nil }
