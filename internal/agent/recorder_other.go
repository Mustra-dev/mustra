//go:build !linux && !darwin && !windows

package agent

import "context"

func startRecorderPlatform(context.Context, *recorder) {}
