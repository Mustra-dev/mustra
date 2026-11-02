//go:build !linux && !windows && !darwin

package agent

import "context"

func readIdentity(context.Context) machineIdentity { return machineIdentity{} }
