//go:build !darwin

package agent

import (
	"context"
	"fmt"
)

// brewInstall exists only so installPackage compiles on every platform —
// the darwin branch is unreachable anywhere else.
func brewInstall(ctx context.Context, pkg string) (string, error) {
	return "", fmt.Errorf("Homebrew is macOS-only")
}
