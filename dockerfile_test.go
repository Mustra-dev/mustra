package mustra

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// TestDockerfileCopiesAgentPackages keeps deploy/Dockerfile.server's agents
// stage in step with the agent's imports. That stage copies only the
// packages the agent needs, so server-only commits keep its build cache;
// nothing else builds it in CI, and a missing package surfaced only as a
// failed `init.sh --start` on a fresh install.
func TestDockerfileCopiesAgentPackages(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	df, err := os.ReadFile("deploy/Dockerfile.server")
	if err != nil {
		t.Fatal(err)
	}
	copied := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^COPY ((?:cmd|internal)/[^ ]+)/ `).FindAllStringSubmatch(string(df), -1) {
		copied[m[1]] = true
	}
	const module = "github.com/mustra-dev/mustra/"
	for _, goos := range []string{"linux", "darwin", "windows"} {
		cmd := exec.Command(goBin, "list", "-deps", "./cmd/agent", "./cmd/mustra-tray")
		cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list for %s: %v", goos, err)
		}
		for _, pkg := range strings.Fields(string(out)) {
			if !strings.HasPrefix(pkg, module) {
				continue
			}
			dir := strings.TrimPrefix(pkg, module)
			covered := false
			for c := range copied {
				if dir == c || strings.HasPrefix(dir, c+"/") {
					covered = true
					break
				}
			}
			if !covered {
				t.Errorf("%s (GOOS=%s) is imported by the agent but not copied in deploy/Dockerfile.server", dir, goos)
			}
		}
	}
}
