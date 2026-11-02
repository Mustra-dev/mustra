package sensorbuild

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, source := range []string{`package main; import "example.com/foo"; func main(){}`, `package main; import "C"; func main(){}`, "package main\n//go:embed /etc/passwd\nvar s string\nfunc main(){}", `package other; func main(){}`} {
		if Validate(Request{Source: source, OS: "linux", Arch: "amd64"}) == nil {
			t.Fatalf("accepted %s", source)
		}
	}
	if err := Validate(Request{Source: `package main; import "fmt"; func main(){fmt.Println("ok")}`, OS: "windows", Arch: "arm64"}); err != nil {
		t.Fatal(err)
	}
	a := Request{Source: "one", OS: "linux", Arch: "amd64"}
	b := a
	b.Arch = "arm64"
	if Key(a) == Key(b) {
		t.Fatal("target missing from key")
	}
}

func TestBuildAndRun(t *testing.T) {
	if os.Getenv("MUSTRA_GO_BUILD_TEST") != "1" {
		t.Skip("set MUSTRA_GO_BUILD_TEST=1 with pinned compiler")
	}
	result := Build(context.Background(), Request{Source: `package main; import "fmt";func main(){fmt.Println("go sensor")}`, OS: runtime.GOOS, Arch: runtime.GOARCH})
	if result.Error != "" {
		t.Fatal(result.Error)
	}
	name := filepath.Join(t.TempDir(), "sensor.exe")
	if err := os.WriteFile(name, result.Data, 0700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(name).Output()
	if err != nil || strings.TrimSpace(string(out)) != "go sensor" {
		t.Fatalf("%s %v", out, err)
	}
}
func TestSixTargets(t *testing.T) {
	if os.Getenv("MUSTRA_GO_CROSS_TEST") != "1" {
		t.Skip("set MUSTRA_GO_CROSS_TEST=1 with pinned compiler")
	}
	for _, platform := range []string{"linux", "darwin", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			t.Run(platform+"/"+arch, func(t *testing.T) {
				r := Build(context.Background(), Request{Source: `package main;import "fmt";func main(){fmt.Println("ok")}`, OS: platform, Arch: arch})
				if r.Error != "" || len(r.Data) == 0 {
					t.Fatalf("%s", r.Error)
				}
			})
		}
	}
}

// The pin and go.mod move together: a toolchain bump that leaves the pin
// behind makes every Go sensor build fail with "pinned Go compiler
// unavailable".
func TestCompilerMatchesGoMod(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "go "); ok {
			if "go"+v != Compiler {
				t.Fatalf("go.mod says go %s but sensorbuild.Compiler is %s", v, Compiler)
			}
			return
		}
	}
	t.Fatal("no go directive in go.mod")
}
