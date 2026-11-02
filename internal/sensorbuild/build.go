// Package sensorbuild compiles single-file sensors inside the isolated tools container.
package sensorbuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Compiler is the Go release custom Go sensors are built with: the one in
// go.mod, which TestCompilerMatchesGoMod holds it to.
const Compiler = "go1.27.3"
const MaxArtifact = 16 << 20

type Request struct {
	Source string `json:"source"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
}
type Result struct {
	Data  []byte `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

func Key(r Request) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(Compiler+"\x00"+r.OS+"\x00"+r.Arch+"\x00"+r.Source)))
}
func Validate(r Request) error {
	if len(r.Source) > 256<<10 {
		return fmt.Errorf("source exceeds 256 KiB")
	}
	if (r.OS != "linux" && r.OS != "darwin" && r.OS != "windows") || (r.Arch != "amd64" && r.Arch != "arm64") {
		return fmt.Errorf("unsupported Go target")
	}
	f, err := parser.ParseFile(token.NewFileSet(), "sensor.go", r.Source, parser.ParseComments)
	if err != nil {
		return err
	}
	if f.Name.Name != "main" {
		return fmt.Errorf("sensor must use package main")
	}
	for _, c := range f.Comments {
		for _, v := range c.List {
			if strings.HasPrefix(v.Text, "//go:") {
				return fmt.Errorf("compiler directives are not supported")
			}
		}
	}
	for _, i := range f.Imports {
		p, e := strconv.Unquote(i.Path.Value)
		if e != nil {
			return e
		}
		pkg, e := build.Default.Import(p, "", build.FindOnly)
		if e != nil || !pkg.Goroot || p == "C" || strings.Contains(p, "/internal/") {
			return fmt.Errorf("only standard-library imports are supported: %s", p)
		}
	}
	return nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if left := (16 << 10) - b.Len(); left > 0 {
		b.Buffer.Write(p[:min(left, n)])
	}
	return n, nil
}
func Build(ctx context.Context, r Request) Result {
	if err := Validate(r); err != nil {
		return Result{Error: err.Error()}
	}
	compilerPath := filepath.Join(runtime.GOROOT(), "bin", "go")
	version, err := exec.Command(compilerPath, "version").Output()
	if err != nil || !strings.Contains(string(version), " "+Compiler+" ") {
		return Result{Error: "pinned Go compiler unavailable"}
	}
	dir, err := os.MkdirTemp("", "mustra-go-")
	if err != nil {
		return Result{Error: err.Error()}
	}
	defer os.RemoveAll(dir)
	if err = os.WriteFile(filepath.Join(dir, "sensor.go"), []byte(r.Source), 0600); err != nil {
		return Result{Error: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, compilerPath, "build", "-p=1", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", "sensor.bin", "sensor.go")
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir, "GOCACHE=" + filepath.Join(dir, "cache"), "GOPATH=" + filepath.Join(dir, "gopath"), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off", "GO111MODULE=off", "CGO_ENABLED=0", "GOMAXPROCS=2", "GOOS=" + r.OS, "GOARCH=" + r.Arch}
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "SystemRoot="+os.Getenv("SystemRoot"), "TEMP="+dir, "TMP="+dir)
	}
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err = cmd.Run(); err != nil {
		return Result{Error: fmt.Sprintf("%s/%s: %v\n%s", r.OS, r.Arch, err, out.String())}
	}
	st, err := os.Stat(filepath.Join(dir, "sensor.bin"))
	if err != nil || st.Size() > MaxArtifact {
		return Result{Error: "build artifact missing or exceeds 16 MiB"}
	}
	data, err := os.ReadFile(filepath.Join(dir, "sensor.bin"))
	if err != nil {
		return Result{Error: err.Error()}
	}
	return Result{Data: data}
}
