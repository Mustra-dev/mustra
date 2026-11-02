package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensorbuild"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGoSensorVerifiedCache(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LocalAppData", t.TempDir())
	data := []byte("artifact")
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.Write(data) }))
	defer srv.Close()
	a := &proto.SensorArtifact{OS: runtime.GOOS, Arch: runtime.GOARCH, File: proto.PackageFileRef{URL: srv.URL, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Size: int64(len(data))}}
	for i := 0; i < 2; i++ {
		p := filepath.Join(t.TempDir(), "binary")
		if err := stageGoSensor(context.Background(), a, p); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		if string(b) != string(data) {
			t.Fatal("incorrect cached bytes")
		}
	}
	if requests != 1 {
		t.Fatalf("downloaded %d times", requests)
	}
	a.File.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("wrong")))
	if stageGoSensor(context.Background(), a, filepath.Join(t.TempDir(), "binary")) == nil {
		t.Fatal("accepted corrupt download")
	}
	a.Arch = "wrong"
	if stageGoSensor(context.Background(), a, filepath.Join(t.TempDir(), "binary")) == nil {
		t.Fatal("accepted wrong target")
	}
}

// Exercise the same executable staging, process scope, timeout and output path
// on each native CI runner; cross-compilation alone cannot establish these.
func TestGoSensorExecution(t *testing.T) {
	if os.Getenv("MUSTRA_GO_BUILD_TEST") != "1" {
		t.Skip("set MUSTRA_GO_BUILD_TEST=1 with pinned compiler")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LocalAppData", t.TempDir())
	for _, tc := range []struct {
		name, source string
		timeout      bool
	}{
		{"output", `package main;import "fmt";func main(){fmt.Println("hello")}`, false},
		{"timeout", `package main;import "time";func main(){time.Sleep(time.Minute)}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			built := sensorbuild.Build(context.Background(), sensorbuild.Request{Source: tc.source, OS: runtime.GOOS, Arch: runtime.GOARCH})
			if built.Error != "" {
				t.Fatal(built.Error)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(built.Data) }))
			defer srv.Close()
			a := &proto.SensorArtifact{OS: runtime.GOOS, Arch: runtime.GOARCH, File: proto.PackageFileRef{URL: srv.URL, SHA256: fmt.Sprintf("%x", sha256.Sum256(built.Data)), Size: int64(len(built.Data))}}
			result := executeCustomSensor(context.Background(), proto.CustomSensorDef{Artifact: a, Platform: proto.SensorPlatform{Language: "go"}, Revision: "revision", TimeoutSeconds: 2})
			if result.Revision != "revision" || result.TimedOut != tc.timeout {
				t.Fatalf("%+v", result)
			}
			if !tc.timeout && (result.Error != "" || result.Raw == nil || strings.TrimSpace(*result.Raw) != "hello") {
				t.Fatalf("%+v", result)
			}
		})
	}
}
