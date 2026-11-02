package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/proto"
)

func actionTestPlan(source, mode, sensor string) proto.DeployPackagePlan {
	a := proto.DeployAction{SuccessMode: mode, Steps: []proto.DeployStep{{ID: "run", Script: &proto.DeployScript{Language: "shell", Source: source, TimeoutSeconds: 2}}}}
	if mode == "sensor" || mode == "both" {
		a.Validation = &proto.DeployCheck{Kind: "sensor", SensorID: "custom_test", Quantifier: "any", Rows: []proto.DeployPredicate{{Field: "value", Operator: "eq", Value: "ok"}}, Sensor: &proto.DeploySensor{Fields: []proto.SensorField{{Name: "value", Type: "string"}}, Definitions: map[string]proto.CustomSensorDef{runtime.GOOS: {Command: sensor, Platform: proto.SensorPlatform{Language: "shell"}, TimeoutSeconds: 1}}}}
	}
	return proto.DeployPackagePlan{PackageID: "app", Name: "Example", Operation: "run", Variant: proto.DeployVariant{OS: runtime.GOOS, Actions: map[string]proto.DeployAction{"run": a}}}
}
func TestActionSuccessModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell integration")
	}
	for _, tc := range []struct {
		name, source, mode, sensor string
		ok                         bool
	}{
		{"default zero", "echo inline-result; exit 0", "", "", true},
		{"default failure", "exit 7", "", "", false},
		{"sensor overrides nonzero", "exit 7", "sensor", "echo ok", true},
		{"both rejects nonzero", "exit 7", "both", "echo ok", false},
		{"both passes", "exit 0", "both", "echo ok", true},
		{"sensor false", "exit 0", "sensor", "echo wrong", false},
		{"sensor error never passes", "exit 0", "sensor", "exit 1", false},
		{"execution timeout never overridden", "sleep 10", "sensor", "echo ok", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := deployTestRunner(t)
			p := actionTestPlan(tc.source, tc.mode, tc.sensor)
			r.st.Job.Operation = "run"
			r.st.Job.Packages = []proto.DeployPackagePlan{p}
			e := r.run(context.Background())
			if (e == nil) != tc.ok {
				t.Fatalf("result %v, want success=%t", e, tc.ok)
			}
			logs, e := deploylog.Read(context.Background(), filepath.Join(filepath.Dir(r.a.cfg.DataDir), "logs"), deploylog.ReadOptions{JobID: r.st.Job.ID})
			if e != nil {
				t.Fatal(e)
			}
			found := false
			for _, ev := range logs.Events {
				if ev.Stage == "execution_result" && ev.ExitCode != nil {
					found = true
				}
			}
			if !found {
				t.Fatal("actual exit code not retained")
			}
		})
	}
}
func TestActionNewInvocationRunsAgainAndDuplicateDoesNot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell integration")
	}
	marker := filepath.Join(t.TempDir(), "runs")
	for i := 0; i < 2; i++ {
		r := deployTestRunner(t)
		p := actionTestPlan("echo run >> \"$MUSTRA_PARAM_marker\"", "", "")
		p.Parameters = map[string]string{"marker": marker}
		r.st.Job.Packages = []proto.DeployPackagePlan{p}
		for repeat := 0; repeat < 2; repeat++ {
			if e := r.run(context.Background()); e != nil {
				t.Fatal(e)
			}
		}
	}
	data, e := os.ReadFile(marker)
	if e != nil || strings.Count(string(data), "run") != 2 {
		t.Fatalf("wrong invocation count %q %v", data, e)
	}
}
func TestActionDownloadDeadlineCoversAllFilesAndSurvivesRetry(t *testing.T) {
	r := deployTestRunner(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-time.After(650 * time.Millisecond):
			fmt.Fprint(w, "payload")
		case <-req.Context().Done():
		}
	}))
	defer srv.Close()
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte("payload")))
	p := actionTestPlan("exit 0", "", "")
	a := p.Variant.Actions["run"]
	a.DownloadSeconds = 1
	a.RequireFiles = true
	p.Files = map[string]proto.PackageFileRef{"first": {Name: "a", SHA256: sum, URL: srv.URL}, "second": {Name: "b", SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("other"))), URL: srv.URL}}
	_, e := r.stage(context.Background(), p, a, proto.DeployStep{Files: []string{"first", "second"}})
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("whole phase deadline not enforced: %v", e)
	}
	deadline := r.st.DownloadDeadline
	_, e = r.stage(context.Background(), p, a, proto.DeployStep{Files: []string{"first"}})
	if !errors.Is(e, context.DeadlineExceeded) || r.st.DownloadDeadline != deadline {
		t.Fatalf("retry reset download budget: %v", e)
	}
}
func TestActionOutputContinuesAfterLongLine(t *testing.T) {
	var lines []string
	w := actionOutput{emit: func(s string) { lines = append(lines, s) }}
	w.Write([]byte(strings.Repeat("x", 70000) + "\nnext line\n"))
	w.flush()
	if len(lines) != 2 || lines[1] != "next line" || !strings.Contains(lines[0], "omitted") {
		t.Fatalf("lost later console output: %v", lines)
	}
}
func TestActionCommandHandlesInheritedPipes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell integration")
	}
	r := deployTestRunner(t)
	p := actionTestPlan("sleep 10 & echo parent-exited", "", "")
	a := p.Variant.Actions["run"]
	a.Steps[0].Script.TimeoutSeconds = 1
	p.Variant.Actions["run"] = a
	r.st.Job.Packages = []proto.DeployPackagePlan{p}
	start := time.Now()
	_ = r.run(context.Background())
	if time.Since(start) > 5*time.Second {
		t.Fatal("inherited output pipes escaped execution deadline")
	}
}
