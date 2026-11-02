package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeployBranchAndValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix command integration; Windows execution checked by platform tests")
	}
	dir := t.TempDir()
	st, e := OpenStore(filepath.Join(dir, "agent.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	marker := filepath.Join(dir, "installed")
	a := New(Config{DataDir: filepath.Join(dir, "agent.db")})
	a.store = st
	a.agentID = "agt-test"
	logs, e := deploylog.Open(filepath.Join(dir, "logs"), proto.DefaultDeploySettings().EndpointLogs)
	if e != nil {
		t.Fatal(e)
	}
	action := proto.DeployAction{Validation: &proto.DeployCheck{Kind: "file_exists", Path: marker}, Steps: []proto.DeployStep{{ID: "branch", If: &proto.DeployCheck{Kind: "file_exists", Path: marker}, Then: []proto.DeployStep{{ID: "wrong", Script: &proto.DeployScript{Language: "shell", Source: "exit 9"}}}, Else: []proto.DeployStep{{ID: "install", Script: &proto.DeployScript{Language: "shell", Source: "touch \"$MUSTRA_PARAM_path\""}}}}}}
	p := proto.DeployPackagePlan{PackageID: "sw-test", Operation: "install", Parameters: map[string]string{"path": marker}, Variant: proto.DeployVariant{OS: runtime.GOOS, Detection: &proto.DeployCheck{Kind: "file_exists", Path: marker}, Actions: map[string]proto.DeployAction{"install": action}}}
	state := deployState{Job: proto.DeployJob{ID: "job-test", AgentID: a.agentID, Packages: []proto.DeployPackagePlan{p}, Settings: proto.DefaultDeploySettings()}, Status: "queued", Done: map[string]bool{}, Branches: map[string]bool{}}
	if e = st.acceptDeploy(state.Job); e != nil {
		t.Fatal(e)
	}
	runner := deployRunner{a: a, st: &state, log: logs}
	t.Cleanup(func() {
		if state.Workspace != "" {
			os.RemoveAll(state.Workspace)
		}
	})
	if e = runner.run(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(marker); e != nil {
		t.Fatal("installer did not run")
	}
	if state.Done["sw-test:wrong"] {
		t.Fatal("untaken branch ran")
	}
	if e = st.acceptDeploy(state.Job); e != nil {
		t.Fatal(e)
	}
	states, e := st.deployStates()
	if e != nil || len(states) != 1 || !states[0].Done["sw-test:install"] {
		t.Fatal("duplicate acceptance lost checkpoint")
	}
}
func TestDeploySensorErrorsDoNotChooseElse(t *testing.T) {
	a := New(Config{})
	r := deployRunner{a: a}
	p := proto.DeployPackagePlan{}
	c := proto.DeployCheck{Kind: "sensor", SensorID: "unknown", Quantifier: "none"}
	if ok, e := r.check(context.Background(), p, &c); e == nil || ok {
		t.Fatalf("sensor error treated as boolean: %v %v", ok, e)
	}
}
func TestDeployCancellationSurvivesCheckpoint(t *testing.T) {
	s, e := OpenStore(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	job := proto.DeployJob{ID: "one", Packages: []proto.DeployPackagePlan{{PackageID: "app"}}}
	if e = s.acceptDeploy(job); e != nil {
		t.Fatal(e)
	}
	states, _ := s.deployStates()
	if e = s.cancelDeploy(job.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.saveDeploy(&states[0]); e != nil {
		t.Fatal(e)
	}
	if !states[0].Cancel {
		t.Fatal("checkpoint cleared cancellation")
	}
	raw, _ := json.Marshal(states[0])
	if len(raw) == 0 {
		t.Fatal("missing state")
	}
}

func deployTestRunner(t *testing.T) *deployRunner {
	t.Helper()
	dir := t.TempDir()
	st, e := OpenStore(filepath.Join(dir, "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { st.Close() })
	a := New(Config{DataDir: filepath.Join(dir, "state.db")})
	a.store = st
	a.agentID = "agt-test"
	l, e := deploylog.Open(filepath.Join(dir, "logs"), proto.DefaultDeploySettings().EndpointLogs)
	if e != nil {
		t.Fatal(e)
	}
	job := proto.DeployJob{ID: idgen.New("act-test-"), AgentID: a.agentID, Settings: proto.DefaultDeploySettings(), Packages: []proto.DeployPackagePlan{{PackageID: "app"}}}
	if e = st.acceptDeploy(job); e != nil {
		t.Fatal(e)
	}
	r := &deployRunner{a: a, log: l, st: &deployState{Job: job, Status: "queued", Done: map[string]bool{}, Branches: map[string]bool{}}}
	t.Cleanup(func() {
		if r.st.Workspace != "" {
			os.RemoveAll(r.st.Workspace)
		}
	})
	return r
}
func TestDeployFilesAreLazyAndVerified(t *testing.T) {
	r := deployTestRunner(t)
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { downloads.Add(1); io.WriteString(w, "payload") }))
	defer server.Close()
	sum := sha256.Sum256([]byte("payload"))
	p := proto.DeployPackagePlan{PackageID: "app", Files: map[string]proto.PackageFileRef{"needed": {Name: "payload.bin", SHA256: fmt.Sprintf("%x", sum), URL: server.URL}}}
	if _, e := r.stage(context.Background(), p, proto.DeployAction{}, proto.DeployStep{}); e != nil {
		t.Fatal(e)
	}
	if downloads.Load() != 0 {
		t.Fatal("command-only action downloaded files")
	}
	a := proto.DeployAction{RequireFiles: true}
	step := proto.DeployStep{Files: []string{"needed"}}
	dir, e := r.stage(context.Background(), p, a, step)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := os.ReadFile(filepath.Join(dir, "payload.bin")); e != nil || string(got) != "payload" {
		t.Fatal("staged payload", e)
	}
	if _, e = r.stage(context.Background(), p, a, step); e != nil {
		t.Fatal(e)
	}
	if downloads.Load() != 1 {
		t.Fatal("verified cache was not reused")
	}
	// Corruption must be detected and replaced before an installer sees the file.
	if e = os.WriteFile(filepath.Join(filepath.Dir(r.a.cfg.DataDir), "deploy", "cache", fmt.Sprintf("%x", sum)), []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = r.stage(context.Background(), p, a, step); e != nil {
		t.Fatal(e)
	}
	if downloads.Load() != 2 {
		t.Fatal("corrupt cache was trusted")
	}
}
func TestDeployRebootCheckpointDoesNotRepeatCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix shell")
	}
	r := deployTestRunner(t)
	marker := filepath.Join(t.TempDir(), "installed")
	a := proto.DeployAction{ValidateAfterReboot: true, Validation: &proto.DeployCheck{Kind: "file_exists", Path: marker}, Steps: []proto.DeployStep{{ID: "installer", Script: &proto.DeployScript{Language: "shell", Source: "printf x >> \"$MUSTRA_PARAM_path\""}}}}
	r.st.Job.Packages = []proto.DeployPackagePlan{{PackageID: "app", Operation: "install", Parameters: map[string]string{"path": marker}, Variant: proto.DeployVariant{OS: runtime.GOOS, Detection: &proto.DeployCheck{Kind: "file_exists", Path: marker}, Actions: map[string]proto.DeployAction{"install": a}}}}
	var wait deployWait
	if e := r.run(context.Background()); !errors.As(e, &wait) || wait.status != "reboot_required" {
		t.Fatal("expected reboot checkpoint", e)
	}
	if e := r.run(context.Background()); !errors.As(e, &wait) {
		t.Fatal("validation did not wait for actual reboot", e)
	}
	r.st.RebootAt-- // A different boot identity simulates the next boot without rebooting the test host.
	if e := r.run(context.Background()); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(marker)
	if string(raw) != "x" {
		t.Fatal("installer repeated after reboot", string(raw))
	}
}
func TestDeployRecoveryMarksUncertainCommandInterrupted(t *testing.T) {
	r := deployTestRunner(t)
	r.st.ActiveStep = "app:installer"
	if e := r.a.store.saveDeploy(r.st); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r.a.runDeployLoop(ctx)
	if states, e := r.a.store.deployStates(); e != nil || len(states) != 0 {
		t.Fatal("uncertain command remained dispatchable", states, e)
	}
	raw, e := os.ReadFile(filepath.Join(filepath.Dir(r.a.cfg.DataDir), "deploy", "logs", "active.log"))
	if e != nil || !strings.Contains(string(raw), `"status":"interrupted"`) {
		t.Fatal("missing interrupted outcome", e)
	}
}
