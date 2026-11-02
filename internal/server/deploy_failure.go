package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/proto"
)

// A failed Deploy job ends with an event whose message is whatever stopped
// the run, which for a script is "exit status 100". Recorded as the
// endpoint's result, that is all Deployments could show, and every failure
// of a run grouped under the one line. What the operator needs is in the
// job's log, which the server has just written: the step that failed, its
// exit code and the last lines it wrote, errors first.

const (
	failureTailLines = 12
	failureDetailMax = 4000
)

// deployFailureDetail builds the result recorded for a job that ended
// badly. It falls back to the final message alone when the log cannot be
// read.
func deployFailureDetail(ctx context.Context, logDir string, job proto.DeployJob, final proto.DeployEvent) string {
	steps := deployStepNames(job)
	var (
		stepID   string
		exitCode *int
		stderr   []string
		stdout   []string
	)
	keep := func(lines []string, s string) []string {
		lines = append(lines, s)
		if len(lines) > failureTailLines {
			lines = lines[len(lines)-failureTailLines:]
		}
		return lines
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := deploylog.Walk(rctx, logDir, job.ID, func(ev proto.DeployEvent) error {
		if ev.JobID != job.ID {
			return nil
		}
		// Output from an earlier step that went on to succeed is not the
		// failure; start over whenever a new step begins writing.
		if ev.StepID != "" && ev.StepID != stepID && (ev.Stage == "stdout" || ev.Stage == "stderr") {
			stepID, stderr, stdout, exitCode = ev.StepID, nil, nil, nil
		}
		switch ev.Stage {
		case "stderr":
			if m := strings.TrimRight(ev.Message, "\r\n"); m != "" {
				stderr = keep(stderr, m)
			}
		case "stdout":
			if m := strings.TrimRight(ev.Message, "\r\n"); m != "" {
				stdout = keep(stdout, m)
			}
		case "execution_result":
			if ev.ExitCode != nil {
				exitCode = ev.ExitCode
			}
			if ev.StepID != "" {
				stepID = ev.StepID
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) && len(stderr)+len(stdout) == 0 {
		return final.Message
	}
	return composeFailureDetail(final, steps[stepID], stepID, exitCode, stderr, stdout)
}

// composeFailureDetail writes the result: a first line that names what
// failed and why (Deployments groups failures by it), then the output.
func composeFailureDetail(final proto.DeployEvent, stepName, stepID string, exitCode *int, stderr, stdout []string) string {
	what := "the run"
	switch {
	case stepName != "":
		what = fmt.Sprintf("step %q", stepName)
	case stepID != "":
		what = "step " + stepID
	}
	reason := "failed"
	switch {
	case final.Status == "timed_out":
		reason = "timed out"
	case exitCode != nil:
		reason = fmt.Sprintf("exited with code %d", *exitCode)
	}
	// The line most likely to say why: the last error line, the last
	// output line when the command wrote no errors, else what the agent
	// said.
	agent := strings.TrimSpace(final.Message)
	why := agent
	if len(stderr) > 0 {
		why = stderr[len(stderr)-1]
	} else if len(stdout) > 0 {
		why = stdout[len(stdout)-1]
	}
	var b strings.Builder
	b.WriteString(strings.ToUpper(what[:1]) + what[1:] + " " + reason)
	if why != "" {
		b.WriteString(": " + why)
	}
	if len(stderr) > 0 {
		b.WriteString("\n\nErrors (last lines):\n" + strings.Join(stderr, "\n"))
	}
	if len(stdout) > 0 {
		b.WriteString("\n\nOutput (last lines):\n" + strings.Join(stdout, "\n"))
	}
	if agent != "" && agent != why {
		b.WriteString("\n\nAgent: " + agent)
	}
	return safeTruncate(b.String(), failureDetailMax)
}

// deployStepNames maps every step of the job's plans, nested ones included,
// to its name.
func deployStepNames(job proto.DeployJob) map[string]string {
	out := map[string]string{}
	var walk func([]proto.DeployStep)
	walk = func(steps []proto.DeployStep) {
		for _, s := range steps {
			if s.ID != "" && s.Name != "" {
				out[s.ID] = s.Name
			}
			walk(s.Then)
			walk(s.Else)
		}
	}
	for _, p := range job.Packages {
		for _, a := range p.Variant.Actions {
			walk(a.Steps)
		}
	}
	return out
}
