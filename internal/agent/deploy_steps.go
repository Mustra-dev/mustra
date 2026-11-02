package agent

import (
	"context"
	"fmt"
	"slices"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/shirou/gopsutil/v4/host"
)

func (r *deployRunner) steps(ctx context.Context, p proto.DeployPackagePlan, a proto.DeployAction, steps []proto.DeployStep) error {
	for _, step := range steps {
		key := p.PackageID + ":" + step.ID
		if r.st.Done[key] {
			continue
		}
		if e := r.checkpoint(); e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if step.If != nil {
			choice, exists := r.st.Branches[key]
			if !exists {
				var e error
				choice, e = r.check(ctx, p, step.If)
				if e != nil {
					return e
				}
				r.st.Branches[key] = choice
				if e = r.checkpoint(); e != nil {
					return e
				}
				r.event(p.PackageID, step.ID, "branch", "running", fmt.Sprintf("Condition=%t", choice))
			}
			branch := step.Else
			if choice {
				branch = step.Then
			}
			if e := r.steps(ctx, p, a, branch); e != nil {
				return e
			}
		} else {
			dir, e := r.stage(ctx, p, a, step)
			if e != nil {
				return e
			}
			// Save before starting a process. Recovery refuses to repeat a step whose
			// completion was never committed, even if its installer might have exited.
			r.st.ActiveStep = key
			if e = r.checkpoint(); e != nil {
				return e
			}
			r.event(p.PackageID, step.ID, "command", "running", step.Name)
			var code int
			for attempt := 0; attempt <= step.Retries; attempt++ {
				code, e = r.command(ctx, p, a, step, dir)
				if e == nil || !step.RetrySafe || ctx.Err() != nil {
					break
				}
				r.event(p.PackageID, step.ID, "retry", "running", fmt.Sprintf("Retry-safe attempt %d failed: %v", attempt+1, e))
			}
			for _, path := range step.LogPaths {
				r.collectLog(p, step.ID, path)
			}
			if slices.Contains(step.RebootCodes, code) && e == nil {
				boot, be := host.BootTimeWithContext(ctx)
				if be != nil {
					return be
				}
				r.st.Done[key] = true
				r.st.ActiveStep = ""
				r.st.RebootAt = boot
				if ce := r.checkpoint(); ce != nil {
					return ce
				}
				if r.st.Job.AllowReboot {
					if ce := deployReboot(ctx); ce != nil {
						return ce
					}
				}
				return deployWait{"reboot_required", "Installer requested a reboot"}
			}
			if e != nil {
				r.event(p.PackageID, step.ID, "command", "running", e.Error())
				if !step.ContinueOnError {
					return e
				}
			}
		}
		// Completion and clearing ActiveStep are one journal write. A crash between
		// two separate writes could otherwise make an uncertain step rerunnable.
		r.st.Done[key] = true
		r.st.ActiveStep = ""
		if e := r.checkpoint(); e != nil {
			return e
		}
	}
	return nil
}
