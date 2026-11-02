package agent

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Enforce, endpoint half: check a setting, fix it if it is wrong, then
// check it again.
//
// That last step is the whole design. A remediation command exiting zero
// says the command ran, not that the setting took — `systemctl enable ufw`
// succeeds on a machine where ufw is not installed, and a registry write
// succeeds into a key the effective policy overrides five seconds later.
// Reporting "remediated" on an exit code would produce a fleet that is
// green in the console and wrong in reality, which is worse than being
// visibly non-compliant, because nobody goes looking.
//
// The agent decides nothing about *whether* to remediate. Each setting
// arrives with Enforce already resolved by the server, which is the only
// party that knows this same fix has already failed three times here.

// remediationTimeout caps one remediation command. Longer than a compliance
// rule's 20 seconds — installing a package or reconfiguring a service is a
// legitimate remediation — and far shorter than a patch run, because a
// desired-state fix that takes five minutes is doing something a package
// should be doing instead.
const remediationTimeoutSeconds = 300

func runEnforce(ctx context.Context, spec *proto.EnforcePolicySpec) []proto.EnforceResult {
	if spec == nil {
		return nil
	}
	out := make([]proto.EnforceResult, 0, len(spec.Settings))
	for _, setting := range spec.Settings {
		out = append(out, enforceSetting(ctx, setting))
	}
	return out
}

func enforceSetting(ctx context.Context, setting proto.EnforceSetting) proto.EnforceResult {
	res := proto.EnforceResult{SettingID: setting.ID, Name: setting.Name}
	check := proto.ComplianceCheck{
		ID: setting.ID, Title: setting.Name,
		Condition: setting.Condition, Rules: setting.Rules,
	}

	before := evaluateCheck(ctx, check)
	switch {
	case before.State == "unknown":
		// Not a pass and not a drift: we could not tell. Remediating on an
		// answer we do not have is how enforcement breaks machines.
		res.State, res.Detail = "unknown", before.Detail
		return res
	case before.Pass:
		res.State = "compliant"
		return res
	}

	res.State, res.Detail = "drifted", before.Detail
	if !setting.Enforce {
		return res
	}
	command := remediationFor(setting)
	if strings.TrimSpace(command) == "" {
		res.Detail = fmt.Sprintf("%s (no remediation defined for %s)", res.Detail, runtime.GOOS)
		return res
	}

	output, runErr := runSoftwareCommandIn(ctx, command, remediationTimeoutSeconds, "")
	res.Output = output

	// Re-check regardless of the exit code, in both directions: a command
	// that failed may still have done the job, and one that succeeded may
	// not have.
	after := evaluateCheck(ctx, check)
	switch {
	case after.Pass:
		res.State = "remediated"
		res.Detail = "was: " + before.Detail
		if runErr != nil {
			// Worth saying out loud rather than hiding behind the green
			// state — a remediation that reports failure and works anyway is
			// a remediation somebody should look at.
			res.Detail += fmt.Sprintf(" (the command reported an error but the setting is now correct: %v)", runErr)
		}
	case runErr != nil:
		res.State, res.Detail = "failed", "remediation failed: "+runErr.Error()
	default:
		res.State = "failed"
		res.Detail = "the remediation command succeeded but the setting is still wrong: " + after.Detail
	}
	return res
}

// remediationFor picks the command for the platform this agent is on. A
// blank one is not an error — plenty of settings only make sense to fix on
// one OS — so it reports drift rather than a failure.
func remediationFor(s proto.EnforceSetting) string {
	switch runtime.GOOS {
	case "windows":
		return s.RemediateWindows
	case "darwin":
		return s.RemediateDarwin
	default:
		return s.RemediateLinux
	}
}
