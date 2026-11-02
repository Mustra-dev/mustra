package agent

import (
	"context"
	"fmt"
)

// patchRestartNote decides and schedules the restart a patch job asked
// for, and returns the line the job's result reports. Nothing restarts
// after a failed or timed-out run: an endpoint half-way through updates is
// better left up for someone to look at.
func patchRestartNote(ctx context.Context, mode string, warnMinutes int, required, succeeded bool) string {
	if mode == "" {
		return ""
	}
	if !succeeded {
		return "Not restarting: the updates did not finish cleanly."
	}
	if mode == "if_required" && !required {
		return "No restart needed."
	}
	if warnMinutes < 1 {
		warnMinutes = 1
	}
	msg := fmt.Sprintf("This computer will restart in %d minute(s) to finish installing updates. Save your work.", warnMinutes)
	if err := scheduleRestart(ctx, warnMinutes, msg); err != nil {
		return "Could not schedule the restart: " + err.Error()
	}
	return fmt.Sprintf("Restarting in %d minute(s) to finish the updates; the signed-in user was warned.", warnMinutes)
}
