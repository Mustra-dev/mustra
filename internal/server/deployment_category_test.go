package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestDeploymentCategory(t *testing.T) {
	cases := []struct {
		name  string
		run   store.PatchJobRun
		kinds []string
		want  string
	}{
		{"bulk patch", store.PatchJobRun{}, []string{"patch_apply"}, "patch"},
		{"patch schedule, every target offline", store.PatchJobRun{ScheduleID: "sch-1"}, nil, "patch"},
		{"catalog install", store.PatchJobRun{ScheduleName: "Install Firefox"}, []string{"software_install"}, "software"},
		// An action package's run is named after the package, so the name
		// says nothing; the work does.
		{"action package", store.PatchJobRun{ScheduleName: "Reboot Computer"}, []string{"software_run"}, "software"},
		{"held for a window, no action yet", store.PatchJobRun{ScheduleName: "Update 7-Zip"}, []string{"deploy_job"}, "software"},
		{"self service", store.PatchJobRun{ScheduleName: "Self Service: Slack"}, []string{"catalog_install"}, "software"},
		{"playbook that installs", store.PatchJobRun{ScheduleName: "Playbook: New laptop"}, []string{"software_install", "patch_apply"}, "playbook"},
		{"survey", store.PatchJobRun{ScheduleName: "How is your laptop?"}, []string{"survey"}, "other"},
		{"message", store.PatchJobRun{ScheduleName: "Restart tonight"}, []string{"end_user_notification"}, "other"},
		{"nothing dispatched, no schedule", store.PatchJobRun{ScheduleName: "Install X"}, nil, "other"},
	}
	for _, c := range cases {
		if got := deploymentCategory(c.run, c.kinds); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
