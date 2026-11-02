package agent

import (
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestPatchVerificationResult(t *testing.T) {
	v := patchVerification{RunID: "r1", ActionID: "a1", Names: []string{"KB1 .NET", "KB2 Defender platform"}}

	res, again := patchVerificationResult(v, nil)
	if !res.OK || res.RebootRequired || again || !res.Verification || !strings.Contains(res.Detail, "all 2") {
		t.Errorf("nothing listed after the restart should verify: %+v again=%v", res, again)
	}

	res, again = patchVerificationResult(v, []proto.PatchInfo{{Name: "KB2 Defender platform"}, {Name: "unrelated"}})
	if res.OK || again || !strings.Contains(res.Detail, "1 of 2") || !strings.Contains(res.Detail, "Defender") {
		t.Errorf("one still listed should fail: %+v again=%v", res, again)
	}

	res, again = patchVerificationResult(v, []proto.PatchInfo{{Name: "KB1 .NET", RestartRequired: true}})
	if !res.OK || !res.RebootRequired || !again {
		t.Errorf("one wanting another restart should stay pending: %+v again=%v", res, again)
	}
	if res.RunID != "r1" || res.ActionID != "a1" || res.Kind != "patch_apply" {
		t.Errorf("the report must close the same action: %+v", res)
	}
}
