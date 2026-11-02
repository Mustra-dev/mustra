package server

import (
	"bytes"
	"strings"
	"testing"
)

func TestCSVCellsCannotBeFormulas(t *testing.T) {
	var buf bytes.Buffer
	w := newSafeCSVWriter(&buf)
	_ = w.Write([]string{"=HYPERLINK(\"http://evil\")", "+1", "-cmd", "@SUM(A1)", "\tx", "\r=1", "host-1", ""})
	w.Flush()
	got := strings.TrimSpace(buf.String())
	for _, bad := range []string{",=", ",+", ",-", ",@"} {
		if strings.Contains(","+got, bad) {
			t.Fatalf("formula cell survived: %s", got)
		}
	}
	if !strings.Contains(got, "host-1") || !strings.HasPrefix(got, `"'=HYPERLINK`) {
		t.Fatalf("unexpected output: %s", got)
	}
}
