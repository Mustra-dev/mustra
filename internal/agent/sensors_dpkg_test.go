package agent

import (
	"testing"
)

func TestParseDpkgAppsSource(t *testing.T) {
	out := "libssl3t64\t3.5.7-1~deb13u3\tamd64\topenssl\t3.5.7-1~deb13u3\n" +
		"libfoo1\t1.2-3+b1\tamd64\tfoo\t1.2-3\n" +
		"old-format\t1.0\n"
	apps := parseDpkgApps([]byte(out))
	if len(apps) != 3 {
		t.Fatalf("got %d apps", len(apps))
	}
	if a := apps[0]; a.Name != "libssl3t64" || a.Source != "openssl" || a.SourceVersion != "3.5.7-1~deb13u3" {
		t.Errorf("libssl3t64: %+v", a)
	}
	if a := apps[1]; a.Version != "1.2-3+b1" || a.SourceVersion != "1.2-3" {
		t.Errorf("binNMU: %+v", a)
	}
	if a := apps[2]; a.Name != "old-format" || a.Version != "1.0" || a.Source != "" {
		t.Errorf("short line: %+v", a)
	}
}
