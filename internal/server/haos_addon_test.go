package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

// The tarball is what install.sh unpacks into /addons; the Supervisor
// ignores a directory without config.yaml, and run.sh must stay executable.
func TestHAOSAddonTarball(t *testing.T) {
	data, err := haosAddonTarball()
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	modes := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		modes[h.Name] = h.Mode
	}
	for _, want := range []string{"config.yaml", "build.yaml", "Dockerfile", "run.sh"} {
		if _, ok := modes[want]; !ok {
			t.Errorf("tarball is missing %s (has %v)", want, modes)
		}
	}
	if modes["run.sh"]&0o111 == 0 {
		t.Errorf("run.sh is not executable: %o", modes["run.sh"])
	}
}
