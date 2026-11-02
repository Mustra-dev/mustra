package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestStagePackageFilesVerifiesHash(t *testing.T) {
	payload := []byte("this is the installer")
	sum := sha256.Sum256(payload)
	good := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()

	t.Run("stages a matching file", func(t *testing.T) {
		dir, cleanup, err := stagePackageFiles(context.Background(),
			[]proto.PackageFileRef{{Name: "setup.msi", SHA256: good, URL: srv.URL}})
		if err != nil {
			t.Fatalf("stagePackageFiles: %v", err)
		}
		defer cleanup()
		got, err := os.ReadFile(filepath.Join(dir, "setup.msi"))
		if err != nil {
			t.Fatalf("staged file unreadable: %v", err)
		}
		if string(got) != string(payload) {
			t.Errorf("staged content = %q, want %q", got, payload)
		}
	})

	// The whole reason the hash travels with the file. A truncated download
	// that still runs is worse than one that failed to arrive, because the
	// command executes against it and reports whatever nonsense follows.
	t.Run("refuses a file whose hash does not match", func(t *testing.T) {
		_, _, err := stagePackageFiles(context.Background(),
			[]proto.PackageFileRef{{Name: "setup.msi", SHA256: hex.EncodeToString(make([]byte, 32)), URL: srv.URL}})
		if err == nil {
			t.Fatal("expected a hash mismatch to be refused")
		}
	})

	// A name the endpoint writes into a directory must be a bare filename;
	// otherwise one package escapes the staging directory on every machine.
	t.Run("refuses a traversing filename", func(t *testing.T) {
		for _, bad := range []string{"../evil", "/etc/cron.d/x", `..\evil`, ".."} {
			if _, _, err := stagePackageFiles(context.Background(),
				[]proto.PackageFileRef{{Name: bad, SHA256: good, URL: srv.URL}}); err == nil {
				t.Errorf("expected %q to be refused", bad)
			}
		}
	})

	t.Run("no files is not an error", func(t *testing.T) {
		dir, cleanup, err := stagePackageFiles(context.Background(), nil)
		defer cleanup()
		if err != nil || dir != "" {
			t.Fatalf("got dir=%q err=%v, want empty and nil", dir, err)
		}
	})
}
