package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Staging a package's payload before its command runs.
//
// The command runs with the staging directory as its working directory, so a
// package can say `msiexec /i setup.msi /qn` and mean the file that was just
// put next to it. The directory is also exported as MUSTRA_PACKAGE_DIR for
// commands that need an absolute path.
//
// Everything here is deliberately strict, because the failure modes are
// quiet ones: a truncated download that still runs, or a filename that
// escapes the directory and lands somewhere on the system.

const stageDownloadTimeout = 30 * time.Minute

// stagePackageFiles downloads each file into a fresh directory and verifies
// it. It returns the directory and a cleanup function; on any failure the
// directory is removed and an error returned, because running a package
// command against a payload that did not arrive intact is worse than not
// running it at all.
func stagePackageFiles(ctx context.Context, files []proto.PackageFileRef) (string, func(), error) {
	if len(files) == 0 {
		return "", func() {}, nil
	}
	dir, err := os.MkdirTemp("", "mustra-pkg-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("could not create a staging directory: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }

	for _, f := range files {
		// The server checks this too, but the endpoint is where a bad name
		// would actually do harm, and a check on only one side of a network
		// boundary is a check that can be skipped.
		name := filepath.Base(strings.ReplaceAll(f.Name, "\\", "/"))
		if name == "" || name == "." || name == ".." || strings.ContainsAny(f.Name, `/\`) {
			cleanup()
			return "", func() {}, fmt.Errorf("refusing to stage a file named %q", f.Name)
		}
		if err := downloadAndVerify(ctx, f, filepath.Join(dir, name)); err != nil {
			cleanup()
			return "", func() {}, err
		}
	}
	return dir, cleanup, nil
}

func downloadAndVerify(ctx context.Context, f proto.PackageFileRef, dst string) error {
	dctx, cancel := context.WithTimeout(ctx, stageDownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(dctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return fmt.Errorf("staging %s: %w", f.Name, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("staging %s: %w", f.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("staging %s: server said %s", f.Name, resp.Status)
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return fmt.Errorf("staging %s: %w", f.Name, err)
	}
	// Hashed while writing rather than by re-reading: these are large by
	// assumption, and reading a 400 MB file twice to check it is a waste of
	// the endpoint's disk.
	hasher := sha256.New()
	limit := int64(2 << 30)
	if f.Size > 0 && f.Size < limit {
		limit = f.Size
	}
	written, copyErr := io.Copy(io.MultiWriter(out, hasher), io.LimitReader(resp.Body, limit+1))
	if copyErr == nil && (written > limit || f.Size > 0 && written != f.Size) {
		copyErr = fmt.Errorf("payload size does not match the expected size limit")
	}
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("staging %s: %w", f.Name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("staging %s: %w", f.Name, closeErr)
	}

	// The whole point of carrying the hash. A file that silently truncated
	// is worse than one that failed to arrive, because the command runs
	// against it regardless and reports whatever nonsense follows.
	got := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(got, f.SHA256) {
		return fmt.Errorf("staging %s: content does not match its expected hash "+
			"(got %s, expected %s) — the download was corrupted or the file changed", f.Name, got, f.SHA256)
	}
	return nil
}
