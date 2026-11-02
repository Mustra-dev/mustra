package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// secretWrite puts a renewed application credential in place (see
// proto.SecretWriteJob): backs the file up, writes it with the old mode
// (0600 when new), reloads, and restores the backup if the reload fails.
func secretWrite(ctx context.Context, job proto.SecretWriteJob) (string, error) {
	if !filepath.IsAbs(job.Path) {
		return "", errors.New("the path must be absolute")
	}
	if job.Content == "" {
		return "", errors.New("nothing to write")
	}
	old, readErr := os.ReadFile(job.Path)
	mode := os.FileMode(0o600)
	if st, err := os.Stat(job.Path); err == nil {
		mode = st.Mode().Perm()
	}
	var data []byte
	if job.Key != "" {
		if readErr != nil {
			return "", fmt.Errorf("read %s to replace %s in it: %w", job.Path, job.Key, readErr)
		}
		out, err := replaceKeyValue(string(old), job.Key, job.Content)
		if err != nil {
			return "", err
		}
		data = []byte(out)
	} else {
		data = []byte(job.Content)
	}
	if err := os.MkdirAll(filepath.Dir(job.Path), 0o755); err != nil {
		return "", err
	}
	bak := ""
	if readErr == nil {
		bak = job.Path + ".mustra-bak-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.WriteFile(bak, old, 0o600); err != nil {
			return "", fmt.Errorf("back up %s: %w", job.Path, err)
		}
	}
	if err := writeLike(job.Path, data, mode); err != nil {
		return "", fmt.Errorf("write %s: %w", job.Path, err)
	}
	var report strings.Builder
	what := job.Path
	if job.Key != "" {
		what = job.Key + " in " + job.Path
	}
	fmt.Fprintf(&report, "Wrote %s", what)
	if bak != "" {
		fmt.Fprintf(&report, " (backup %s)", filepath.Base(bak))
	}
	report.WriteString(".\n")
	if job.ReloadCmd != "" {
		if out, err := runReload(ctx, job.ReloadCmd); err != nil {
			if bak != "" {
				_ = os.Rename(bak, job.Path)
				_, _ = runReload(ctx, job.ReloadCmd)
			}
			return report.String(), fmt.Errorf("reload failed, the previous file was put back: %v %s", err, strings.TrimSpace(out))
		}
		fmt.Fprintf(&report, "Reloaded with: %s\n", job.ReloadCmd)
	}
	return report.String(), nil
}

// replaceKeyValue sets key's value on its line, keeping the separator and
// any quotes the old value had. It refuses a file without the key, or with
// it more than once, rather than guess.
func replaceKeyValue(text, key, value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", errors.New("a value written into a line cannot span lines; write the whole file instead")
	}
	re := regexp.MustCompile(`(?m)^(\s*(?:export\s+)?` + regexp.QuoteMeta(key) + `\s*[=:]\s*)(["']?)(.*?)(["']?)(\s*)$`)
	matches := re.FindAllStringSubmatchIndex(text, -1)
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no %s line in the file", key)
	case 1:
	default:
		return "", fmt.Errorf("%s appears %d times in the file; write the whole file instead", key, len(matches))
	}
	m := matches[0]
	open, closeQ := text[m[4]:m[5]], text[m[8]:m[9]]
	if open != closeQ {
		open, closeQ = "", ""
	}
	return text[:m[2]] + text[m[2]:m[3]] + open + value + closeQ + text[m[10]:m[11]] + text[m[1]:], nil
}
