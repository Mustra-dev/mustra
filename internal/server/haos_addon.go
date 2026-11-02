package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"embed"
	"io/fs"
	"net/http"
	"sync"
	"time"
)

// haosAddonFiles is the Home Assistant OS add-on that runs the agent where
// install.sh cannot (no systemd, no host shell). install.sh unpacks it into
// /addons when it finds itself in the HA SSH add-on.
//
//go:embed haosaddon
var haosAddonFiles embed.FS

var haosAddonTarball = sync.OnceValues(func() ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	sub, err := fs.Sub(haosAddonFiles, "haosaddon")
	if err != nil {
		return nil, err
	}
	err = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(sub, path)
		if err != nil {
			return err
		}
		mode := int64(0o644)
		if path == "run.sh" {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: path, Mode: mode, Size: int64(len(data)), ModTime: time.Unix(0, 0)}); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
})

func (s *Server) handleHAOSAddon(w http.ResponseWriter, r *http.Request) {
	data, err := haosAddonTarball()
	if err != nil {
		http.Error(w, "could not package the add-on", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Write(data)
}
