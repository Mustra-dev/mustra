package deploylog

import (
	"archive/zip"
	"bytes"
	"github.com/mustra-dev/mustra/internal/proto"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRotationArchivesOnlyAfterFiveFiles(t *testing.T) {
	dir := t.TempDir()
	l, e := Open(dir, proto.DeployLogSettings{ArchiveMB: 100, RotateMB: 1, CompressFiles: 5})
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 4; i++ {
		if _, e = l.Write(bytes.Repeat([]byte("a"), 1000000)); e != nil {
			t.Fatal(e)
		}
	}
	z, _ := filepath.Glob(filepath.Join(dir, "*.zip"))
	if len(z) != 0 {
		t.Fatal("compressed before five rotations")
	}
	if _, e = l.Write(bytes.Repeat([]byte("b"), 1000000)); e != nil {
		t.Fatal(e)
	}
	z, _ = filepath.Glob(filepath.Join(dir, "*.zip"))
	if len(z) != 1 {
		t.Fatalf("want one archive, got %d", len(z))
	}
	r, e := zip.OpenReader(z[0])
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if len(r.File) != 5 {
		t.Fatalf("archive has %d segments", len(r.File))
	}
	var size int64
	for _, f := range r.File {
		in, _ := f.Open()
		n, e := io.Copy(io.Discard, in)
		in.Close()
		if e != nil {
			t.Fatal(e)
		}
		size += n
	}
	if size != 5000000 {
		t.Fatalf("lost log bytes: %d", size)
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	if len(segs) != 0 {
		t.Fatal("uncompressed completed segments retained")
	}
	if _, e = os.Stat(z[0]); e != nil {
		t.Fatal("age=0 should retain archive")
	}
}

func TestRotationPreservesRecords(t *testing.T) {
	dir := t.TempDir()
	l, e := Open(dir, proto.DeployLogSettings{ArchiveMB: 100, RotateMB: 1, CompressFiles: 5})
	if e != nil {
		t.Fatal(e)
	}
	line := append(bytes.Repeat([]byte("x"), 599999), '\n')
	for i := 0; i < 2; i++ {
		if _, e = l.Write(line); e != nil {
			t.Fatal(e)
		}
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	if len(paths) != 2 {
		t.Fatal(paths)
	}
	for _, path := range paths {
		data, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(data, line) {
			t.Fatal("rotation split a record", path, e)
		}
	}
}
