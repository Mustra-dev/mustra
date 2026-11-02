//go:build windows

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/mustra-dev/mustra/internal/proto"
)

// fileOwner is not resolved on Windows: ownership lives in a security
// descriptor rather than a uid, and reading it properly is a different
// job from hashing. Content, size, mode and mtime still detect change.
func fileOwner(info os.FileInfo) (owner, group string) { return "", "" }

// collectRegistryIntegrity describes each watched registry key as a
// pseudo-file: the hash covers every value (name and rendered data) and
// every subkey name, sorted, so any change to the key changes the hash and
// the server's file diff reports it. Size is the value count.
func collectRegistryIntegrity(keys []string) []proto.IntegrityFile {
	var out []proto.IntegrityFile
	for _, name := range keys {
		root, path, ok := parseRegistryPath(name)
		if !ok {
			continue
		}
		snap, err := readRegSnapshot(root, path)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(snap.values))
		for n := range snap.values {
			names = append(names, n)
		}
		sort.Strings(names)
		subs := make([]string, 0, len(snap.subkeys))
		for s := range snap.subkeys {
			subs = append(subs, s)
		}
		sort.Strings(subs)
		h := sha256.New()
		for _, n := range names {
			fmt.Fprintf(h, "v:%s=%s\n", n, snap.values[n])
		}
		for _, s := range subs {
			fmt.Fprintf(h, "k:%s\n", s)
		}
		out = append(out, proto.IntegrityFile{Path: name, Hash: hex.EncodeToString(h.Sum(nil)), Size: int64(len(names)), Mode: "registry"})
	}
	return out
}

// parseRegistryPath splits "HKLM\SOFTWARE\..." into a root and a subkey.
func parseRegistryPath(name string) (registry.Key, string, bool) {
	name = strings.TrimSpace(name)
	i := strings.Index(name, `\`)
	if i <= 0 {
		return 0, "", false
	}
	root, rest := strings.ToUpper(name[:i]), name[i+1:]
	switch root {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, rest, true
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, rest, true
	case "HKU", "HKEY_USERS":
		return registry.USERS, rest, true
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, rest, true
	}
	return 0, "", false
}
