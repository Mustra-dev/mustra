package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Alpine's package manager, apk. Installed packages come from its database
// file rather than a command (it is plain text, and apk has no stable
// machine-readable listing); pending updates from `apk version -l '<'`,
// which compares against the index apk last fetched without fetching
// again, as the apt path does.

const apkInstalledDB = "/lib/apk/db/installed"

// apkPresent reports whether this host's packages are apk's.
func apkPresent() bool {
	if _, err := exec.LookPath("apk"); err != nil {
		return false
	}
	_, err := os.Stat(apkInstalledDB)
	return err == nil
}

// apkPackage is one record of the installed database: P name, V version,
// A architecture, o origin (source package), t build time.
type apkPackage struct {
	Name, Version, Arch, Origin string
	BuildTime                   int64
}

// parseApkInstalled reads the installed database: records separated by a
// blank line, one "X:value" field per line.
func parseApkInstalled(db string) []apkPackage {
	var out []apkPackage
	var cur apkPackage
	flush := func() {
		if cur.Name != "" {
			out = append(out, cur)
		}
		cur = apkPackage{}
	}
	for _, line := range strings.Split(db, "\n") {
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		v := line[2:]
		switch line[0] {
		case 'P':
			cur.Name = v
		case 'V':
			cur.Version = v
		case 'A':
			cur.Arch = v
		case 'o':
			cur.Origin = v
		case 't':
			fmt.Sscan(v, &cur.BuildTime)
		}
	}
	flush()
	return out
}

func collectAppsAPK() ([]proto.InstalledApp, error) {
	raw, err := os.ReadFile(apkInstalledDB)
	if err != nil {
		return nil, err
	}
	return apkApps(parseApkInstalled(string(raw))), nil
}

// apkApps reports installed packages with their origin, the source package
// Alpine's advisories are filed under; an origin's version is its
// packages' version.
func apkApps(pkgs []apkPackage) []proto.InstalledApp {
	apps := make([]proto.InstalledApp, 0, len(pkgs))
	for _, p := range pkgs {
		apps = append(apps, proto.InstalledApp{Name: p.Name, Version: p.Version, Source: p.Origin, SourceVersion: p.Version})
	}
	return apps
}

// collectPatchesAPK lists the installed packages the cached index has a
// newer version of.
func collectPatchesAPK(ctx context.Context) ([]proto.PatchInfo, error) {
	raw, err := os.ReadFile(apkInstalledDB)
	if err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, "apk", "version", "-l", "<").Output()
	if err != nil {
		return nil, fmt.Errorf("apk version: %w", err)
	}
	return parseApkVersion(string(out), parseApkInstalled(string(raw))), nil
}

// parseApkVersion reads `apk version -l '<'`: "name-oldversion < newversion"
// under a header line. A package name may itself contain dashes and digits,
// so the name is found by matching "name-version" against the installed
// database rather than by splitting the string.
func parseApkVersion(out string, installed []apkPackage) []proto.PatchInfo {
	byFull := make(map[string]apkPackage, len(installed))
	for _, p := range installed {
		byFull[p.Name+"-"+p.Version] = p
	}
	var patches []proto.PatchInfo
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[1] != "<" {
			continue
		}
		p, ok := byFull[f[0]]
		if !ok {
			continue
		}
		patch := proto.PatchInfo{Name: p.Name, CurrentVersion: p.Version, NewVersion: f[2]}
		if apkKernelPackage(p.Name) {
			patch.RestartRequired = true
		}
		patches = append(patches, patch)
	}
	return patches
}

// apkKernelPackage reports whether a package is a kernel, which takes a
// restart to run.
func apkKernelPackage(name string) bool {
	return name == "linux-lts" || name == "linux-virt" || name == "linux-edge" || strings.HasPrefix(name, "linux-rpi") || name == "linux-stable"
}

// apkKernelReplaced reports whether the running kernel's modules are gone,
// which is how an upgraded kernel package shows on Alpine: it removes the
// old /lib/modules/<release> directory, and the host needs a restart to run
// the new one. A host without /lib/modules (a container) never does.
func apkKernelReplaced() bool {
	if _, err := os.Stat("/lib/modules"); err != nil {
		return false
	}
	rel, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return false
	}
	_, err = os.Stat("/lib/modules/" + strings.TrimSpace(string(rel)))
	return os.IsNotExist(err)
}

// apkUpdateTimeout bounds the index refresh before an upgrade.
const apkUpdateTimeout = 5 * time.Minute
