package agent

import (
	"reflect"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

const apkDBFixture = `C:Q1VUDpgJeUrOn4O34ZOihImI9hYis=
P:acl-libs
V:2.3.2-r1
A:x86_64
o:acl
t:1735923921
F:usr
R:libacl.so.1
Z:Q1tO6n8mNmxrWYcNE/D0ES1Q4VF9Y=

C:Q11ELKnukdume+ToP0JdC1XXr46jM=
P:busybox-binsh
V:1.37.0-r18
A:x86_64
o:busybox

P:linux-virt
V:6.12.30-r0
A:x86_64
o:linux-lts
`

func TestParseApkInstalled(t *testing.T) {
	got := parseApkInstalled(apkDBFixture)
	want := []apkPackage{
		{Name: "acl-libs", Version: "2.3.2-r1", Arch: "x86_64", Origin: "acl", BuildTime: 1735923921},
		{Name: "busybox-binsh", Version: "1.37.0-r18", Arch: "x86_64", Origin: "busybox"},
		{Name: "linux-virt", Version: "6.12.30-r0", Arch: "x86_64", Origin: "linux-lts"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestParseApkVersion(t *testing.T) {
	out := "Installed:                                Available:\n" +
		"busybox-binsh-1.37.0-r18                < 1.37.0-r20 \n" +
		"linux-virt-6.12.30-r0                   < 6.12.41-r0 \n" +
		"not-installed-1.0-r0                    < 1.1-r0 \n" +
		"acl-libs-2.3.2-r1                       = 2.3.2-r1 \n"
	want := []proto.PatchInfo{
		{Name: "busybox-binsh", CurrentVersion: "1.37.0-r18", NewVersion: "1.37.0-r20"},
		{Name: "linux-virt", CurrentVersion: "6.12.30-r0", NewVersion: "6.12.41-r0", RestartRequired: true},
	}
	if got := parseApkVersion(out, parseApkInstalled(apkDBFixture)); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestApkAppsReportOrigin(t *testing.T) {
	apps := apkApps(parseApkInstalled(apkDBFixture))
	want := proto.InstalledApp{Name: "busybox-binsh", Version: "1.37.0-r18", Source: "busybox", SourceVersion: "1.37.0-r18"}
	if len(apps) != 3 || apps[1] != want {
		t.Errorf("got %+v, want busybox-binsh as %+v", apps, want)
	}
}
