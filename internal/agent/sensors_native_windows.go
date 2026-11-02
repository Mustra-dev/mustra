//go:build windows

package agent

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Services and installed applications, read in-process. Both used to start
// PowerShell (Get-Service, Get-ItemProperty over the Uninstall keys) every
// sensor interval; the Service Control Manager and the registry answer the
// same questions directly, with the same values: Get-Service's Status and
// StartType are the SCM's own state and start-type codes.

func collectServicesNative(ctx context.Context) ([]proto.ServiceInfo, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("open service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	var needed, count, resume uint32
	buf := make([]byte, 64*1024)
	for {
		err = windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32,
			windows.SERVICE_STATE_ALL, &buf[0], uint32(len(buf)), &needed, &count, &resume, nil)
		if err == nil {
			break
		}
		if err != windows.ERROR_MORE_DATA || needed <= uint32(len(buf)) {
			return nil, fmt.Errorf("enumerate services: %w", err)
		}
		buf, resume = make([]byte, needed), 0
	}
	entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
	out := make([]proto.ServiceInfo, 0, count)
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		name := windows.UTF16PtrToString(e.ServiceName)
		out = append(out, proto.ServiceInfo{
			Name:        name,
			DisplayName: windows.UTF16PtrToString(e.DisplayName),
			Status:      windowsServiceStatus(int(e.ServiceStatusProcess.CurrentState)),
			StartType:   windowsServiceStartType(serviceStartType(name)),
		})
	}
	return out, nil
}

// serviceStartType reads a service's start type from its registry key, the
// same value QueryServiceConfig reports, without opening the service.
func serviceStartType(name string) int {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE)
	if err != nil {
		return -1
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("Start")
	if err != nil {
		return -1
	}
	return int(v)
}

// uninstallKeys are where installers register what they installed, for
// 64- and 32-bit programs.
var uninstallKeys = []struct {
	path  string
	flags uint32
}{
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_64KEY},
	{`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_64KEY},
}

// installedAppRaw is one Uninstall entry with a display name.
type installedAppRaw struct {
	DisplayName, DisplayVersion, Publisher, InstallDate, DisplayIcon string
}

func collectAppsNative(ctx context.Context) ([]installedAppRaw, error) {
	var out []installedAppRaw
	opened := 0
	for _, u := range uninstallKeys {
		root, err := registry.OpenKey(registry.LOCAL_MACHINE, u.path, registry.ENUMERATE_SUB_KEYS|u.flags)
		if err != nil {
			continue
		}
		opened++
		names, _ := root.ReadSubKeyNames(-1)
		root.Close()
		for _, n := range names {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, u.path+`\`+n, registry.QUERY_VALUE|u.flags)
			if err != nil {
				continue
			}
			str := func(v string) string { s, _, _ := k.GetStringValue(v); return strings.TrimSpace(s) }
			a := installedAppRaw{DisplayName: str("DisplayName"), DisplayVersion: str("DisplayVersion"),
				Publisher: str("Publisher"), InstallDate: str("InstallDate"), DisplayIcon: str("DisplayIcon")}
			k.Close()
			if a.DisplayName != "" {
				out = append(out, a)
			}
		}
	}
	if opened == 0 {
		return nil, fmt.Errorf("could not open the Uninstall registry keys")
	}
	return out, nil
}
