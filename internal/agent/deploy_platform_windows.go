package agent

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var wtsDeploy = windows.NewLazySystemDLL("wtsapi32.dll")

func deployUser(wanted string) (string, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xffffffff {
		return "", fmt.Errorf("no active console session")
	}
	var token windows.Token
	r, _, e := wtsDeploy.NewProc("WTSQueryUserToken").Call(uintptr(session), uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return "", e
	}
	defer token.Close()
	u, e := token.GetTokenUser()
	if e != nil {
		return "", e
	}
	name, domain, _, e := u.User.Sid.LookupAccount("")
	if e != nil {
		return "", e
	}
	full := domain + "\\" + name
	if wanted != "" && !strings.EqualFold(wanted, name) && !strings.EqualFold(wanted, full) {
		return "", fmt.Errorf("active session belongs to another user")
	}
	return full, nil
}
func configureDeployUser(ctx context.Context, cmd *exec.Cmd, wanted, dir string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	name, e := deployUser(wanted)
	if e != nil {
		return e
	}
	session := windows.WTSGetActiveConsoleSessionId()
	var token windows.Token
	r, _, e := wtsDeploy.NewProc("WTSQueryUserToken").Call(uintptr(session), uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return e
	}
	// exec.Cmd uses the token during Start; keep a duplicate alive for this command.
	cmd.SysProcAttr.Token = syscall.Token(token)
	env, e := token.Environ(false)
	if e != nil {
		cleanupDeployUser(cmd)
		return e
	}
	for _, v := range cmd.Env {
		if strings.HasPrefix(v, "MUSTRA_") {
			env = append(env, v)
		}
	}
	cmd.Env = env
	if e = exec.CommandContext(ctx, "icacls.exe", dir, "/grant", name+":(OI)(CI)F", "/T", "/Q").Run(); e != nil {
		cleanupDeployUser(cmd)
		return e
	}
	return nil
}
func deployRegistryValue(path, name string) (string, error) {
	root, sub, ok := strings.Cut(path, `\`)
	if !ok {
		return "", fmt.Errorf("invalid registry path")
	}
	key, ok := registryRoots[strings.ToUpper(root)]
	if !ok {
		return "", fmt.Errorf("invalid registry root")
	}
	k, e := registry.OpenKey(key, sub, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e != nil {
		return "", e
	}
	defer k.Close()
	return readRegistryValue(k, name)
}
func deployFileVersion(ctx context.Context, path string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `(Get-Item -LiteralPath $env:MUSTRA_FILE).VersionInfo.FileVersion`)
	cmd.Env = append(cmd.Environ(), "MUSTRA_FILE="+path)
	out, e := cmd.Output()
	return strings.TrimSpace(string(out)), e
}
func deployReboot(ctx context.Context) error {
	return exec.CommandContext(ctx, "shutdown.exe", "/r", "/t", "60").Run()
}

func cleanupDeployUser(cmd *exec.Cmd) {
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Token != 0 {
		_ = windows.Token(cmd.SysProcAttr.Token).Close()
		cmd.SysProcAttr.Token = 0
	}
}
