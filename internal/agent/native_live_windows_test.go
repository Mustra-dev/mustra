//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestLiveNativeCollectors compares each native collector with the
// PowerShell command it replaced, on a real Windows machine, and reports
// the CPU each costs. Opt-in: MUSTRA_LIVE_WINDOWS=1.
func TestLiveNativeCollectors(t *testing.T) {
	if os.Getenv("MUSTRA_LIVE_WINDOWS") == "" {
		t.Skip("set MUSTRA_LIVE_WINDOWS=1 on a Windows machine")
	}
	ctx := context.Background()
	cpu := func() time.Duration {
		var c, e, k, u windows.Filetime
		windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u)
		return time.Duration(k.Nanoseconds() + u.Nanoseconds())
	}
	ps := func(script string) (string, time.Duration) {
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		out, _ := cmd.Output()
		var used time.Duration
		if cmd.ProcessState != nil {
			used = cmd.ProcessState.UserTime() + cmd.ProcessState.SystemTime()
		}
		return strings.TrimSpace(string(out)), used
	}
	measure := func(name string, f func() int, psScript string) {
		before := cpu()
		n := f()
		native := cpu() - before
		psOut, psCPU := ps(psScript)
		t.Logf("%-14s native: %4d items, %6.3fs CPU | powershell: %s items, %6.3fs CPU", name, n, native.Seconds(), psOut, psCPU.Seconds())
	}
	measure("services", func() int {
		s, err := collectServicesNative(ctx)
		if err != nil {
			t.Error(err)
		}
		return len(s)
	},
		"@(Get-Service).Count")
	measure("installed apps", func() int {
		a, err := collectAppsNative(ctx)
		if err != nil {
			t.Error(err)
		}
		return len(a)
	},
		`@(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }).Count`)
	measure("local admins", func() int {
		a, err := collectLocalAdmins(ctx)
		if err != nil {
			t.Error(err)
		}
		b, _ := json.Marshal(a)
		t.Logf("  local admins: %s", b)
		return len(a)
	}, `try { @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop).Count } catch { 'n/a (no local SAM)' }`)
	measure("certificates", func() int { return len(windowsStoreCertificates(ctx)) },
		`$n=0; foreach ($s in 'My','WebHosting','Remote Desktop') { $p="Cert:\LocalMachine\$s"; if (Test-Path -LiteralPath $p) { $n += @(Get-ChildItem -LiteralPath $p).Count } }; $n`)
	measure("dns cache", func() int {
		k, err := dnsCacheNames()
		if err != nil {
			t.Error(err)
		}
		withAnswers := 0
		for _, x := range k {
			if dnsCacheAnswer(x) != "" {
				withAnswers++
			}
		}
		t.Logf("  dns cache: %d names, %d with cached answers", len(k), withAnswers)
		return len(k)
	}, `@(Get-DnsClientCache | Where-Object { $_.Type -in 1, 28, 5 -and $_.Data } | Select-Object -Unique Entry,Type).Count`)

	// The Security subscription: open it, cause a failed network logon
	// against this machine, and see the 4625 arrive.
	sub, err := subscribeEvents("Security", "*[System[(EventID=4624 or EventID=4625 or EventID=4648)]]")
	if err != nil {
		t.Fatalf("subscribe Security: %v", err)
	}
	defer sub.Close()
	before := cpu()
	exec.Command("net", "use", `\\127.0.0.1\IPC$`, "/user:mustra-probe-nonexistent", "wrong-password").Run()
	got := 0
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && got == 0 {
		if sub.wait(ctx, 2*time.Second) {
			evs, err := sub.drain(500)
			if err != nil {
				t.Error(err)
			}
			for _, e := range evs {
				if e.ID == 4625 && strings.EqualFold(e.Data["TargetUserName"], "mustra-probe-nonexistent") {
					got++
					t.Logf("  4625 via subscription: record %d at %s, status %s/%s", e.Record, e.At.Format(time.RFC3339), e.Data["Status"], e.Data["SubStatus"])
				}
			}
		}
	}
	if got == 0 {
		t.Error("the failed logon never arrived through the subscription")
	}
	t.Logf("security sub   %6.3fs CPU while waiting and reading", (cpu() - before).Seconds())
	if s, err := subscribeEvents("Microsoft-Windows-Sysmon/Operational", "*"); err == nil {
		t.Log("  sysmon channel: present")
		s.Close()
	} else {
		t.Logf("  sysmon channel: %v", err)
	}
}

// TestLiveRecorderCost runs what the recorder now runs, the Security
// subscription and the DNS cache read every 15 s, for a minute, and
// reports the CPU it used. Opt-in: MUSTRA_LIVE_WINDOWS=1.
func TestLiveRecorderCost(t *testing.T) {
	if os.Getenv("MUSTRA_LIVE_WINDOWS") == "" {
		t.Skip("set MUSTRA_LIVE_WINDOWS=1 on a Windows machine")
	}
	cpu := func() time.Duration {
		var c, e, k, u windows.Filetime
		windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u)
		return time.Duration(k.Nanoseconds() + u.Nanoseconds())
	}
	sub, err := subscribeEvents("Security", "*[System[(EventID=4624 or EventID=4625 or EventID=4648)]]")
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	before, events, lookups := cpu(), 0, 0
	end := time.Now().Add(60 * time.Second)
	nextDNS := time.Now()
	known := map[dnsCacheKey]bool{}
	for time.Now().Before(end) {
		if sub.wait(context.Background(), time.Second) {
			evs, _ := sub.drain(500)
			events += len(evs)
		}
		if time.Now().After(nextDNS) {
			keys, _ := dnsCacheNames()
			cur := map[dnsCacheKey]bool{}
			for _, k := range keys {
				cur[k] = true
				if !known[k] {
					dnsCacheAnswer(k)
					lookups++
				}
			}
			known, nextDNS = cur, time.Now().Add(15*time.Second)
		}
	}
	used := cpu() - before
	t.Logf("recorder for 60 s: %d logon events, %d DNS lookups, %.3f CPU-seconds = %.4f cores", events, lookups, used.Seconds(), used.Seconds()/60)
}
