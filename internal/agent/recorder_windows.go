//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Windows: three producers.
//
//	registry  a Go-native diff of the persistence keys every few seconds —
//	          no PowerShell, no audit policy, no Sysmon needed. It sees the
//	          keys an attacker writes to survive a reboot, which is the
//	          registry activity worth an event; a full registry feed needs
//	          Sysmon, and when Sysmon is installed its events 12/13/14 are
//	          taken as well.
//	logon     the Security log: 4624 (logon), 4625 (failed), 4648
//	          (explicit credentials), by event log subscription, so each
//	          event arrives once, as it is written.
//	dns       new entries in the DNS client cache, read in-process, which
//	          is the cheapest honest answer to "what did this box resolve"
//	          without enabling the DNS-Client operational log; Sysmon 22
//	          when present.
func startRecorderPlatform(ctx context.Context, r *recorder) {
	r.setSource("registry", "regpoll")
	r.setSource("logon", "winevent")
	r.setSource("dns", "dnscache")
	go r.registryLoop(ctx)
	go r.windowsEventLoop(ctx)
}

// Persistence keys watched for changes. Values are compared by name and
// data; subkeys by name. HKCU is not watched: the agent runs as SYSTEM and
// sees SYSTEM's hive, not the user's; the per-user Run keys are covered by
// Sysmon when it is present.
var registryWatch = []struct {
	root registry.Key
	path string
	name string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`},
	{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, `HKLM\SYSTEM\CurrentControlSet\Services`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`},
	{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`},
	{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`, `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows Defender`, `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`},
}

type regSnapshot struct {
	values  map[string]string // value name -> rendered data
	subkeys map[string]bool
}

func readRegSnapshot(root registry.Key, path string) (regSnapshot, error) {
	snap := regSnapshot{values: map[string]string{}, subkeys: map[string]bool{}}
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return snap, err
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	for _, n := range names {
		if v, err := readRegistryValue(k, n); err == nil {
			snap.values[n] = truncate(v, 512)
		}
	}
	subs, _ := k.ReadSubKeyNames(-1)
	for _, s := range subs {
		snap.subkeys[s] = true
	}
	return snap, nil
}

func (r *recorder) registryLoop(ctx context.Context) {
	last := map[string]regSnapshot{}
	first := true
	tick := time.NewTicker(recorderPollInterval)
	defer tick.Stop()
	for {
		for _, w := range registryWatch {
			cur, err := readRegSnapshot(w.root, w.path)
			if err != nil {
				continue
			}
			prev, had := last[w.name]
			last[w.name] = cur
			if first || !had {
				continue
			}
			for name, data := range cur.values {
				old, existed := prev.values[name]
				if !existed {
					r.emit(proto.RecorderEvent{Kind: "registry", Op: "create", Key: w.name, ValueName: name, Data: data, Summary: fmt.Sprintf("%s\\%s created = %s", w.name, valueLabel(name), data)})
				} else if old != data {
					r.emit(proto.RecorderEvent{Kind: "registry", Op: "set", Key: w.name, ValueName: name, Data: data, Summary: fmt.Sprintf("%s\\%s set = %s (was %s)", w.name, valueLabel(name), data, old)})
				}
			}
			for name := range prev.values {
				if _, still := cur.values[name]; !still {
					r.emit(proto.RecorderEvent{Kind: "registry", Op: "delete", Key: w.name, ValueName: name, Summary: fmt.Sprintf("%s\\%s deleted", w.name, valueLabel(name))})
				}
			}
			for sub := range cur.subkeys {
				if !prev.subkeys[sub] {
					r.emit(proto.RecorderEvent{Kind: "registry", Op: "create", Key: w.name + `\` + sub, Summary: fmt.Sprintf("%s\\%s key created", w.name, sub)})
				}
			}
			for sub := range prev.subkeys {
				if !cur.subkeys[sub] {
					r.emit(proto.RecorderEvent{Kind: "registry", Op: "delete", Key: w.name + `\` + sub, Summary: fmt.Sprintf("%s\\%s key deleted", w.name, sub)})
				}
			}
		}
		first = false
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func valueLabel(name string) string {
	if name == "" {
		return "(Default)"
	}
	return name
}

// windowsEventLoop follows the Security log for logons and Sysmon's log
// when it exists, by event log subscription, and the DNS client cache by
// reading it in-process. It used to start PowerShell every fifteen seconds
// to poll all three, which on a two-core server was most of the agent's
// constant CPU (winevent_windows.go).
func (r *recorder) windowsEventLoop(ctx context.Context) {
	go r.followChannel(ctx, "Security",
		"*[System[(EventID=4624 or EventID=4625 or EventID=4648)]]",
		func(e winEvent) {
			d := e.Data
			if ev, ok := logonFromSecurity(e.ID, e.At.Format(time.RFC3339Nano), d["TargetUserName"], d["TargetDomainName"], d["LogonType"],
				d["IpAddress"], d["ProcessName"], d["Status"], d["SubStatus"], d["SubjectUserName"]); ok {
				r.emit(ev)
			}
		}, nil)
	go r.followChannel(ctx, "Microsoft-Windows-Sysmon/Operational",
		"*[System[(EventID=3 or EventID=12 or EventID=13 or EventID=14 or EventID=22)]]",
		func(e winEvent) {
			if ev, ok := eventFromSysmon(e.ID, e.At.Format(time.RFC3339Nano), e.Data); ok {
				r.emit(ev)
			}
		}, func() {
			r.setSource("registry", "regpoll+sysmon")
			r.setSource("dns", "dnscache+sysmon")
		})
	r.dnsCacheLoop(ctx)
}

// recorderEventsPerWake bounds what one wake-up reads; the rest of a burst
// is skipped rather than queued (see drain).
const recorderEventsPerWake = 500

// followChannel subscribes to channel and hands each matching event to
// handle as it arrives. A channel that does not exist yet (Sysmon not
// installed) or a subscription that breaks (the event log service
// restarting) is retried every few minutes; opened runs once it is open.
func (r *recorder) followChannel(ctx context.Context, channel, query string, handle func(winEvent), opened func()) {
	warned := false
	for ctx.Err() == nil {
		sub, err := subscribeEvents(channel, query)
		if err != nil {
			if !errors.Is(err, errEvtChannelNotFound) && !warned {
				r.agent.logger.Warn("event log subscription failed; retrying", "channel", channel, "error", err)
				warned = true
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Minute):
			}
			continue
		}
		warned = false
		if opened != nil {
			opened()
		}
		for ctx.Err() == nil {
			// The timeout only bounds how long a cancelled ctx goes
			// unnoticed; events wake the wait at once.
			if !sub.wait(ctx, 30*time.Second) {
				continue
			}
			events, err := sub.drain(recorderEventsPerWake)
			for _, e := range events {
				handle(e)
			}
			if err != nil {
				r.agent.logger.Warn("event log subscription broke; reopening", "channel", channel, "error", err)
				break
			}
		}
		sub.Close()
	}
}

// dnsCacheLoop reports names newly in the DNS client cache. The cache is a
// set: what is new since the last look was resolved in between. Entries
// that expire and come back are reported again, which is right; they were
// resolved again. Only new names are looked up for their answers.
func (r *recorder) dnsCacheLoop(ctx context.Context) {
	known := map[dnsCacheKey]bool{}
	first, warned := true, false
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		keys, err := dnsCacheNames()
		if err != nil {
			if !warned {
				r.agent.logger.Warn("reading the DNS client cache failed", "error", err)
				warned = true
			}
		} else {
			cur := make(map[dnsCacheKey]bool, len(keys))
			for _, k := range keys {
				k.Name = strings.ToLower(k.Name)
				cur[k] = true
				if first || known[k] {
					continue
				}
				if answers := dnsCacheAnswer(k); answers != "" {
					r.emit(proto.RecorderEvent{Kind: "dns", Op: "query", Query: k.Name, Answers: answers, Summary: k.Name + " -> " + answers})
				}
			}
			known, first = cur, false
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
