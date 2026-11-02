package agent

import (
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// A rendered Security 4625 event, as EvtRender returns it.
const sample4625 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-10-27T14:41:48.3912345Z'/><EventRecordID>48211907</EventRecordID><Correlation/><Execution ProcessID='716' ThreadID='4012'/><Channel>Security</Channel><Computer>SRV01.corp.example.com</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='TargetUserName'>alex</Data><Data Name='TargetDomainName'>AD</Data><Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>192.0.2.50</Data></EventData></Event>`

func TestParseEventXMLFeedsTheLogonMapping(t *testing.T) {
	e, err := parseEventXML(sample4625)
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != 4625 || e.Record != 48211907 || e.At.IsZero() || e.Data["TargetUserName"] != "alex" {
		t.Fatalf("parsed %+v", e)
	}
	d := e.Data
	ev, ok := logonFromSecurity(e.ID, e.At.Format(time.RFC3339Nano), d["TargetUserName"], d["TargetDomainName"], d["LogonType"],
		d["IpAddress"], d["ProcessName"], d["Status"], d["SubStatus"], d["SubjectUserName"])
	if !ok || ev.Op != "failure" || ev.Reason != "bad password" || ev.Source != "192.0.2.50" || ev.LogonType != "network" {
		t.Fatalf("logon event %+v", ev)
	}
	if _, err := parseEventXML("<Event><System>"); err == nil {
		t.Fatal("broken XML parsed")
	}
}

func TestSensorPhasesSpreadTheExpensiveSensors(t *testing.T) {
	seen := map[time.Duration]bool{}
	for _, k := range sensorPhases {
		off := sensorPhaseOffset(k)
		if seen[off] {
			t.Fatalf("%s shares offset %s", k, off)
		}
		seen[off] = true
	}
	if off := sensorPhaseOffset(proto.SensorHardware); off != 0 {
		t.Fatalf("a cheap sensor waits %s", off)
	}
	if last := sensorPhaseOffset(sensorPhases[len(sensorPhases)-1]); last > 2*time.Minute {
		t.Fatalf("the last expensive sensor starts %s after the agent", last)
	}
}
