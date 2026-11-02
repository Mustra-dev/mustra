package agent

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// winEvent is the part of a rendered event the recorder reads.
type winEvent struct {
	ID     int
	Record int64
	At     time.Time
	Data   map[string]string
}

// parseEventXML reads the System and EventData parts of a rendered event.
func parseEventXML(s string) (winEvent, error) {
	var x struct {
		System struct {
			EventID       int   `xml:"EventID"`
			EventRecordID int64 `xml:"EventRecordID"`
			TimeCreated   struct {
				SystemTime string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
		} `xml:"System"`
		EventData struct {
			Data []struct {
				Name  string `xml:"Name,attr"`
				Value string `xml:",chardata"`
			} `xml:"Data"`
		} `xml:"EventData"`
	}
	if err := xml.Unmarshal([]byte(s), &x); err != nil {
		return winEvent{}, err
	}
	ev := winEvent{ID: x.System.EventID, Record: x.System.EventRecordID, Data: map[string]string{}}
	ev.At, _ = time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime)
	for _, d := range x.EventData.Data {
		if d.Name != "" {
			ev.Data[d.Name] = strings.TrimSpace(d.Value)
		}
	}
	return ev, nil
}

// dnsCacheKey is one cached name and record type.
type dnsCacheKey struct {
	Name string
	Type uint16
}

// joinAnswers renders a cached name's answers the way the console shows
// them, in the order the cache holds them.
func joinAnswers(a []string) string { return strings.Join(a, ", ") }

var logonTypes = map[string]string{"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock", "8": "network-cleartext", "9": "new-credentials", "10": "remote-interactive", "11": "cached-interactive"}

func logonFromSecurity(id int, at, user, domain, typ, ip, procName, status, substatus, subject string) (proto.RecorderEvent, bool) {
	// Machine accounts and the pseudo-users that log on constantly are the
	// noise floor of a domain controller; the ones a person can use are
	// what the feed is for.
	if strings.HasSuffix(user, "$") || user == "" || user == "-" || strings.EqualFold(user, "ANONYMOUS LOGON") || strings.EqualFold(domain, "NT AUTHORITY") || strings.EqualFold(domain, "Window Manager") || strings.EqualFold(domain, "Font Driver Host") {
		return proto.RecorderEvent{}, false
	}
	if typ == "5" || typ == "0" { // service logons happen every few seconds
		return proto.RecorderEvent{}, false
	}
	t, _ := time.Parse(time.RFC3339Nano, at)
	ev := proto.RecorderEvent{Kind: "logon", At: t, User: user, Domain: domain, Source: ip, LogonType: typ, Process: procName}
	if name, ok := logonTypes[typ]; ok {
		ev.LogonType = name
	}
	if ip == "-" || ip == "" {
		ev.Source = "local"
	}
	switch id {
	case 4624:
		ev.Op = "success"
		ev.Summary = fmt.Sprintf("%s\\%s logged on (%s) from %s", domain, user, ev.LogonType, ev.Source)
	case 4625:
		ev.Op = "failure"
		ev.Reason = failureReason(status, substatus)
		ev.Summary = fmt.Sprintf("%s\\%s failed to log on (%s) from %s: %s", domain, user, ev.LogonType, ev.Source, ev.Reason)
	case 4648:
		ev.Op = "explicit"
		ev.Summary = fmt.Sprintf("%s used explicit credentials for %s\\%s", subject, domain, user)
	default:
		return ev, false
	}
	return ev, true
}

func failureReason(status, substatus string) string {
	codes := map[string]string{
		"0xc000006a": "bad password", "0xc0000064": "no such user", "0xc0000234": "account locked out",
		"0xc0000072": "account disabled", "0xc000006f": "outside logon hours", "0xc0000070": "workstation restriction",
		"0xc0000193": "account expired", "0xc0000071": "password expired", "0xc0000133": "clock skew", "0xc000015b": "logon type not granted",
	}
	for _, c := range []string{strings.ToLower(substatus), strings.ToLower(status)} {
		if v, ok := codes[c]; ok {
			return v
		}
	}
	return "status " + status
}

func eventFromSysmon(id int, at string, d map[string]string) (proto.RecorderEvent, bool) {
	t, _ := time.Parse(time.RFC3339Nano, at)
	image := d["Image"]
	proc := image
	if i := strings.LastIndex(image, `\`); i >= 0 {
		proc = image[i+1:]
	}
	switch id {
	case 12, 13, 14:
		op := map[string]string{"CreateKey": "create", "DeleteKey": "delete", "SetValue": "set", "DeleteValue": "delete", "RenameKey": "rename"}[d["EventType"]]
		if op == "" {
			op = strings.ToLower(d["EventType"])
		}
		key := d["TargetObject"]
		ev := proto.RecorderEvent{Kind: "registry", At: t, Op: op, Key: key, Data: truncate(d["Details"], 512), Process: proc, User: d["User"]}
		ev.Summary = fmt.Sprintf("%s %s %s", proc, op, key)
		if ev.Data != "" {
			ev.Summary += " = " + ev.Data
		}
		return ev, true
	case 22:
		ev := proto.RecorderEvent{Kind: "dns", At: t, Op: "query", Query: d["QueryName"], Answers: d["QueryResults"], Process: proc, User: d["User"]}
		ev.Summary = proc + " resolved " + d["QueryName"]
		return ev, true
	case 3:
		ev := proto.RecorderEvent{Kind: "network", At: t, Op: "connect", Process: proc, User: d["User"], Protocol: strings.ToLower(d["Protocol"]),
			LocalIP: d["SourceIp"], RemoteIP: d["DestinationIp"]}
		fmt.Sscanf(d["SourcePort"], "%d", &ev.LocalPort)
		fmt.Sscanf(d["DestinationPort"], "%d", &ev.RemotePort)
		if d["Initiated"] == "false" {
			ev.Op = "accept"
		}
		ev.Summary = fmt.Sprintf("%s -> %s:%s (%s)", proc, d["DestinationIp"], d["DestinationPort"], ev.Protocol)
		return ev, true
	}
	return proto.RecorderEvent{}, false
}
