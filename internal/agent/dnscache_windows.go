//go:build windows

package agent

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The DNS client cache, read in-process. Get-DnsClientCache asks the same
// cache through WMI from a PowerShell process; DnsGetCacheDataTable lists
// the cached names and types directly, and a standard DnsQuery for a name
// that is in the cache is answered from it. (DNS_QUERY_NO_WIRE_QUERY, which
// promises cache-only, reports "does not exist" for cached names on Windows
// Server 2025, so it is not used; a name is queried only right after the
// cache listed it, so at worst an entry that expired in between is looked
// up again.) DnsGetCacheDataTable is not in the Windows SDK headers but has
// been exported by dnsapi.dll unchanged since Windows 2000, and
// ipconfig /displaydns is built on it.

var (
	moddnsapi                = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsGetCacheDataTable = moddnsapi.NewProc("DnsGetCacheDataTable")
	procDnsFree              = moddnsapi.NewProc("DnsFree")
)

const (
	dnsQueryStandard = 0
	dnsFreeFlat      = 0
)

// dnsCacheEntry mirrors DNS_CACHE_ENTRY.
type dnsCacheEntry struct {
	next       *dnsCacheEntry
	name       *uint16
	recordType uint16
	dataLength uint16
	flags      uint32
}

// dnsCacheNames lists the cached names of the record types the recorder
// reports: A, AAAA and CNAME.
func dnsCacheNames() ([]dnsCacheKey, error) {
	if err := procDnsGetCacheDataTable.Find(); err != nil {
		return nil, err
	}
	var head *dnsCacheEntry
	r, _, err := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if r == 0 {
		return nil, err
	}
	var out []dnsCacheKey
	for e := head; e != nil; {
		next := e.next
		if e.name != nil {
			switch e.recordType {
			case windows.DNS_TYPE_A, windows.DNS_TYPE_AAAA, windows.DNS_TYPE_CNAME:
				out = append(out, dnsCacheKey{Name: windows.UTF16PtrToString(e.name), Type: e.recordType})
			}
			procDnsFree.Call(uintptr(unsafe.Pointer(e.name)), dnsFreeFlat)
		}
		procDnsFree.Call(uintptr(unsafe.Pointer(e)), dnsFreeFlat)
		e = next
	}
	return out, nil
}

// dnsCacheAnswer reads one cached name's answer: the CNAMEs it passed
// through, in order, then its addresses. Get-DnsClientCache listed each of
// those as a row of its own, so one lookup used to be several events; it
// is now one.
func dnsCacheAnswer(k dnsCacheKey) string {
	var rec *windows.DNSRecord
	if err := windows.DnsQuery(k.Name, k.Type, dnsQueryStandard, nil, &rec, nil); err != nil || rec == nil {
		return ""
	}
	defer windows.DnsRecordListFree(rec, 1)
	var answers []string
	for r := rec; r != nil; r = r.Next {
		switch r.Type {
		case windows.DNS_TYPE_A:
			answers = append(answers, net.IP(r.Data[:4]).String())
		case windows.DNS_TYPE_AAAA:
			answers = append(answers, net.IP(r.Data[:16]).String())
		case windows.DNS_TYPE_CNAME:
			p := (*windows.DNSPTRData)(unsafe.Pointer(&r.Data[0]))
			if p.Host != nil {
				answers = append(answers, windows.UTF16PtrToString(p.Host))
			}
		}
	}
	return joinAnswers(answers)
}
