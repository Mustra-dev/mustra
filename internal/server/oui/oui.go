// Package oui names the manufacturer behind a MAC address from the IEEE
// MA-L registry (24-bit prefixes), embedded so that answering a question
// about the local network never needs the internet.
//
// oui.tsv.gz is "aa:bb:cc<TAB>Vendor" per line, built from Wireshark's
// manuf file (itself generated from the IEEE registry) with legal suffixes
// such as "Inc." and "Co., Ltd." removed. To refresh it:
//
//	curl -sL https://www.wireshark.org/download/automated/data/manuf.gz
//
// and keep the 24-bit prefixes and long names (see git history for the
// one-off script).
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.tsv.gz
var registry []byte

var (
	once  sync.Once
	byPfx map[string]string
)

func load() {
	byPfx = map[string]string{}
	zr, err := gzip.NewReader(bytes.NewReader(registry))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		if pfx, name, ok := strings.Cut(sc.Text(), "\t"); ok {
			byPfx[pfx] = name
		}
	}
}

// Lookup returns the manufacturer for a MAC address (any case, colon or
// dash separated), or "" when the prefix is not registered.
func Lookup(mac string) string {
	once.Do(load)
	mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
	if len(mac) < 8 {
		return ""
	}
	return byPfx[mac[:8]]
}

// Size reports how many prefixes are loaded (for tests and diagnostics).
func Size() int {
	once.Do(load)
	return len(byPfx)
}
