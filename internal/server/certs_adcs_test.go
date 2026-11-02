package server

import (
	"strings"
	"testing"
)

func TestSplitLeafChain(t *testing.T) {
	a := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	b := "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
	leaf, chain, err := splitLeafChain(a + b)
	if err != nil || leaf != a || chain != b {
		t.Fatalf("leaf %q chain %q err %v", leaf, chain, err)
	}
	leaf, chain, err = splitLeafChain(a)
	if err != nil || leaf != a || chain != "" {
		t.Fatalf("single: leaf %q chain %q err %v", leaf, chain, err)
	}
	if _, _, err := splitLeafChain("certreq: denied"); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatal("no certificate must be an error")
	}
}
