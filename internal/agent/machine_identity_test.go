package agent

import "testing"

func TestIdentityHelpers(t *testing.T) {
	for in, want := range map[string]string{"08/17/2023": "2023-08-17", "20230817000000.000000+000": "2023-08-17", "2023-08-17": "2023-08-17", "junk": ""} {
		if got := normalizeBIOSDate(in); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
	if cleanIdentity("Latitude 5480") != "Latitude 5480" || cleanIdentity("ABC0x\x00") != "ABC0x" {
		t.Error("trailing 0 and x are part of a model or serial; only NUL padding goes")
	}
	if !virtualVendor("QEMU Standard PC (Q35 + ICH9, 2009)") || !virtualVendor("Microsoft Corporation Virtual Machine") || virtualVendor("Dell Inc. Latitude 5480") {
		t.Error("virtual vendors")
	}
	if cleanIdentity("To Be Filled By O.E.M.") != "" || cleanIdentity(" Dell Inc. ") != "Dell Inc." {
		t.Error("firmware placeholders must be dropped, real values kept")
	}
	if chassisName("10") != "laptop" || chassisName("17") != "server" || chassisName("35") != "mini PC" || chassisName("2") != "" {
		t.Error("chassis codes")
	}
}
