//go:build windows

package agent

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// machineStoreCertificates returns the DER of every certificate in one
// LocalMachine system store, or nothing when the store does not exist.
// Opened read-only and only if it already exists, so reading never
// creates a store.
func machineStoreCertificates(store string) [][]byte {
	name, err := windows.UTF16PtrFromString(store)
	if err != nil {
		return nil
	}
	h, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG,
		uintptr(unsafe.Pointer(name)))
	if err != nil {
		return nil
	}
	defer windows.CertCloseStore(h, 0)
	var out [][]byte
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(h, ctx)
		if err != nil || ctx == nil {
			return out
		}
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		out = append(out, append([]byte(nil), der...))
	}
}
