//go:build windows

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// winStoreCSR has certreq make an RSA key in the machine key store and a
// request for it. NETWORK SERVICE may read the key: Remote Desktop runs as
// it and could not use the certificate otherwise.
func winStoreCSR(job proto.CertJob) (string, error) {
	if len(job.Names) == 0 {
		return "", errors.New("at least one name is required")
	}
	var san strings.Builder
	for _, n := range job.Names {
		if !winCertNameRe.MatchString(n) {
			return "", fmt.Errorf("%q is not a name a certificate can carry", n)
		}
		if net.ParseIP(n) != nil {
			fmt.Fprintf(&san, "_continue_ = \"ipaddress=%s&\"\r\n", n)
		} else {
			fmt.Fprintf(&san, "_continue_ = \"dns=%s&\"\r\n", n)
		}
	}
	friendly := job.FriendlyName
	if friendly == "" {
		friendly = "Mustra: " + job.Names[0]
	}
	inf := "[Version]\r\nSignature=\"$Windows NT$\"\r\n\r\n[NewRequest]\r\n" +
		fmt.Sprintf("Subject = \"CN=%s\"\r\n", job.Names[0]) +
		"KeyAlgorithm = RSA\r\nKeyLength = 2048\r\nProviderName = \"Microsoft Software Key Storage Provider\"\r\n" +
		"MachineKeySet = TRUE\r\nExportable = FALSE\r\nKeyUsage = 0xa0\r\nRequestType = PKCS10\r\nHashAlgorithm = sha256\r\n" +
		fmt.Sprintf("FriendlyName = \"%s\"\r\n", strings.ReplaceAll(friendly, `"`, "")) +
		"SecurityDescriptor = \"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;NS)\"\r\n\r\n" +
		"[EnhancedKeyUsageExtension]\r\nOID=1.3.6.1.5.5.7.3.1\r\n\r\n" +
		"[Extensions]\r\n2.5.29.17 = \"{text}\"\r\n" + san.String()
	dir, err := os.MkdirTemp("", "mustra-certreq-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	infFile, csrFile := filepath.Join(dir, "req.inf"), filepath.Join(dir, "req.csr")
	if err := os.WriteFile(infFile, []byte(inf), 0o600); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "certreq.exe", "-new", "-q", "-f", infFile, csrFile).CombinedOutput(); err != nil {
		return "", fmt.Errorf("certreq -new: %v %s", err, strings.TrimSpace(string(out)))
	}
	raw, err := os.ReadFile(csrFile)
	if err != nil {
		return "", err
	}
	// certreq writes "NEW CERTIFICATE REQUEST"; CAs expect the plain label.
	block, _ := pem.Decode(bytes.ReplaceAll(raw, []byte("NEW CERTIFICATE REQUEST"), []byte("CERTIFICATE REQUEST")))
	if block == nil {
		return "", errors.New("certreq wrote no request")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: block.Bytes})), nil
}

// ps runs a PowerShell script with its inputs in the environment.
func ps(ctx context.Context, script string, env map[string]string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

const (
	psBindIIS = `$ErrorActionPreference='Stop'
Import-Module WebAdministration
$site=$env:MUSTRA_SITE; $port=[int]$env:MUSTRA_PORT; $thumb=$env:MUSTRA_THUMB
if (-not (Get-Website -Name $site)) { throw "IIS has no site named '$site'" }
$prev=''
$sb = Get-Item "IIS:\SslBindings\0.0.0.0!$port" -ErrorAction SilentlyContinue
if ($sb) { $prev=$sb.Thumbprint }
$b = Get-WebBinding -Name $site -Protocol https -Port $port
if (-not $b) { New-WebBinding -Name $site -Protocol https -Port $port -IPAddress '*'; $b = Get-WebBinding -Name $site -Protocol https -Port $port }
$b.AddSslCertificate($thumb, 'My')
"PREV $prev"`
	psRestoreIIS = `$ErrorActionPreference='Stop'
Import-Module WebAdministration
$b = Get-WebBinding -Name $env:MUSTRA_SITE -Protocol https -Port ([int]$env:MUSTRA_PORT)
if ($b -and $env:MUSTRA_THUMB) { $b.AddSslCertificate($env:MUSTRA_THUMB, 'My') }`
	psCurrentRDP = `$ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
"PREV $($ts.SSLCertificateSHA1Hash)"`
	psBindRDP = `$ErrorActionPreference='Stop'
$ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
Set-CimInstance -InputObject $ts -Property @{SSLCertificateSHA1Hash=$env:MUSTRA_THUMB}
$now = (Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'").SSLCertificateSHA1Hash
if ($now -ne $env:MUSTRA_THUMB) { throw "Remote Desktop still uses $now" }`
	// Remote Desktop's own self-signed certificate lives in the "Remote
	// Desktop" store, which WMI will not bind; going back to it means
	// removing the custom setting, as Windows' own tools do.
	psRestoreRDP = `$t = $env:MUSTRA_THUMB
if ($t -and (Test-Path ("Cert:\LocalMachine\My\" + $t))) {
  $ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
  Set-CimInstance -InputObject $ts -Property @{SSLCertificateSHA1Hash=$t}
} else {
  Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SSLCertificateSHA1Hash -ErrorAction SilentlyContinue
}`
	// The installed certificate must have its key; then name it, and
	// remove the earlier ones Mustra made under the same name.
	psCheckKey = `$ErrorActionPreference='Stop'
$c = Get-Item ("Cert:\LocalMachine\My\" + $env:MUSTRA_THUMB)
if (-not $c.HasPrivateKey) { throw 'the certificate was installed without its private key' }
$c.FriendlyName = $env:MUSTRA_FRIENDLY`
	psRemoveCert = `Remove-Item ("Cert:\LocalMachine\My\" + $env:MUSTRA_THUMB) -DeleteKey -ErrorAction SilentlyContinue`
	psRemoveOld  = `Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -eq $env:MUSTRA_FRIENDLY -and $_.Thumbprint -ne $env:MUSTRA_THUMB } | ForEach-Object { Remove-Item $_.PSPath -DeleteKey; "removed $($_.Thumbprint)" }`
)

// winStoreInstall accepts the signed certificate into the machine store,
// binds it, checks the binding took, and undoes all of it on any failure.
func winStoreInstall(ctx context.Context, job proto.CertJob) (string, error) {
	block, _ := pem.Decode([]byte(job.CertPEM))
	if block == nil {
		return "", errors.New("the server sent no certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	thumb := strings.ToUpper(hex.EncodeToString(sha1Sum(leaf.Raw)))
	sum := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(sum[:])
	friendly := job.FriendlyName
	if friendly == "" && len(job.Names) > 0 {
		friendly = "Mustra: " + job.Names[0]
	}
	if job.WinBind == "iis" && !iisSiteRe.MatchString(job.IISSite) {
		return "", fmt.Errorf("%q is not an IIS site name", job.IISSite)
	}
	dir, err := os.MkdirTemp("", "mustra-certaccept-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	var report strings.Builder
	if c := strings.TrimSpace(job.ChainPEM); c != "" {
		chainFile := filepath.Join(dir, "chain.pem")
		if err := os.WriteFile(chainFile, []byte(c+"\n"), 0o600); err == nil {
			_, _ = exec.CommandContext(ctx, "certutil.exe", "-f", "-addstore", "CA", chainFile).CombinedOutput()
		}
	}
	if job.PFXBase64 != "" {
		// An uploaded certificate arrives with its key as a PFX; import
		// it into the machine store, key not exportable.
		raw, err := base64.StdEncoding.DecodeString(job.PFXBase64)
		if err != nil {
			return "", errors.New("the uploaded certificate could not be read")
		}
		pfxFile := filepath.Join(dir, "upload.pfx")
		if err := os.WriteFile(pfxFile, raw, 0o600); err != nil {
			return "", err
		}
		if out, err := exec.CommandContext(ctx, "certutil.exe", "-f", "-p", job.PFXPassword, "-importPFX", "My", pfxFile, "NoExport").CombinedOutput(); err != nil {
			return "", fmt.Errorf("certutil -importPFX: %v %s", err, strings.TrimSpace(string(out)))
		}
	} else {
		leafFile := filepath.Join(dir, "leaf.cer")
		if err := os.WriteFile(leafFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o600); err != nil {
			return "", err
		}
		if out, err := exec.CommandContext(ctx, "certreq.exe", "-accept", "-q", "-machine", leafFile).CombinedOutput(); err != nil {
			return "", fmt.Errorf("certreq -accept (the key for this request is missing; renew again): %v %s", err, strings.TrimSpace(string(out)))
		}
	}
	env := map[string]string{"MUSTRA_THUMB": thumb, "MUSTRA_FRIENDLY": friendly, "MUSTRA_SITE": job.IISSite, "MUSTRA_PORT": strconv.Itoa(job.VerifyPort)}
	removeNew := func() { _, _ = ps(ctx, psRemoveCert, env) }
	if out, err := ps(ctx, psCheckKey, env); err != nil {
		removeNew()
		return "", fmt.Errorf("checking the installed certificate: %v %s", err, out)
	}
	fmt.Fprintf(&report, "Installed in Cert:\\LocalMachine\\My as %s (%s).\n", thumb, friendly)

	// Bind, remembering what was bound before so a failure can put it back.
	prev, restore := "", ""
	switch job.WinBind {
	case "iis":
		out, err := ps(ctx, psBindIIS, env)
		if err != nil {
			removeNew()
			return report.String(), fmt.Errorf("binding to IIS site %q: %v %s", job.IISSite, err, out)
		}
		prev, restore = prevThumb(out), psRestoreIIS
		fmt.Fprintf(&report, "Bound to IIS site %q on port %d.\n", job.IISSite, job.VerifyPort)
	case "rdp":
		// What it uses now, read first: a bind that fails halfway must
		// still be able to put it back.
		cur, _ := ps(ctx, psCurrentRDP, env)
		prev, restore = prevThumb(cur), psRestoreRDP
		if out, err := ps(ctx, psBindRDP, env); err != nil {
			_, _ = ps(ctx, psRestoreRDP, map[string]string{"MUSTRA_THUMB": prev})
			removeNew()
			return report.String(), fmt.Errorf("binding to Remote Desktop: %v %s", err, out)
		}
		report.WriteString("Remote Desktop now presents it (new connections; open sessions keep theirs).\n")
	}
	fail := func(why string) (string, error) {
		if restore != "" && (prev != "" || job.WinBind == "rdp") {
			_, _ = ps(ctx, restore, map[string]string{"MUSTRA_THUMB": prev, "MUSTRA_SITE": job.IISSite, "MUSTRA_PORT": strconv.Itoa(job.VerifyPort)})
		}
		removeNew()
		return report.String(), fmt.Errorf("%s; the previous certificate was put back", why)
	}
	// IIS serves TLS directly, so the port check works as for files; Remote
	// Desktop negotiates TLS inside its own protocol and was read back above.
	if job.WinBind == "iis" && job.VerifyPort > 0 {
		target := net.JoinHostPort("127.0.0.1", strconv.Itoa(job.VerifyPort))
		served := ""
		for i := 0; i < 10; i++ {
			if c := presentedCertificate(ctx, target, leaf.Subject.CommonName); c != nil {
				s := sha256.Sum256(c.Raw)
				if served = hex.EncodeToString(s[:]); served == fingerprint {
					break
				}
			}
			time.Sleep(1500 * time.Millisecond)
		}
		if served != fingerprint {
			return fail(fmt.Sprintf("port %d still presents a different certificate", job.VerifyPort))
		}
		fmt.Fprintf(&report, "Verified: port %d presents the new certificate.\n", job.VerifyPort)
	}
	if out, _ := ps(ctx, psRemoveOld, env); out != "" {
		report.WriteString("Removed the certificate it replaced: " + strings.ReplaceAll(out, "\n", ", ") + ".\n")
	}
	return report.String() + "fingerprint " + fingerprint, nil
}

func prevThumb(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if t, ok := strings.CutPrefix(strings.TrimSpace(line), "PREV "); ok {
			return strings.TrimSpace(t)
		}
	}
	return ""
}
