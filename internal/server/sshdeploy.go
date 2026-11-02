package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"

	"github.com/mustra-dev/mustra/internal/server/vault"
)

// Host keys. Pushing an agent sends a vault credential to the target and
// runs the installer as root there, so the target has to be the machine
// it claims to be. A key is trusted only once confirmed: either it is
// already stored for the target (and must match exactly), or the caller
// supplies the fingerprint they verified out of band (and it is stored on
// success). Otherwise the push stops after key exchange — before any
// credential is offered — and reports the fingerprint to confirm.

// errHostKeyProbe aborts a handshake once the host key has been seen.
var errHostKeyProbe = errors.New("host key probe")

// hostKeyUnknownError carries the key a target presented that nobody has
// confirmed yet.
type hostKeyUnknownError struct {
	Target      string
	KeyType     string
	Fingerprint string
}

func (e *hostKeyUnknownError) Error() string {
	return fmt.Sprintf("the SSH host key of %s is not yet trusted: %s %s. Verify it on the host "+
		"(ssh-keygen -lf /etc/ssh/ssh_host_%s_key.pub) and push again with host_key_fingerprint set to it",
		e.Target, e.KeyType, e.Fingerprint, strings.TrimPrefix(e.KeyType, "ssh-"))
}

// fetchSSHHostKey connects only far enough to learn the host key.
func fetchSSHHostKey(ctx context.Context, target string) (ssh.PublicKey, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, "22"))
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s:22: %w", target, err)
	}
	defer conn.Close()
	var seen ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "mustra-hostkey-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return errHostKeyProbe
		},
		Timeout: 10 * time.Second,
	}
	_, _, _, err = ssh.NewClientConn(conn, target, cfg)
	if seen != nil {
		return seen, nil
	}
	return nil, fmt.Errorf("ssh handshake with %s: %w", target, err)
}

// pinnedHostKey accepts exactly one key.
func pinnedHostKey(want ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if key.Type() == want.Type() && bytes.Equal(key.Marshal(), want.Marshal()) {
			return nil
		}
		return fmt.Errorf("the SSH host key changed (expected %s %s, got %s %s); if the host was "+
			"reinstalled, remove its stored key and confirm the new one", want.Type(), ssh.FingerprintSHA256(want),
			key.Type(), ssh.FingerprintSHA256(key))
	}
}

// fingerprintHostKey accepts a key whose SHA256 fingerprint is fp, and
// reports it through seen so it can be stored.
func fingerprintHostKey(fp string, seen *ssh.PublicKey) ssh.HostKeyCallback {
	fp = strings.TrimSpace(fp)
	if !strings.HasPrefix(fp, "SHA256:") {
		fp = "SHA256:" + fp
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != fp {
			return fmt.Errorf("the SSH host key fingerprint is %s, not the %s you confirmed", ssh.FingerprintSHA256(key), fp)
		}
		*seen = key
		return nil
	}
}

func sshClientConfig(cred *vault.Decrypted, hostKey ssh.HostKeyCallback) (*ssh.ClientConfig, string, error) {
	if hostKey == nil {
		return nil, "", fmt.Errorf("no host key verification configured")
	}
	var authMethods []ssh.AuthMethod
	var keyDesc string
	switch cred.AuthType {
	case "password":
		authMethods = append(authMethods, ssh.Password(cred.Secret))
	case "private_key":
		var signer ssh.Signer
		var err error
		if cred.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cred.Secret), []byte(cred.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cred.Secret))
		}
		if err != nil {
			return nil, "", fmt.Errorf("parse private key: %w", err)
		}
		// Carried so a rejection can name the exact key that needs
		// authorizing, rather than leaving you to guess which one was tried.
		pub := signer.PublicKey()
		keyDesc = pub.Type() + " " + ssh.FingerprintSHA256(pub)
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	default:
		return nil, "", fmt.Errorf("unknown credential auth type: %s", cred.AuthType)
	}
	return &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKey,
		Timeout:         10 * time.Second,
	}, keyDesc, nil
}

// explainHandshake turns golang.org/x/crypto/ssh's "unable to authenticate,
// attempted methods [none publickey]" into something you can act on. The
// raw message names the mechanism but never the cause, and the cause is
// almost always one of a short list.
func explainHandshake(err error, target string, cred *vault.Decrypted, keyDesc string) error {
	msg := err.Error()
	if !strings.Contains(msg, "unable to authenticate") {
		return fmt.Errorf("ssh handshake with %s: %w", target, err)
	}
	switch cred.AuthType {
	case "private_key":
		return fmt.Errorf("%s rejected this key for user %q. The key mustra offered was %s — "+
			"check that its public half is in ~%s/.ssh/authorized_keys on that host, "+
			"and that sshd allows this user to log in (PermitRootLogin, AllowUsers). "+
			"Underlying error: %w", target, cred.Username, keyDesc, cred.Username, err)
	case "password":
		return fmt.Errorf("%s rejected the password for user %q. Most often that host has "+
			"PasswordAuthentication disabled and only accepts keys — add a private-key "+
			"credential instead. Underlying error: %w", target, cred.Username, err)
	default:
		return fmt.Errorf("ssh handshake with %s: %w", target, err)
	}
}

// detectRemoteOS decides whether the target speaks a POSIX shell
// (Linux/macOS) or is Windows (OpenSSH Server on Windows defaults to
// cmd.exe, not bash). Returns "" when it genuinely can't tell.
//
// Three things this gets right that the obvious version doesn't:
//   - It reads stdout only. A login shell that prints to stderr — a broken
//     line in .bashrc, say — would otherwise contaminate the probe output.
//   - It looks for the marker anywhere in the output rather than matching
//     the whole blob, since shells also print banners and motd to stdout.
//   - Windows requires positive evidence. Assuming Windows whenever the
//     POSIX probe is unclear meant running a PowerShell script against a
//     Debian box and failing with "powershell: command not found".
func detectRemoteOS(client *ssh.Client) string {
	probe := func(cmd string) string {
		sess, err := client.NewSession()
		if err != nil {
			return ""
		}
		defer sess.Close()
		out, err := sess.Output(cmd) // stdout only, deliberately
		if err != nil {
			return ""
		}
		return string(out)
	}

	if out := probe("uname -s"); out != "" {
		switch {
		case strings.Contains(out, "Linux"):
			return "linux"
		case strings.Contains(out, "Darwin"):
			return "darwin"
		}
	}
	// Only now consider Windows, and only on positive evidence.
	for _, cmd := range []string{"cmd.exe /c ver", "ver"} {
		if out := probe(cmd); strings.Contains(strings.ToLower(out), "windows") {
			return "windows"
		}
	}
	return ""
}

// pushAgentViaSSH connects to target, detects its OS, and runs the same
// install script /install.sh and /install.ps1 serve — piped directly over
// the SSH session so the target never needs to reach back to mustra over
// HTTP for anything but the agent binary download itself.
func pushAgentViaSSH(ctx context.Context, target string, cred *vault.Decrypted, data installScriptData, hostKey ssh.HostKeyCallback) (string, error) {
	cfg, keyDesc, err := sshClientConfig(cred, hostKey)
	if err != nil {
		return "", err
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, "22"))
	if err != nil {
		return "", fmt.Errorf("tcp dial %s:22: %w", target, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, cfg)
	if err != nil {
		conn.Close()
		return "", explainHandshake(err, target, cred, keyDesc)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	osKind := detectRemoteOS(client)

	var script bytes.Buffer
	var cmd string
	switch osKind {
	case "linux", "darwin":
		if err := installShTemplate.Execute(&script, data); err != nil {
			return "", fmt.Errorf("render install script: %w", err)
		}
		// Only reach for sudo if we're not already root — many minimal
		// hosts (small servers, containers) don't even have sudo installed,
		// and root over SSH doesn't need it.
		if cred.Username == "root" {
			cmd = "bash -s"
		} else {
			cmd = "sudo bash -s"
		}
	case "windows":
		if err := installPs1Template.Execute(&script, data); err != nil {
			return "", fmt.Errorf("render install script: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(utf16LE(script.String()))
		script.Reset() // the script travels inside -EncodedCommand, not stdin
		cmd = "powershell -NoProfile -EncodedCommand " + encoded
	default:
		return "", fmt.Errorf("couldn't determine the remote operating system on %s — "+
			"neither `uname -s` nor a Windows version probe answered. "+
			"Check the account can run a shell there", target)
	}

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("open ssh session: %w", err)
	}
	defer sess.Close()

	if script.Len() > 0 {
		sess.Stdin = &script
	}
	// One transcript for both streams, behind a lock. x/crypto/ssh copies
	// stdout and stderr in separate goroutines, and a bare bytes.Buffer
	// shared between them drops whole writes: pushes to Home Assistant's
	// SSH add-on came back "exited with status 1" with an empty transcript,
	// losing the installer's own explanation of why it refused.
	var outBuf bytes.Buffer
	out := &lockedWriter{w: &outBuf}
	sess.Stdout = out
	sess.Stderr = out

	if err := sess.Run(cmd); err != nil {
		transcript := outBuf.String()
		if reason := lastLine(transcript); reason != "" {
			return transcript, fmt.Errorf("install script failed on %s (%s): %w: %s", target, osKind, err, reason)
		}
		return transcript, fmt.Errorf("install script failed on %s (%s): %w", target, osKind, err)
	}
	return outBuf.String(), nil
}

// lockedWriter serialises writes from concurrent stream copiers.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// lastLine returns the transcript's last non-empty line. The installers
// print their reason for giving up just before exiting, so it belongs in
// the error the Deploy history shows, not only in the full transcript.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return safeTruncate(strings.TrimSpace(lines[len(lines)-1]), 300)
}

// utf16LE encodes s as UTF-16LE, the encoding PowerShell's -EncodedCommand
// requires.
func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, len(units)*2)
	for i, v := range units {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}
	return b
}
