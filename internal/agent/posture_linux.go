//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectPostureLinux: firewall from whichever front end is installed,
// encryption from the block-device tree, no antimalware or application
// control model (reported as "none", not as "off", because a Linux box
// without ClamAV is not misconfigured).
func collectPosturePlatform(ctx context.Context) proto.SecurityPosture {
	p := proto.SecurityPosture{FirewallEngine: "none", EncryptionEngine: "none", AntivirusEngine: "none", AppControlEngine: "none", AppControlMode: "off"}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	run := func(name string, args ...string) (string, error) {
		out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
		return string(out), err
	}
	if _, err := exec.LookPath("ufw"); err == nil {
		p.FirewallEngine = "ufw"
		out, _ := run("ufw", "status")
		p.FirewallEnabled = strings.Contains(out, "Status: active")
	} else if _, err := exec.LookPath("firewall-cmd"); err == nil {
		p.FirewallEngine = "firewalld"
		out, _ := run("firewall-cmd", "--state")
		p.FirewallEnabled = strings.TrimSpace(out) == "running"
	} else if _, err := exec.LookPath("nft"); err == nil {
		p.FirewallEngine = "nftables"
		out, _ := run("nft", "list", "ruleset")
		// A ruleset with any chain that has a hook is a live firewall; an
		// empty ruleset means nftables is installed and doing nothing.
		p.FirewallEnabled = strings.Contains(out, "hook ")
	} else if _, err := exec.LookPath("iptables"); err == nil {
		p.FirewallEngine = "iptables"
		out, _ := run("iptables", "-S")
		p.FirewallEnabled = strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-A INPUT")
	}
	if out, err := run("lsblk", "-rno", "TYPE,MOUNTPOINT"); err == nil {
		sc := bufio.NewScanner(bytes.NewReader([]byte(out)))
		var vols []proto.VolumeEncryption
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 1 {
				continue
			}
			mount := ""
			if len(f) > 1 {
				mount = f[1]
			}
			if f[0] == "crypt" {
				p.EncryptionEngine = "luks"
				vols = append(vols, proto.VolumeEncryption{Mount: mount, Status: "FullyEncrypted", ProtectionOn: true, Method: "LUKS", Percent: 100})
				if mount == "/" {
					p.OSVolumeEncrypted = true
				}
			}
		}
		// The root filesystem may sit on LVM over LUKS; then the crypt
		// row carries no mountpoint and "/" is on a child. Walk parents.
		if !p.OSVolumeEncrypted && p.EncryptionEngine == "luks" {
			if out, err := run("lsblk", "-rno", "TYPE,MOUNTPOINT,PKNAME,NAME"); err == nil {
				crypt := map[string]bool{}
				parent := map[string]string{}
				rootDev := ""
				sc := bufio.NewScanner(bytes.NewReader([]byte(out)))
				for sc.Scan() {
					f := strings.Fields(sc.Text())
					if len(f) < 4 {
						// mountpoint blank collapses the field count; re-split by position
						parts := strings.Split(sc.Text(), " ")
						if len(parts) == 4 {
							f = parts
						} else {
							continue
						}
					}
					typ, mount, pk, name := f[0], f[1], f[2], f[3]
					if typ == "crypt" {
						crypt[name] = true
					}
					parent[name] = pk
					if mount == "/" {
						rootDev = name
					}
				}
				for d := rootDev; d != "" && !p.OSVolumeEncrypted; d = parent[d] {
					if crypt[d] {
						p.OSVolumeEncrypted = true
					}
				}
			}
		}
		p.Volumes = vols
	}
	return p
}
