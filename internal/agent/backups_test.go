package agent

import "testing"

func TestParseVzdumpJobs(t *testing.T) {
	cfg := `vzdump: backup-all
	schedule 2,19:30
	all 1
	exclude 117,120
	storage pbs-local

realm-sync: ldap
	schedule daily
	all 1

vzdump: some
	vmid 200,201
	node other
	enabled 1

vzdump: off
	vmid 117
	enabled 0
`
	jobs := parseVzdumpJobs(cfg)
	if len(jobs) != 3 {
		t.Fatalf("want 3 vzdump jobs, got %d: %+v", len(jobs), jobs)
	}
	covered := func(vmid int, node string) bool {
		for _, j := range jobs {
			if j.covers(vmid, node) {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		vmid int
		node string
		want bool
	}{
		{100, "pve1", true},  // all
		{117, "pve1", false}, // excluded, and the job naming it is disabled
		{120, "pve1", false},
		{200, "other", true},
		{201, "pve1", true}, // the all-job covers it on pve1
	} {
		if got := covered(c.vmid, c.node); got != c.want {
			t.Errorf("vmid %d on %s: got %v", c.vmid, c.node, got)
		}
	}
	if !guestMACRe.MatchString("virtio=BC:24:11:9D:F1:4D,bridge=vmbr0,firewall=1") || !guestMACRe.MatchString("name=eth0,bridge=vmbr0,hwaddr=BC:24:11:5E:1D:D9,ip=dhcp") {
		t.Error("qemu and lxc network lines must yield their MAC")
	}
}

// A pool-based job covers the pool's members as Proxmox lists them, minus
// its exclusions; a pool with no members, or that does not exist, covers
// nothing.
func TestPoolBasedVzdumpJobs(t *testing.T) {
	users := `user:root@pam:1:0:::root@example.com:::

pool:web:Web servers:101,102,103:local-lvm
pool:empty:::
group:admins:root@pam::
`
	pools := parsePoolMembers(users)
	if len(pools["web"]) != 3 || len(pools["empty"]) != 0 {
		t.Fatalf("pools = %v", pools)
	}
	jobs := parseVzdumpJobs(`vzdump: web-nightly
	pool web
	exclude 103
	schedule 21:00

vzdump: ghost
	pool missing
`)
	for i := range jobs {
		jobs[i].expandPool(pools)
	}
	for vmid, want := range map[int]bool{101: true, 102: true, 103: false, 200: false} {
		got := false
		for _, j := range jobs {
			got = got || j.covers(vmid, "pve1")
		}
		if got != want {
			t.Errorf("vmid %d covered = %v, want %v", vmid, got, want)
		}
	}
}
