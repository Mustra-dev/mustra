package agent

import (
	"testing"

	"github.com/shirou/gopsutil/v4/disk"
)

func TestCountsTowardDiskPressure(t *testing.T) {
	for _, c := range []struct {
		p    disk.PartitionStat
		want bool
	}{
		{disk.PartitionStat{Mountpoint: "/System/Volumes/Data", Fstype: "apfs"}, true},
		{disk.PartitionStat{Mountpoint: "/", Fstype: "ext4", Opts: []string{"rw", "relatime"}}, true},
		// What made a MacBook's disk score 0 with its disk a third full.
		{disk.PartitionStat{Mountpoint: "/dev", Fstype: "devfs"}, false},
		{disk.PartitionStat{Mountpoint: "/snap/core22/1380", Fstype: "squashfs", Opts: []string{"ro"}}, false},
		{disk.PartitionStat{Mountpoint: "/mnt/cdrom", Fstype: "iso9660"}, false},
		{disk.PartitionStat{Mountpoint: "/boot/efi", Fstype: "vfat", Opts: []string{"ro"}}, false},
	} {
		if got := countsTowardDiskPressure(c.p); got != c.want {
			t.Errorf("%s (%s %v): got %v, want %v", c.p.Mountpoint, c.p.Fstype, c.p.Opts, got, c.want)
		}
	}
}
