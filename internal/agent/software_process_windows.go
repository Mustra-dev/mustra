package agent

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// configureSoftwareProcess places a package command in a Job Object so a
// timeout terminates the whole tree (PowerShell plus msiexec, setup.exe and
// whatever they spawned), not just powershell.exe.
//
// The process starts suspended so it is inside the job before it can create
// an untracked child, as the custom-sensor helper does. Unlike that helper
// the job is not KILL_ON_JOB_CLOSE: closing it after a normal exit must not
// kill a service or application the installer legitimately left running.
func configureSoftwareProcess(cmd *exec.Cmd) (afterStart func() error, release func(), err error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	afterStart = func() error {
		process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
		if err != nil {
			return err
		}
		defer windows.CloseHandle(process)
		if err = windows.AssignProcessToJobObject(job, process); err != nil {
			return err
		}
		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(snapshot)
		entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
		for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
			if entry.OwnerProcessID != uint32(cmd.Process.Pid) {
				continue
			}
			thread, e := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if e != nil {
				return e
			}
			defer windows.CloseHandle(thread)
			_, e = windows.ResumeThread(thread)
			return e
		}
		return fmt.Errorf("cannot find suspended package thread: %w", err)
	}
	cmd.Cancel = func() error { return windows.TerminateJobObject(job, 1) }
	return afterStart, func() { windows.CloseHandle(job) }, nil
}
