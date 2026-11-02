package agent

import "runtime"

// kqueueWatches reports whether this platform's file watcher is backed by
// kqueue, where fsnotify emulates a directory watch by opening a descriptor
// for every file inside it.
//
// This distinction is the whole reason the watch budget exists twice. On
// Linux, inotify takes one watch descriptor per directory from a kernel
// pool that does not touch the process's own descriptor limit. On macOS and
// the BSDs, watching /Library/LaunchDaemons costs one descriptor per plist
// in it — and a launchd job gets 256 by default.
var kqueueWatches = map[string]bool{
	"darwin": true, "freebsd": true, "netbsd": true, "openbsd": true, "dragonfly": true,
}[runtime.GOOS]
