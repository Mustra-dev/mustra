//go:build windows

package agent

import "io/fs"

// chownLike keeps nothing on Windows: a new file inherits its folder's ACL.
func chownLike(string, fs.FileInfo) {}
