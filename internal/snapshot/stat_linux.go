//go:build linux

package snapshot

import (
	"os"
	"syscall"
)

func ownerIDs(fi os.FileInfo) (int, int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}
