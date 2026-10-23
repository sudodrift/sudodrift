//go:build !linux

package snapshot

import "os"

func ownerIDs(fi os.FileInfo) (int, int) { return -1, -1 }
