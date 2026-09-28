//go:build linux

package sidecar

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// peerUcred is the platform-neutral shape of a peer credential record.
type peerUcred struct {
	UID, GID int
	Groups   []int
}

// getPeerCredentials reads the peer's credential record on Linux:
// SO_PEERCRED for uid/gid, then SO_PEERGROUPS for supplementary groups
// (added in Linux 4.5; absent or erroring, supplementary groups are simply
// unknown and only the effective GID decides membership).
func getPeerCredentials(fd uintptr) (*peerUcred, error) {
	u, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return nil, err
	}
	groups := []int{int(u.Gid)}
	// SO_PEERGROUPS (Linux 4.5+) returns the peer's supplementary groups as a
	// byte buffer of uint32 gids. Not in the syscall package as a constant;
	// value is 0x31 (49). Absent or erroring, supplementary groups are
	// unknown and only the effective GID decides membership.
	const soPeerGroups = 0x31
	buf := make([]byte, 256)
	sz := uint32(len(buf))
	// Raw getsockopt via Syscall6 — the Go syscall package exposes no typed
	// wrapper for SO_PEERGROUPS.
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_SOCKET, soPeerGroups,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)), 0)
	if errno == 0 && sz > 0 {
		groups = groups[:0]
		for i := 0; i+4 <= int(sz); i += 4 {
			g := binary.LittleEndian.Uint32(buf[i : i+4])
			groups = append(groups, int(g))
		}
	}
	return &peerUcred{UID: int(u.Uid), GID: int(u.Gid), Groups: groups}, nil
}