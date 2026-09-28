//go:build darwin

package sidecar

import (
	"syscall"
	"unsafe"
)

// peerUcred is the platform-neutral shape of a peer credential record.
type peerUcred struct {
	UID, GID int
	Groups   []int
}

// getPeerCredentials reads the peer's credential record on macOS via
// LOCAL_PEERCRED (SO_PEERCRED does not exist here). crpgid is unavailable
// without privileged entitlements, so supplementary groups cannot be listed;
// membership is decided on the effective GID, which the deployment's socket
// group is (safekeys/dev-key-custody, separate-user-socket).
func getPeerCredentials(fd uintptr) (*peerUcred, error) {
	var cred struct {
		UID      uint32
		GID      uint32
		Refcount uint32
	}
	// struct xucred on darwin: 4-byte uid, 4-byte gid, 4-byte refcount +
	// padding, then cr_groups[16]. We only need uid/gid, so a 12-byte read
	// of the head is sufficient and safe.
	slen := uint32(12)
	// LOCAL_PEERCRED = 0x002, SOL_SOCKET = 0xffff on darwin.
	const solSocket = 0xffff
	const localPeerCred = 0x002
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd, solSocket, localPeerCred,
		uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&slen)), 0)
	if errno != 0 {
		return nil, errno
	}
	return &peerUcred{UID: int(cred.UID), GID: int(cred.GID), Groups: []int{int(cred.GID)}}, nil
}