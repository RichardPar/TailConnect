//go:build !linux && !windows

package localapi

import (
	"errors"
	"net"
	"os"
)

// peerUID is unimplemented here, so privileged calls are refused.
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("peer credentials not supported on this OS")
}

// peerAccess gives root and the daemon's own user full access, others none.
func peerAccess(c net.Conn) (Access, error) {
	uid, err := peerUID(c)
	if err != nil {
		return AccessNone, err
	}
	if uid == 0 || uid == os.Geteuid() {
		return AccessAdmin, nil
	}
	return AccessNone, nil
}
