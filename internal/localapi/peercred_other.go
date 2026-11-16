//go:build !linux && !windows

package localapi

import (
	"errors"
	"net"
)

// peerUID is unimplemented here, so privileged calls are refused.
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("peer credentials not supported on this OS")
}
