//go:build !linux

package localapi

import (
	"errors"
	"net"
)

// peerUID is unimplemented here, so privileged calls are refused. Windows
// will use a named pipe with an ACL instead (milestone 6).
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("peer credentials not supported on this OS")
}
