//go:build linux && !android

package netmark

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Control marks the socket. Without CAP_NET_ADMIN (userspace mode as an
// ordinary user) marking fails; that's fine, since such a tcd can't use an
// exit node anyway, so the error is ignored.
func Control(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, Mark)
	})
}
