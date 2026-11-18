package netmark

import (
	"encoding/binary"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

// Windows has no socket marks. While this machine uses an exit node, the
// tunnel holds the default routes, and tcd's sockets are pinned to the
// physical interface that had them instead (IP_UNICAST_IF, as WireGuard
// for Windows does), so they keep using the real network.
//
// Every socket made through this package is remembered (until it's
// closed), so the binding also applies to sockets opened before the exit
// node was turned on, and follows the default interface when it changes.

// Socket options from ws2ipdef.h.
const (
	ipUnicastIf   = 31 // IP_UNICAST_IF: interface index, in network byte order
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF: interface index, in host order
)

var (
	mu         sync.Mutex
	idx4, idx6 uint32 // interface indexes to pin to (0 = not pinned)
	socks      []*sockRef
)

type sockRef struct {
	c        syscall.RawConn
	v4, v6   bool // address families the socket may carry
	lastIdx4 uint32
	lastIdx6 uint32
}

// Control remembers the socket and applies the current pinning.
func Control(network, address string, c syscall.RawConn) error {
	r := &sockRef{c: c}
	switch {
	case strings.HasSuffix(network, "4"):
		r.v4 = true
	case strings.HasSuffix(network, "6"):
		r.v6 = true
	default:
		r.v4, r.v6 = true, true
	}
	mu.Lock()
	defer mu.Unlock()
	if len(socks) >= 32 {
		prune()
	}
	socks = append(socks, r)
	r.apply(idx4, idx6) // errors here are not fatal: the socket works unpinned
	return nil
}

// apply sets the socket's interfaces. It reports false once the socket is
// closed.
func (r *sockRef) apply(i4, i6 uint32) bool {
	alive := true
	err := r.c.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if r.v4 && i4 != r.lastIdx4 {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], i4)
			if windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(binary.NativeEndian.Uint32(b[:]))) == nil {
				r.lastIdx4 = i4
			}
		}
		if r.v6 && i6 != r.lastIdx6 {
			if windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIf, int(i6)) == nil {
				r.lastIdx6 = i6
			}
		}
	})
	if err != nil {
		alive = false // closed
	}
	return alive
}

// prune forgets closed sockets. mu must be held.
func prune() {
	live := socks[:0]
	for _, r := range socks {
		if r.c.Control(func(uintptr) {}) == nil {
			live = append(live, r)
		}
	}
	clear(socks[len(live):])
	socks = live
}

// PinToInterface pins tcd's sockets, current and future, to the interfaces
// with these indexes for IPv4 and IPv6 (0 = unpin that family).
func PinToInterface(i4, i6 uint32) {
	mu.Lock()
	defer mu.Unlock()
	idx4, idx6 = i4, i6
	live := socks[:0]
	for _, r := range socks {
		if r.apply(i4, i6) {
			live = append(live, r)
		}
	}
	clear(socks[len(live):])
	socks = live
}
