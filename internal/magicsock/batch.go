package magicsock

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

// batchSize is how many packets WireGuard hands magicsock per call, and
// magicsock reads per system call: sendmmsg/recvmmsg on Linux. Elsewhere
// x/net falls back to one packet per call, which is still correct.
const batchSize = conn.IdealBatchSize

// socketBuffer is the requested UDP socket buffer size, as in wireguard-go.
const socketBuffer = 7 << 20

// sock is one UDP socket with batched I/O.
type sock struct {
	pc *net.UDPConn
	bc batchConn
}

// socks are the IPv4 and IPv6 sockets, bound to the same port. Separate
// sockets (not one dual-stack socket) because batched sends encode an IPv4
// destination as an IPv4 address, which an IPv6 socket rejects. Either may
// be nil (no IPv6 on the host, or no IPv4).
type socks struct {
	v4, v6 *sock
}

// listenSocks binds IPv4 and IPv6 UDP sockets to port (0 = any free port,
// the same for both).
func listenSocks(port uint16) (*socks, uint16, error) {
	s := &socks{}
	pc4, err4 := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	if err4 == nil {
		s.v4 = &sock{pc: pc4, bc: ipv4.NewPacketConn(pc4)}
		port = uint16(pc4.LocalAddr().(*net.UDPAddr).Port)
	}
	if pc6, err6 := net.ListenUDP("udp6", &net.UDPAddr{Port: int(port)}); err6 == nil {
		s.v6 = &sock{pc: pc6, bc: ipv6.NewPacketConn(pc6)}
		if s.v4 == nil {
			port = uint16(pc6.LocalAddr().(*net.UDPAddr).Port)
		}
	}
	if s.v4 == nil && s.v6 == nil {
		return nil, 0, err4
	}
	for _, k := range []*sock{s.v4, s.v6} {
		if k != nil {
			// Best effort: room for bursts while the reader is busy (the
			// kernel caps this at net.core.rmem_max without privileges).
			k.pc.SetReadBuffer(socketBuffer)
			k.pc.SetWriteBuffer(socketBuffer)
		}
	}
	return s, port, nil
}

func (s *socks) close() {
	for _, k := range []*sock{s.v4, s.v6} {
		if k != nil {
			k.pc.Close()
		}
	}
}

// forAddr picks the socket for a destination (nil if that family has none).
func (s *socks) forAddr(a netip.Addr) *sock {
	if s == nil {
		return nil
	}
	if a.Unmap().Is4() {
		return s.v4
	}
	return s.v6
}

// write sends bufs to to through the right socket.
func (s *socks) write(bufs [][]byte, to netip.AddrPort) error {
	k := s.forAddr(to.Addr())
	if k == nil {
		return errNoSocket
	}
	return writeBatch(k.pc, k.bc, bufs, netip.AddrPortFrom(to.Addr().Unmap(), to.Port()))
}

var errNoSocket = errors.New("magicsock: no socket for that address family")

// batchConn is the batched I/O of an ipv4 or ipv6 PacketConn. Both use the
// same message type (an alias of x/net's internal socket.Message).
type batchConn interface {
	ReadBatch(ms []ipv6.Message, flags int) (int, error)
	WriteBatch(ms []ipv6.Message, flags int) (int, error)
}

var msgPool = sync.Pool{New: func() any { m := make([]ipv6.Message, batchSize); return &m }}

// writeBatch sends bufs to one address with as few system calls as possible.
func writeBatch(pc *net.UDPConn, bc batchConn, bufs [][]byte, to netip.AddrPort) error {
	if len(bufs) == 1 || bc == nil {
		for _, b := range bufs {
			if _, err := pc.WriteToUDPAddrPort(b, to); err != nil {
				return err
			}
		}
		return nil
	}
	mp := msgPool.Get().(*[]ipv6.Message)
	defer msgPool.Put(mp)
	ua := net.UDPAddrFromAddrPort(to)
	msgs := (*mp)[:0]
	for i := range bufs {
		msgs = append(msgs, ipv6.Message{Buffers: bufs[i : i+1], Addr: ua})
	}
	for start := 0; start < len(msgs); {
		n, err := bc.WriteBatch(msgs[start:], 0)
		if err != nil {
			return err
		}
		start += n
	}
	return nil
}
