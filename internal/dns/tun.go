package dns

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// writeOffset is the headroom left in front of injected packets; Linux TUNs
// with offloads need room for a virtio-net header.
const writeOffset = 16

// TUN wraps the tunnel device and answers DNS queries the host sends to the
// resolver addresses (UDP and TCP port 53) by writing responses back into
// the host, as if they came from the resolver. Everything else passes
// through.
type TUN struct {
	tun.Device
	r    *Resolver
	logf func(string, ...any)

	addr4, addr6 netip.Addr
	enabled      atomic.Bool
	exit         atomic.Pointer[exitDNS] // the exit node's addresses, while one is in use

	redirMu sync.Mutex
	redir   map[redirKey]time.Time // queries readdressed to the exit node → when they expire

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// closeMu orders Close after work Read starts: Read (WireGuard's reader
	// may still be in it) holds it shared while adding to wg or writing to
	// the TCP stack; Close takes it exclusively to set closed first.
	closeMu sync.RWMutex
	closed  bool

	tcpOnce  sync.Once
	tcpStack *tcpStack // DNS over TCP, started on first use (see tcp.go)
}

// WrapTUN returns dev with DNS interception for addr4/addr6 (either may be
// invalid). Interception starts disabled; see SetEnabled.
func WrapTUN(dev tun.Device, r *Resolver, addr4, addr6 netip.Addr, logf func(string, ...any)) *TUN {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TUN{Device: dev, r: r, logf: logf, addr4: addr4, addr6: addr6, ctx: ctx, cancel: cancel}
}

// SetEnabled turns interception on or off (MagicDNS on/off).
func (t *TUN) SetEnabled(on bool) { t.enabled.Store(on) }

// exitDNS is where queries for names outside MagicDNS go while an exit
// node is in use: its tunnel addresses (see exit.go).
type exitDNS struct{ v4, v6 netip.Addr }

// redirKey identifies a query readdressed to the exit node, so only its
// answer is readdressed back (not, say, the answer to a query someone sent
// the exit node's DNS port directly).
type redirKey struct {
	client netip.Addr
	port   uint16
	id     uint16
}

const (
	redirTTL = 10 * time.Second // longer than any client waits
	redirMax = 4096
)

func dnsID(payload []byte) uint16 {
	if len(payload) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(payload)
}

func (t *TUN) noteRedirect(k redirKey) {
	now := time.Now()
	t.redirMu.Lock()
	defer t.redirMu.Unlock()
	if t.redir == nil {
		t.redir = map[redirKey]time.Time{}
	}
	if len(t.redir) >= redirMax {
		for k, exp := range t.redir {
			if now.After(exp) {
				delete(t.redir, k)
			}
		}
		if len(t.redir) >= redirMax {
			return // a flood of queries: their answers won't be readdressed
		}
	}
	t.redir[k] = now.Add(redirTTL)
}

// takeRedirect reports whether k was redirected (and still waits), and
// forgets it.
func (t *TUN) takeRedirect(k redirKey) bool {
	t.redirMu.Lock()
	defer t.redirMu.Unlock()
	exp, ok := t.redir[k]
	if !ok {
		return false
	}
	delete(t.redir, k)
	return time.Now().Before(exp)
}

// SetExitDNS sends the host's queries for names outside MagicDNS to the
// exit node at v4/v6 (its tunnel addresses), port ExitPort, through the
// tunnel; both invalid: answer them here as usual.
func (t *TUN) SetExitDNS(v4, v6 netip.Addr) {
	if !v4.IsValid() && !v6.IsValid() {
		t.exit.Store(nil)
		return
	}
	t.exit.Store(&exitDNS{v4, v6})
}

// toExit readdresses the query q (in pkt, a buffer of at least the
// packet's length) to the exit node, if one is in use and the name isn't
// MagicDNS's, returning the new packet's length (0: not redirected).
func (t *TUN) toExit(pkt []byte, q query) int {
	ex := t.exit.Load()
	if ex == nil || t.r.Local(q.payload) {
		return 0
	}
	to := ex.v4
	if q.dst.Is6() {
		to = ex.v6
	}
	if !to.IsValid() {
		return 0
	}
	t.noteRedirect(redirKey{q.src, q.srcPort, dnsID(q.payload)})
	return copy(pkt, udpPacket(q.src, to, q.srcPort, ExitPort, q.payload))
}

// fromExit readdresses the exit node's answer in pkt so it comes from
// MagicDNS, port 53, as the host asked; it returns the new length (0: not
// an answer from the exit node's DNS).
func (t *TUN) fromExit(pkt []byte) int {
	ex := t.exit.Load()
	if ex == nil {
		return 0
	}
	u, ok := parseUDP(pkt)
	if !ok || u.srcPort != ExitPort || (u.src != ex.v4 && u.src != ex.v6) ||
		!t.takeRedirect(redirKey{u.dst, u.dstPort, dnsID(u.payload)}) {
		return 0
	}
	from := t.addr4
	if u.src.Is6() {
		from = t.addr6
	}
	if !from.IsValid() {
		return 0
	}
	return copy(pkt, udpPacket(from, u.dst, 53, u.dstPort, u.payload))
}

// Write carries packets from the tunnel to the host, readdressing the exit
// node's DNS answers (see SetExitDNS).
func (t *TUN) Write(bufs [][]byte, offset int) (int, error) {
	if t.exit.Load() != nil && t.enabled.Load() {
		for i, b := range bufs {
			if n := t.fromExit(b[offset:]); n > 0 {
				bufs[i] = b[:offset+n]
			}
		}
	}
	return t.Device.Write(bufs, offset)
}

func (t *TUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		n, err := t.Device.Read(bufs, sizes, offset)
		if n == 0 || !t.enabled.Load() {
			return n, err
		}
		j := 0
		for i := 0; i < n; i++ {
			pkt := bufs[i][offset : offset+sizes[i]]
			if q, ok := t.match(pkt); ok {
				n := t.toExit(pkt, q)
				if n == 0 {
					t.handle(q)
					continue
				}
				// Readdressed to the exit node: on into the tunnel.
				sizes[i], pkt = n, pkt[:n]
			}
			if t.isTCPToResolver(pkt) {
				t.toTCPStack(pkt)
				continue
			}
			if j != i {
				copy(bufs[j][offset:], pkt)
				sizes[j] = sizes[i]
			}
			j++
		}
		if j > 0 || err != nil {
			return j, err
		}
	}
}

func (t *TUN) Close() error {
	t.closeMu.Lock()
	t.closed = true
	t.closeMu.Unlock()
	t.cancel()
	err := t.Device.Close()
	t.tcpOnce.Do(func() {}) // no stack starts after this
	if t.tcpStack != nil {
		t.tcpStack.close()
	}
	t.wg.Wait()
	return err
}

// query is a parsed DNS-over-UDP packet addressed to the resolver.
type query struct {
	src, dst         netip.Addr
	srcPort, dstPort uint16
	payload          []byte
}

// match reports whether pkt is a UDP packet to the resolver's port 53 and
// returns a copy of its contents.
func (t *TUN) match(pkt []byte) (query, bool) {
	q, ok := parseUDP(pkt)
	if !ok || q.dstPort != 53 || (q.dst != t.addr4 && q.dst != t.addr6) || !q.dst.IsValid() {
		return query{}, false
	}
	return q, true
}

// parseUDP parses an unfragmented IPv4 or IPv6 (no extension headers) UDP
// packet, copying its payload.
func parseUDP(pkt []byte) (query, bool) {
	if len(pkt) < 1 {
		return query{}, false
	}
	var q query
	var udp []byte
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return query{}, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if ihl < 20 || total < ihl || total > len(pkt) || pkt[9] != 17 {
			return query{}, false
		}
		if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
			return query{}, false // fragment
		}
		q.src, q.dst = netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20]))
		udp = pkt[ihl:total]
	case 6:
		if len(pkt) < 40 || pkt[6] != 17 { // no extension headers
			return query{}, false
		}
		plen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if 40+plen > len(pkt) {
			return query{}, false
		}
		q.src, q.dst = netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
		udp = pkt[40 : 40+plen]
	default:
		return query{}, false
	}
	if len(udp) < 8 {
		return query{}, false
	}
	q.srcPort, q.dstPort = binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4])
	ulen := int(binary.BigEndian.Uint16(udp[4:6]))
	if ulen < 8 || ulen > len(udp) {
		return query{}, false
	}
	q.payload = append([]byte(nil), udp[8:ulen]...)
	return q, true
}

// handle answers q in the background (forwarded queries can take seconds).
func (t *TUN) handle(q query) {
	t.closeMu.RLock()
	defer t.closeMu.RUnlock()
	if t.closed {
		return
	}
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		resp := t.r.Query(t.ctx, q.payload)
		if resp == nil || t.ctx.Err() != nil {
			return
		}
		pkt := udpPacket(q.dst, q.src, q.dstPort, q.srcPort, resp)
		buf := make([]byte, writeOffset+len(pkt))
		copy(buf[writeOffset:], pkt)
		if _, err := t.Device.Write([][]byte{buf}, writeOffset); err != nil && t.ctx.Err() == nil {
			t.logf("dns: write response: %v", err)
		}
	}()
}

// udpPacket builds an IPv4 or IPv6 UDP packet.
func udpPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	ulen := 8 + len(payload)
	var pkt []byte
	var udp []byte
	if src.Is4() {
		pkt = make([]byte, 20+ulen)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // don't fragment
		pkt[8] = 64
		pkt[9] = 17
		s, d := src.As4(), dst.As4()
		copy(pkt[12:16], s[:])
		copy(pkt[16:20], d[:])
		binary.BigEndian.PutUint16(pkt[10:12], ^fold(sum16(pkt[:20], 0)))
		udp = pkt[20:]
	} else {
		pkt = make([]byte, 40+ulen)
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:6], uint16(ulen))
		pkt[6] = 17
		pkt[7] = 64
		s, d := src.As16(), dst.As16()
		copy(pkt[8:24], s[:])
		copy(pkt[24:40], d[:])
		udp = pkt[40:]
	}
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(ulen))
	copy(udp[8:], payload)
	// Pseudo-header: addresses, protocol, UDP length.
	sum := sum16(src.AsSlice(), 0)
	sum = sum16(dst.AsSlice(), sum)
	sum += 17 + uint32(ulen)
	cs := ^fold(sum16(udp, sum))
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], cs)
	return pkt
}

// sum16 adds b's 16-bit big-endian words to sum (Internet checksum).
// Call with even-length b except for the last chunk.
func sum16(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}
