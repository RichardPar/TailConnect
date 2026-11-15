// Package filter is tcd's in-tunnel packet filter. It makes sharing one-way:
// a machine shared with our tenant may answer connections we open to it,
// but can't open connections to us.
//
// The filter sits between WireGuard and the TUN device. Packets we send to
// a restricted peer create flow entries; packets from a restricted peer are
// delivered only if they belong to one of those flows, open a connection
// the peer is allowed (access rules: e.g. TCP port 443), or are ICMP errors
// (path-MTU discovery needs them). Peers' source addresses can be trusted:
// WireGuard only accepts packets from a peer with that peer's own tunnel
// addresses as the source.
package filter

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"tailconnect/internal/protocol"
)

// Idle timeouts for flows, refreshed by traffic in either direction.
const (
	tcpTimeout    = 30 * time.Minute
	tcpRSTTimeout = 5 * time.Second
	udpTimeout    = 2 * time.Minute
	icmpTimeout   = 30 * time.Second
	maxFlows      = 65536
	gcInterval    = 30 * time.Second
)

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
	tcpRST      = 0x04
)

// flowKey identifies a flow from this machine's point of view. For ICMP
// echo, lport is the echo identifier and rport is 0.
type flowKey struct {
	proto         uint8
	local, remote netip.Addr
	lport, rport  uint16
}

type TUN struct {
	tun.Device
	now func() time.Time

	// restricted maps each restricted peer address to what it may still open
	// here (empty: nothing). nil = filter off.
	restricted atomic.Pointer[map[netip.Addr][]protocol.PortRange]

	mu     sync.Mutex
	flows  map[flowKey]time.Time // expiry
	lastGC time.Time

	dropped atomic.Int64
}

// Wrap returns dev with filtering (off until SetRestricted is called with addresses).
func Wrap(dev tun.Device) *TUN {
	return &TUN{Device: dev, now: time.Now, flows: map[flowKey]time.Time{}}
}

// SetRestricted sets the tunnel addresses of peers that may only reply.
func (t *TUN) SetRestricted(addrs []netip.Addr) {
	m := make(map[netip.Addr][]protocol.PortRange, len(addrs))
	for _, a := range addrs {
		m[a] = nil
	}
	t.SetPolicies(m)
}

// SetPolicies sets the restricted peers: each address may reply to our
// connections and open only the listed ports here.
func (t *TUN) SetPolicies(p map[netip.Addr][]protocol.PortRange) {
	if len(p) == 0 {
		t.restricted.Store(nil)
		return
	}
	m := make(map[netip.Addr][]protocol.PortRange, len(p))
	for a, r := range p {
		m[a.Unmap()] = r
	}
	t.restricted.Store(&m)
}

// Dropped counts packets the filter refused.
func (t *TUN) Dropped() int64 { return t.dropped.Load() }

// Read carries packets from this host into the tunnel; packets to
// restricted peers open (or refresh) flows.
func (t *TUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	rp := t.restricted.Load()
	if rp == nil || n == 0 {
		return n, err
	}
	locked := false
	var now time.Time
	for i := 0; i < n; i++ {
		b := bufs[i][offset : offset+sizes[i]]
		// Cheap address check first: most packets go to unrestricted peers.
		dst, ok := dstAddr(b)
		if !ok {
			continue
		}
		if _, restricted := (*rp)[dst]; !restricted {
			continue
		}
		pk, ok := parse(b)
		if !ok {
			continue
		}
		k, ok := pk.outboundKey()
		if !ok {
			continue
		}
		if !locked {
			t.mu.Lock()
			locked, now = true, t.now()
		}
		t.trackLocked(k, pk, now)
	}
	if locked {
		t.gcLocked(now)
		t.mu.Unlock()
	}
	return n, err
}

// Write carries packets from the tunnel to this host; packets from
// restricted peers pass only as part of a flow we started.
func (t *TUN) Write(bufs [][]byte, offset int) (int, error) {
	rp := t.restricted.Load()
	if rp == nil {
		return t.Device.Write(bufs, offset)
	}
	var keep [][]byte // allocated only once something is dropped
	locked := false
	var now time.Time
	for i, b := range bufs {
		pkt := b[offset:]
		src, isIP := srcAddr(pkt)
		allowedPorts, restricted := (*rp)[src]
		if !isIP || !restricted {
			if keep != nil {
				keep = append(keep, b)
			}
			continue
		}
		if !locked {
			t.mu.Lock()
			locked, now = true, t.now()
		}
		// From a restricted peer: unparseable packets (fragments, extension
		// headers) are refused, the rest must belong to one of our flows.
		if pk, ok := parse(pkt); ok && (permits(allowedPorts, pk) || t.allowInboundLocked(pk, now)) {
			if keep != nil {
				keep = append(keep, b)
			}
			continue
		}
		t.dropped.Add(1)
		if keep == nil {
			keep = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
		}
	}
	if locked {
		t.mu.Unlock()
	}
	if keep == nil {
		keep = bufs
	}
	if len(keep) == 0 {
		return len(bufs), nil
	}
	if _, err := t.Device.Write(keep, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

func (t *TUN) trackLocked(k flowKey, pk packet, now time.Time) {
	if _, exists := t.flows[k]; !exists && len(t.flows) >= maxFlows {
		t.lastGC = time.Time{}
		t.gcLocked(now)
		if len(t.flows) >= maxFlows {
			return // full: the reply will be dropped
		}
	}
	t.flows[k] = now.Add(pk.timeout())
}

func (t *TUN) allowInboundLocked(pk packet, now time.Time) bool {
	if pk.icmpError() {
		return true
	}
	k, ok := pk.inboundKey()
	if !ok {
		return false
	}
	exp, found := t.flows[k]
	if !found || now.After(exp) {
		return false
	}
	t.flows[k] = now.Add(pk.timeout()) // replies keep the flow alive too
	return true
}

func (t *TUN) gcLocked(now time.Time) {
	if now.Sub(t.lastGC) < gcInterval {
		return
	}
	t.lastGC = now
	for k, exp := range t.flows {
		if now.After(exp) {
			delete(t.flows, k)
		}
	}
}

// ---- packet parsing ----

type packet struct {
	proto        uint8
	src, dst     netip.Addr
	sport, dport uint16 // TCP/UDP ports; for ICMP echo, sport = identifier
	tcpFlags     uint8
	icmpType     uint8
	v6           bool
}

func (p packet) echoRequest() bool {
	return (p.proto == protoICMP && p.icmpType == 8) || (p.proto == protoICMPv6 && p.icmpType == 128)
}

func (p packet) echoReply() bool {
	return (p.proto == protoICMP && p.icmpType == 0) || (p.proto == protoICMPv6 && p.icmpType == 129)
}

func (p packet) icmpError() bool {
	switch p.proto {
	case protoICMP:
		return p.icmpType == 3 || p.icmpType == 11 || p.icmpType == 12
	case protoICMPv6:
		return p.icmpType >= 1 && p.icmpType <= 4
	}
	return false
}

// outboundKey is the flow a packet we send belongs to.
func (p packet) outboundKey() (flowKey, bool) {
	switch {
	case p.proto == protoTCP || p.proto == protoUDP:
		return flowKey{p.proto, p.src, p.dst, p.sport, p.dport}, true
	case p.echoRequest():
		return flowKey{p.proto, p.src, p.dst, p.sport, 0}, true
	}
	return flowKey{}, false
}

// inboundKey is the flow a received packet would have to belong to.
func (p packet) inboundKey() (flowKey, bool) {
	switch {
	case p.proto == protoTCP || p.proto == protoUDP:
		return flowKey{p.proto, p.dst, p.src, p.dport, p.sport}, true
	case p.echoReply():
		return flowKey{p.proto, p.dst, p.src, p.sport, 0}, true
	}
	return flowKey{}, false
}

func (p packet) timeout() time.Duration {
	switch p.proto {
	case protoTCP:
		if p.tcpFlags&tcpRST != 0 {
			return tcpRSTTimeout
		}
		return tcpTimeout
	case protoUDP:
		return udpTimeout
	}
	return icmpTimeout
}

func dstAddr(b []byte) (netip.Addr, bool) {
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(b[16:20])), true
	case len(b) >= 40 && b[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(b[24:40])).Unmap(), true
	}
	return netip.Addr{}, false
}

func srcAddr(b []byte) (netip.Addr, bool) {
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case len(b) >= 40 && b[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(b[8:24])).Unmap(), true
	}
	return netip.Addr{}, false
}

// parse extracts what the filter needs. It fails for non-first fragments,
// IPv6 extension headers and truncated packets.
func parse(b []byte) (packet, bool) {
	var p packet
	var l4 []byte
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return p, false
		}
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return p, false // non-first fragment: no transport header
		}
		p.proto = b[9]
		p.src, p.dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		l4 = b[ihl:]
	case len(b) >= 40 && b[0]>>4 == 6:
		p.v6 = true
		p.proto = b[6]
		if p.proto != protoTCP && p.proto != protoUDP && p.proto != protoICMPv6 {
			return p, false
		}
		p.src, p.dst = netip.AddrFrom16([16]byte(b[8:24])).Unmap(), netip.AddrFrom16([16]byte(b[24:40])).Unmap()
		l4 = b[40:]
	default:
		return p, false
	}
	switch p.proto {
	case protoTCP:
		if len(l4) < 14 {
			return p, false
		}
		p.sport, p.dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
		p.tcpFlags = l4[13]
	case protoUDP:
		if len(l4) < 8 {
			return p, false
		}
		p.sport, p.dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
	case protoICMP, protoICMPv6:
		if len(l4) < 8 {
			return p, false
		}
		p.icmpType = l4[0]
		p.sport = binary.BigEndian.Uint16(l4[4:6]) // echo identifier
	}
	return p, true
}

// permits reports whether a restricted peer may open this connection here.
func permits(ranges []protocol.PortRange, p packet) bool {
	for _, r := range ranges {
		switch {
		case r.Proto == "icmp":
			if p.echoRequest() {
				return true
			}
		case p.proto == protoTCP && (r.Proto == "" || r.Proto == "tcp"),
			p.proto == protoUDP && (r.Proto == "" || r.Proto == "udp"):
			if p.dport >= r.First && p.dport <= r.Last {
				return true
			}
		}
	}
	return false
}
