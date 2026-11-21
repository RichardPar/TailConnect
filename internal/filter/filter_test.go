package filter

import (
	"encoding/binary"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"tailconnect/internal/protocol"
)

// fakeTUN returns queued packets from Read and records Writes.
type fakeTUN struct {
	out     [][]byte // packets the host "sends" (returned by Read)
	written [][]byte
}

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return 1280, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return 1 }
func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	p := f.out[0]
	f.out = f.out[1:]
	sizes[0] = copy(bufs[0][offset:], p)
	return 1, nil
}
func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written = append(f.written, slices.Clone(b[offset:]))
	}
	return len(bufs), nil
}

var (
	me     = netip.MustParseAddr("100.64.0.1")
	shared = netip.MustParseAddr("100.64.0.9") // restricted: may only reply
	friend = netip.MustParseAddr("100.64.0.2") // same tenant: unrestricted
	me6    = netip.MustParseAddr("fd7c:7c0e:a1e0::6440:1")
	shrd6  = netip.MustParseAddr("fd7c:7c0e:a1e0::6440:9")
)

func ip(src, dst netip.Addr, proto uint8, l4 []byte) []byte {
	if src.Is4() {
		b := make([]byte, 20+len(l4))
		b[0], b[9] = 0x45, proto
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		s, d := src.As4(), dst.As4()
		copy(b[12:], s[:])
		copy(b[16:], d[:])
		copy(b[20:], l4)
		return b
	}
	b := make([]byte, 40+len(l4))
	b[0], b[6] = 0x60, proto
	binary.BigEndian.PutUint16(b[4:6], uint16(len(l4)))
	s, d := src.As16(), dst.As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	copy(b[40:], l4)
	return b
}

func tcp(src, dst netip.Addr, sport, dport uint16, flags uint8) []byte {
	l4 := make([]byte, 20)
	binary.BigEndian.PutUint16(l4[0:], sport)
	binary.BigEndian.PutUint16(l4[2:], dport)
	l4[12], l4[13] = 5<<4, flags
	return ip(src, dst, protoTCP, l4)
}

func udp(src, dst netip.Addr, sport, dport uint16) []byte {
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:], sport)
	binary.BigEndian.PutUint16(l4[2:], dport)
	return ip(src, dst, protoUDP, l4)
}

func icmp(src, dst netip.Addr, typ uint8, id uint16) []byte {
	l4 := make([]byte, 8)
	l4[0] = typ
	binary.BigEndian.PutUint16(l4[4:], id)
	proto := uint8(protoICMP)
	if src.Is6() {
		proto = protoICMPv6
	}
	return ip(src, dst, proto, l4)
}

const (
	syn    = 0x02
	synack = 0x12
	ack    = 0x10
	rst    = 0x04
)

type harness struct {
	t   *testing.T
	f   *fakeTUN
	w   *TUN
	now time.Time
}

func newHarness(t *testing.T) *harness {
	f := &fakeTUN{}
	h := &harness{t: t, f: f, w: Wrap(f), now: time.Now()}
	h.w.now = func() time.Time { return h.now }
	h.w.SetRestricted([]netip.Addr{shared, shrd6})
	return h
}

// send passes a packet from this host into the tunnel.
func (h *harness) send(p []byte) {
	h.t.Helper()
	h.f.out = append(h.f.out, p)
	bufs := [][]byte{make([]byte, 16+1500)}
	sizes := []int{0}
	if n, err := h.w.Read(bufs, sizes, 16); n != 1 || err != nil {
		h.t.Fatalf("read: %d %v", n, err)
	}
}

// recv delivers a packet from the tunnel and reports whether it reached the host.
func (h *harness) recv(p []byte) bool {
	h.t.Helper()
	before := len(h.f.written)
	buf := make([]byte, 16+len(p))
	copy(buf[16:], p)
	if _, err := h.w.Write([][]byte{buf}, 16); err != nil {
		h.t.Fatal(err)
	}
	return len(h.f.written) > before
}

func TestRestrictedPeerCannotInitiate(t *testing.T) {
	h := newHarness(t)
	if h.recv(tcp(shared, me, 40000, 22, syn)) {
		t.Fatal("TCP SYN from a shared machine reached the host")
	}
	if h.recv(udp(shared, me, 5000, 53)) {
		t.Fatal("UDP from a shared machine reached the host")
	}
	if h.recv(icmp(shared, me, 8, 1)) {
		t.Fatal("ping from a shared machine reached the host")
	}
	if h.recv(ip(shared, me, 47, make([]byte, 8))) {
		t.Fatal("other protocols from a shared machine reached the host")
	}
	if h.recv(tcp(shrd6, me6, 40000, 22, syn)) {
		t.Fatal("IPv6 SYN from a shared machine reached the host")
	}
	if h.w.Dropped() != 5 {
		t.Fatalf("dropped = %d", h.w.Dropped())
	}
	// Same-tenant peers are unaffected.
	if !h.recv(tcp(friend, me, 40000, 22, syn)) || !h.recv(icmp(friend, me, 8, 1)) {
		t.Fatal("same-tenant traffic was filtered")
	}
}

func TestRepliesToOurFlows(t *testing.T) {
	h := newHarness(t)
	// TCP: we connect to the shared machine's port 445.
	h.send(tcp(me, shared, 50000, 445, syn))
	if !h.recv(tcp(shared, me, 445, 50000, synack)) {
		t.Fatal("SYN-ACK for our connection dropped")
	}
	if h.recv(tcp(shared, me, 445, 50001, synack)) {
		t.Fatal("packet to a different local port accepted")
	}
	if h.recv(tcp(shared, me, 446, 50000, ack)) {
		t.Fatal("packet from a different remote port accepted")
	}
	// UDP.
	h.send(udp(me, shared, 6000, 53))
	if !h.recv(udp(shared, me, 53, 6000)) {
		t.Fatal("UDP reply dropped")
	}
	// Ping: our echo request lets the matching reply in.
	h.send(icmp(me, shared, 8, 77))
	if !h.recv(icmp(shared, me, 0, 77)) {
		t.Fatal("echo reply dropped")
	}
	if h.recv(icmp(shared, me, 0, 78)) {
		t.Fatal("echo reply with another identifier accepted")
	}
	// IPv6 too.
	h.send(icmp(me6, shrd6, 128, 5))
	if !h.recv(icmp(shrd6, me6, 129, 5)) {
		t.Fatal("ICMPv6 echo reply dropped")
	}
	// ICMP errors (path MTU discovery) pass.
	if !h.recv(icmp(shared, me, 3, 0)) || !h.recv(icmp(shrd6, me6, 2, 0)) {
		t.Fatal("ICMP errors dropped")
	}
}

func TestFlowExpiry(t *testing.T) {
	h := newHarness(t)
	h.send(udp(me, shared, 6000, 53))
	h.now = h.now.Add(udpTimeout - time.Second)
	if !h.recv(udp(shared, me, 53, 6000)) {
		t.Fatal("reply within the timeout dropped")
	}
	// The reply refreshed the flow.
	h.now = h.now.Add(udpTimeout - time.Second)
	if !h.recv(udp(shared, me, 53, 6000)) {
		t.Fatal("refreshed flow expired early")
	}
	h.now = h.now.Add(udpTimeout + time.Second)
	if h.recv(udp(shared, me, 53, 6000)) {
		t.Fatal("expired flow still open")
	}
	// A reset closes TCP flows quickly.
	h.send(tcp(me, shared, 50000, 80, syn))
	h.recv(tcp(shared, me, 80, 50000, rst))
	h.now = h.now.Add(tcpRSTTimeout + time.Second)
	if h.recv(tcp(shared, me, 80, 50000, ack)) {
		t.Fatal("flow open after RST")
	}
}

func TestFragmentsAndOff(t *testing.T) {
	h := newHarness(t)
	frag := udp(shared, me, 53, 6000)
	binary.BigEndian.PutUint16(frag[6:8], 100) // fragment offset != 0
	h.send(udp(me, shared, 6000, 53))
	if h.recv(frag) {
		t.Fatal("non-first fragment from a shared machine accepted")
	}
	f2 := udp(friend, me, 53, 6000)
	binary.BigEndian.PutUint16(f2[6:8], 100)
	if !h.recv(f2) {
		t.Fatal("fragment from a same-tenant peer dropped")
	}
	// Turning the filter off lets everything through.
	h.w.SetRestricted(nil)
	if !h.recv(tcp(shared, me, 40000, 22, syn)) {
		t.Fatal("filter still active after SetRestricted(nil)")
	}
}

func TestAllowedPorts(t *testing.T) {
	h := newHarness(t)
	h.w.SetPolicies(map[netip.Addr][]protocol.PortRange{
		shared: {{Proto: "tcp", First: 443, Last: 443}, {First: 8000, Last: 8100}, {Proto: "icmp"}},
		shrd6:  nil,
	})
	if !h.recv(tcp(shared, me, 40000, 443, syn)) {
		t.Fatal("tcp:443 not allowed")
	}
	if h.recv(udp(shared, me, 40000, 443)) {
		t.Fatal("udp:443 allowed by a tcp-only rule")
	}
	if !h.recv(udp(shared, me, 40000, 8050)) || !h.recv(tcp(shared, me, 40000, 8100, syn)) {
		t.Fatal("8000-8100 (tcp and udp) not allowed")
	}
	if h.recv(tcp(shared, me, 40000, 22, syn)) {
		t.Fatal("port 22 allowed without a rule")
	}
	if !h.recv(icmp(shared, me, 8, 1)) {
		t.Fatal("ping not allowed by an icmp rule")
	}
	if h.recv(tcp(shrd6, me6, 40000, 443, syn)) {
		t.Fatal("a peer with no allowed ports got in")
	}
	// Replies to our own connections still pass, on any port.
	h.send(tcp(me, shared, 50000, 22, syn))
	if !h.recv(tcp(shared, me, 22, 50000, synack)) {
		t.Fatal("reply to our connection dropped")
	}
}

// On an exit node, packets from the tunnel to addresses that aren't this
// machine's (the internet, the LAN) pass only from peers allowed to use it.
func TestForwardingOnlyForAllowedPeers(t *testing.T) {
	h := newHarness(t)
	internet := netip.MustParseAddr("8.8.8.8")
	lan := netip.MustParseAddr("192.168.10.1")
	h.w.SetPolicy(Policy{
		Restricted: map[netip.Addr][]protocol.PortRange{shared: {{Proto: "tcp", First: 443, Last: 443}}},
		Self:       []netip.Addr{me, me6},
		Forward:    map[netip.Addr]bool{friend: true},
	})
	if !h.recv(tcp(friend, internet, 5000, 443, syn)) {
		t.Fatal("allowed peer's internet traffic dropped")
	}
	if !h.recv(tcp(friend, me, 5000, 22, syn)) {
		t.Fatal("allowed peer can't reach this machine")
	}
	// The shared (restricted) peer may open 443 on this machine, but not
	// anything through it, on any port.
	if !h.recv(tcp(shared, me, 5000, 443, syn)) {
		t.Fatal("restricted peer's allowed port dropped")
	}
	for _, dst := range []netip.Addr{internet, lan} {
		if h.recv(tcp(shared, dst, 5000, 443, syn)) {
			t.Fatalf("restricted peer forwarded to %v", dst)
		}
	}
	// Without Forward (not an exit node), nobody's packets are forwarded.
	h.w.SetPolicy(Policy{Self: []netip.Addr{me, me6}})
	if h.recv(tcp(friend, lan, 5000, 80, syn)) {
		t.Fatal("forwarded although this machine isn't an exit node")
	}
}

// Using a restricted exit node: everything from non-peer addresses gets
// its restrictions; replies to our own connections still come back.
func TestRestrictedExitNodeInUse(t *testing.T) {
	h := newHarness(t)
	exit := shared
	h.w.SetPolicy(Policy{
		Restricted: map[netip.Addr][]protocol.PortRange{exit: nil},
		Self:       []netip.Addr{me, me6},
		Exit:       &ExitLimit{Peers: map[netip.Addr]bool{exit: true, friend: true}},
	})
	spoofed := netip.MustParseAddr("1.2.3.4")
	if h.recv(tcp(spoofed, me, 5000, 22, syn)) {
		t.Fatal("restricted exit node opened a connection from a made-up internet address")
	}
	site := netip.MustParseAddr("93.184.216.34")
	h.send(tcp(me, site, 40000, 443, syn))
	if !h.recv(tcp(site, me, 443, 40000, synack)) {
		t.Fatal("reply from the internet through the exit node dropped")
	}
	if !h.recv(tcp(friend, me, 5000, 22, syn)) {
		t.Fatal("unrestricted peer affected by the exit node's limits")
	}
}

// IPv4 packets claiming to be ICMPv6 (errors pass the filter) are refused.
func TestIPv4WithICMPv6Refused(t *testing.T) {
	h := newHarness(t)
	l4 := make([]byte, 8)
	l4[0] = 1 // ICMPv6 destination unreachable, if it were IPv6
	if h.recv(ip(shared, me, protoICMPv6, l4)) {
		t.Fatal("IPv4 packet with protocol 58 passed the filter")
	}
}
