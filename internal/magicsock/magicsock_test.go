package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
	"tailconnect/internal/stun"
)

func TestTrusted(t *testing.T) {
	now := time.Now()
	addr := netip.MustParseAddrPort("10.0.0.2:41641")
	cases := []struct {
		name string
		p    peer
		want bool
	}{
		{"no direct addr", peer{}, false},
		{"recent receive", peer{directAddr: addr, lastDirectRecv: now.Add(-time.Second)}, true},
		{"stale receive", peer{directAddr: addr, lastDirectRecv: now.Add(-TrustWindow - time.Second)}, false},
		{"sending, answered recently", peer{directAddr: addr, lastDirectRecv: now.Add(-time.Second), firstUnanswered: now.Add(-time.Second)}, true},
		{"sending into the void", peer{directAddr: addr, lastDirectRecv: now.Add(-5 * time.Second), firstUnanswered: now.Add(-UnansweredLimit - time.Second)}, false},
	}
	for _, c := range cases {
		if got := c.p.trusted(now); got != c.want {
			t.Errorf("%s: trusted=%v want %v", c.name, got, c.want)
		}
	}
}

func TestPickEndpoint(t *testing.T) {
	local := []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}
	ap := netip.MustParseAddrPort
	cases := []struct {
		cands []netip.AddrPort
		want  string
	}{
		{[]netip.AddrPort{ap("10.200.0.2:1"), ap("192.168.10.7:1")}, "192.168.10.7:1"}, // same subnet wins
		{[]netip.AddrPort{ap("[fd00::1]:1"), ap("10.200.0.2:1")}, "10.200.0.2:1"},      // else first IPv4
		{[]netip.AddrPort{ap("[fe80::1]:1"), ap("[fd00::1]:1")}, "[fd00::1]:1"},        // link-local skipped
		{[]netip.AddrPort{ap("[::ffff:10.0.0.1]:5")}, "10.0.0.1:5"},                    // unmapped
		{[]netip.AddrPort{ap("0.0.0.0:1")}, "invalid AddrPort"},
	}
	for _, c := range cases {
		got, _ := PickEndpoint(c.cands, local)
		if got.String() != c.want {
			t.Errorf("PickEndpoint(%v) = %v, want %v", c.cands, got, c.want)
		}
	}
}

func wgMsg(typ byte, idxAt int, idx uint32, size int) []byte {
	b := make([]byte, size)
	b[0] = typ
	b[idxAt], b[idxAt+1], b[idxAt+2], b[idxAt+3] = byte(idx), byte(idx>>8), byte(idx>>16), byte(idx>>24)
	return b
}

func TestIndexAttribution(t *testing.T) {
	c := New(Options{PrivateKey: key.NewPrivate[key.NodeKind]()})
	a := key.NewPrivate[key.NodeKind]().Public()
	b := key.NewPrivate[key.NodeKind]().Public()
	c.SetNetworkMap([]protocol.Node{{NodeKey: a, HomeRelay: 2}, {NodeKey: b}}, protocol.RelayMap{}, nil)

	got, err := c.ParseEndpoint(a.String())
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := got.(*Endpoint); !ok || !e.key.Equal(a) {
		t.Fatalf("ParseEndpoint returned %#v", got)
	}

	now := time.Now()
	c.mu.Lock()
	// We send an initiation to a (our index 0x1111) and a response to b (our index 0x2222).
	c.noteSentLocked(a, wgMsg(wgInitiation, 4, 0x1111, 148), now)
	c.noteSentLocked(b, wgMsg(wgResponse, 4, 0x2222, 92), now)
	cases := []struct {
		name string
		pkt  []byte
		want key.NodePublic
	}{
		{"response from a", wgMsg(wgResponse, 8, 0x1111, 92), a},
		{"data from a", wgMsg(wgTransport, 4, 0x1111, 64), a},
		{"data from b", wgMsg(wgTransport, 4, 0x2222, 64), b},
		{"cookie for b", wgMsg(wgCookie, 4, 0x2222, 64), b},
		{"unknown index", wgMsg(wgTransport, 4, 0x9999, 64), key.NodePublic{}},
		{"initiation", wgMsg(wgInitiation, 4, 0x1111, 148), key.NodePublic{}},
		{"not wireguard", []byte{4, 1, 0, 0, 0x11, 0x11, 0, 0}, key.NodePublic{}},
		{"short", []byte{4, 0, 0}, key.NodePublic{}},
	}
	for _, tc := range cases {
		p := c.attributeLocked(tc.pkt)
		switch {
		case tc.want.IsZero() && p != nil:
			t.Errorf("%s: attributed to %v, want none", tc.name, p.key.ShortString())
		case !tc.want.IsZero() && (p == nil || !p.key.Equal(tc.want)):
			t.Errorf("%s: wrong attribution", tc.name)
		}
	}
	c.mu.Unlock()

	if pi := c.Paths()[a]; pi.Direct.IsValid() || pi.Relay != 2 {
		t.Fatalf("new peer should use its home relay: %+v", pi)
	}
	// Removing a peer from the map stops attribution to it.
	c.SetNetworkMap([]protocol.Node{{NodeKey: b}}, protocol.RelayMap{}, nil)
	c.mu.Lock()
	if p := c.attributeLocked(wgMsg(wgTransport, 4, 0x1111, 64)); p != nil {
		t.Fatal("removed peer still attributed")
	}
	c.mu.Unlock()
	// Plain addresses still parse (used only for cookie replies).
	if _, err := c.ParseEndpoint("10.0.0.1:41641"); err != nil {
		t.Fatal(err)
	}
}

func TestChooseHome(t *testing.T) {
	c := New(Options{PrivateKey: key.NewPrivate[key.NodeKind]()})
	defer c.Shutdown()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.relayMap = protocol.RelayMap{Regions: []protocol.RelayRegion{
		{ID: 1, Nodes: []protocol.RelayNode{{URL: "https://r1.example/relay"}}},
		{ID: 2, Nodes: []protocol.RelayNode{{URL: "https://r2.example/relay"}}},
		{ID: 3, Nodes: []protocol.RelayNode{{URL: "https://r3.example/relay"}}},
	}}
	if h := c.chooseHomeLocked(); h != 1 {
		t.Fatalf("before measurements: home=%d, want lowest ID 1", h)
	}
	c.home = 1
	c.regionLatency = map[int]time.Duration{1: 50 * time.Millisecond, 2: 40 * time.Millisecond, 3: 20 * time.Millisecond}
	if h := c.chooseHomeLocked(); h != 3 {
		t.Fatalf("home=%d, want fastest region 3", h)
	}
	c.home = 3
	c.regionLatency[2] = 16 * time.Millisecond // faster, but not by enough to switch
	if h := c.chooseHomeLocked(); h != 3 {
		t.Fatalf("home=%d, hysteresis should keep region 3", h)
	}
	c.regionLatency[2] = 10 * time.Millisecond // now clearly faster
	if h := c.chooseHomeLocked(); h != 2 {
		t.Fatalf("home=%d, want region 2", h)
	}
}

func TestRelayReceiveWithdrawsTrust(t *testing.T) {
	now := time.Now()
	addr := netip.MustParseAddrPort("10.0.0.2:41641")

	// The failure this guards against: the path died while idle, the peer
	// gave up on it and wrote through the relay. We heard from it directly
	// 3s ago and haven't sent since, so we'd otherwise still trust direct.
	p := peer{directAddr: addr, lastDirectRecv: now.Add(-3 * time.Second)}
	if !p.trusted(now) {
		t.Fatal("precondition: direct path trusted")
	}
	if !p.noteRelayRecv(now) || p.trusted(now) {
		t.Fatal("a relayed packet should withdraw trust in a quiet direct path")
	}
	if p.noteRelayRecv(now) {
		t.Fatal("already untrusted: nothing to withdraw")
	}

	// While discovering paths a peer sends both ways; a recent direct packet
	// means the path works, so keep it.
	q := peer{directAddr: addr, lastDirectRecv: now.Add(-200 * time.Millisecond)}
	if q.noteRelayRecv(now) || !q.trusted(now) {
		t.Fatal("recent direct traffic: trust must be kept")
	}
}

func TestSTUNIgnoresHairpin(t *testing.T) {
	c := New(Options{PrivateKey: key.NewPrivate[key.NodeKind]()})
	defer c.Shutdown()
	c.mu.Lock()
	defer c.mu.Unlock()
	answer := func(server, mapped string) {
		tx := stun.NewTxID()
		c.stunTx[tx] = stunRequest{region: 1, server: netip.MustParseAddr(server), sent: time.Now()}
		c.handleSTUNLocked(stun.Response(tx, netip.MustParseAddrPort(mapped)))
	}
	cases := []struct {
		server, mapped string
		want           bool
	}{
		{"90.192.119.100", "78.86.136.87:58537", true},   // public server, public answer
		{"90.192.119.100", "192.168.10.254:2482", false}, // NAT loopback: router's LAN side
		{"90.192.119.100", "100.70.1.2:2482", false},     // CGNAT space is not public either
		{"192.168.10.131", "192.168.10.205:41641", true}, // LAN STUN server: trust it
		{"10.200.0.1", "10.200.0.2:41641", true},         // lab NAT setup
	}
	for _, tc := range cases {
		delete(c.stunAddrs, 1)
		answer(tc.server, tc.mapped)
		got, ok := c.stunAddrs[1]
		if ok != tc.want || (ok && got != netip.MustParseAddrPort(tc.mapped)) {
			t.Errorf("server %s mapped %s: stored=%v (%v), want stored=%v", tc.server, tc.mapped, ok, got, tc.want)
		}
	}
	// A hairpin answer after a real one withdraws the stale address.
	answer("90.192.119.100", "78.86.136.87:58537")
	answer("90.192.119.100", "192.168.10.254:9999")
	if a, ok := c.stunAddrs[1]; ok {
		t.Errorf("hairpin answer left %v advertised", a)
	}
}

// A WireGuard packet attributed to a peer by its receiver index (which an
// eavesdropper can copy) doesn't move the peer's path to a new address; it
// triggers a signed disco ping there instead. Packets from the path in use
// keep it fresh.
func TestNewAddressProbedNotAdopted(t *testing.T) {
	c := New(Options{PrivateKey: key.NewPrivate[key.NodeKind](), DiscoKey: key.NewPrivate[key.DiscoKind]()})
	defer c.Close()
	now := time.Now()
	evil := netip.MustParseAddrPort("203.0.113.66:4444")
	good := netip.MustParseAddrPort("192.168.1.20:41641")
	p := newPeer(key.NewPrivate[key.NodeKind]().Public())
	p.discoKey = key.NewPrivate[key.DiscoKind]().Public()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.noteDirectRecvLocked(p, evil, now)
	if p.directAddr.IsValid() {
		t.Fatalf("path adopted from an unauthenticated packet: %v", p.directAddr)
	}
	if ep := p.eps[evil]; ep == nil {
		t.Fatal("new address not recorded as a candidate to ping")
	}
	// The path in use is refreshed by its own packets.
	p.directAddr, p.lastDirectRecv, p.firstUnanswered = good, now.Add(-10*time.Second), now.Add(-time.Second)
	c.noteDirectRecvLocked(p, good, now)
	if p.lastDirectRecv != now || !p.firstUnanswered.IsZero() {
		t.Fatal("path in use not refreshed")
	}
	// A trusted path isn't replaced by packets from elsewhere.
	c.noteDirectRecvLocked(p, evil, now)
	if p.directAddr != good {
		t.Fatalf("trusted path replaced by %v", p.directAddr)
	}
}

// Two peers with one disco key (one copied the other's) can't be told
// apart, so neither is found by it; a peer with its own key still is.
func TestDuplicateDiscoKeys(t *testing.T) {
	c := New(Options{PrivateKey: key.NewPrivate[key.NodeKind]()})
	a := key.NewPrivate[key.NodeKind]().Public()
	b := key.NewPrivate[key.NodeKind]().Public()
	o := key.NewPrivate[key.NodeKind]().Public()
	shared := key.NewPrivate[key.DiscoKind]().Public()
	own := key.NewPrivate[key.DiscoKind]().Public()
	c.SetNetworkMap([]protocol.Node{{NodeKey: a, DiscoKey: shared}, {NodeKey: b, DiscoKey: shared}, {NodeKey: o, DiscoKey: own}}, protocol.RelayMap{}, nil)
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.byDisco[shared]; p != nil {
		t.Fatalf("duplicate disco key maps to %v", p.key.ShortString())
	}
	if p := c.byDisco[own]; p == nil || !p.key.Equal(o) {
		t.Fatal("peer with its own disco key not found")
	}
}
