package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
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
