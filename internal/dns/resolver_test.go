package dns

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	pool4 = netip.MustParsePrefix("100.64.0.0/10")
	pool6 = netip.MustParsePrefix("fd7c:7c0e:a1e0::/48")
	alice = []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7c:7c0e:a1e0::6440:1")}
)

func testResolver(upstream ...netip.AddrPort) *Resolver {
	r := NewResolver(nil)
	r.SetConfig(Config{
		Domain:          "TC.internal",
		Hosts:           map[string][]netip.Addr{"alice.tc.internal": alice, "v4only.tc.internal": {netip.MustParseAddr("100.64.0.9")}},
		ReversePrefixes: []netip.Prefix{pool4, pool6},
		Upstream:        upstream,
	})
	return r
}

func mkQuery(t *testing.T, name string, typ dnsmessage.Type, edns bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	if edns {
		b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		rh.SetEDNS0(4096, dnsmessage.RCodeSuccess, false)
		b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parse(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return m
}

func answerAddrs(m dnsmessage.Message) []string {
	var out []string
	for _, a := range m.Answers {
		switch b := a.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(b.A).String())
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(b.AAAA).String())
		case *dnsmessage.PTRResource:
			out = append(out, b.PTR.String())
		}
	}
	return out
}

func TestLocalAnswers(t *testing.T) {
	r := testResolver()
	cases := []struct {
		name  string
		typ   dnsmessage.Type
		rcode dnsmessage.RCode
		want  []string
	}{
		{"alice.tc.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []string{"100.64.0.1"}},
		{"ALICE.Tc.Internal.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, []string{"fd7c:7c0e:a1e0::6440:1"}},
		{"alice.tc.internal.", dnsmessage.TypeALL, dnsmessage.RCodeSuccess, []string{"100.64.0.1", "fd7c:7c0e:a1e0::6440:1"}},
		{"alice.tc.internal.", dnsmessage.TypeMX, dnsmessage.RCodeSuccess, nil},
		{"v4only.tc.internal.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, nil},
		{"tc.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, nil},
		{"bob.tc.internal.", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"www.alice.tc.internal.", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"1.0.64.100.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeSuccess, []string{"alice.tc.internal."}},
		{"2.0.64.100.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeNameError, nil},
		{reverse6(alice[1]), dnsmessage.TypePTR, dnsmessage.RCodeSuccess, []string{"alice.tc.internal."}},
		// Not ours, and no upstream configured.
		{"example.com.", dnsmessage.TypeA, dnsmessage.RCodeRefused, nil},
		{"1.1.168.192.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeRefused, nil},
	}
	for _, c := range cases {
		m := parse(t, r.Query(context.Background(), mkQuery(t, c.name, c.typ, false)))
		if m.ID != 0x1234 || !m.Response || m.RCode != c.rcode {
			t.Errorf("%s %v: id=%#x response=%v rcode=%v, want rcode %v", c.name, c.typ, m.ID, m.Response, m.RCode, c.rcode)
			continue
		}
		if got := answerAddrs(m); !slices.Equal(got, c.want) {
			t.Errorf("%s %v: answers %v, want %v", c.name, c.typ, got, c.want)
		}
		if len(m.Questions) != 1 || m.Questions[0].Name.String() != c.name {
			t.Errorf("%s: question not echoed verbatim: %v", c.name, m.Questions)
		}
	}
}

func reverse6(a netip.Addr) string {
	b := a.As16()
	var parts []string
	for i := 15; i >= 0; i-- {
		parts = append(parts, string("0123456789abcdef"[b[i]&0xf]), string("0123456789abcdef"[b[i]>>4]))
	}
	return strings.Join(parts, ".") + ".ip6.arpa."
}

func TestEDNSEcho(t *testing.T) {
	r := testResolver()
	m := parse(t, r.Query(context.Background(), mkQuery(t, "alice.tc.internal.", dnsmessage.TypeA, true)))
	if len(m.Additionals) != 1 || m.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		t.Fatalf("EDNS query should get an OPT record back: %v", m.Additionals)
	}
}

func TestMalformed(t *testing.T) {
	r := testResolver()
	if r.Query(context.Background(), []byte{1, 2, 3}) != nil {
		t.Error("garbage should be dropped")
	}
	resp := r.Query(context.Background(), mkQuery(t, "alice.tc.internal.", dnsmessage.TypeA, false))
	if r.Query(context.Background(), resp) != nil {
		t.Error("responses should be dropped")
	}
}

// fakeUpstream answers every query with n TXT records of 100 bytes.
func fakeUpstream(t *testing.T, n int) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			k, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, _ := p.Start(buf[:k])
			q, _ := p.Question()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			for i := 0; i < n; i++ {
				b.TXTResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.TXTResource{TXT: []string{strings.Repeat("x", 100)}})
			}
			out, _ := b.Finish()
			pc.WriteTo(out, from)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// deadUpstream returns a port where nothing listens (the kernel answers
// with ICMP port unreachable, so the attempt fails fast).
func deadUpstream(t *testing.T) netip.AddrPort {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(pc.LocalAddr().String())
	pc.Close()
	return ap
}

func TestForward(t *testing.T) {
	r := testResolver(deadUpstream(t), fakeUpstream(t, 1))
	m := parse(t, r.Query(context.Background(), mkQuery(t, "example.com.", dnsmessage.TypeTXT, false)))
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 || m.ID != 0x1234 {
		t.Fatalf("forwarded answer: rcode=%v answers=%d id=%#x", m.RCode, len(m.Answers), m.ID)
	}
	// MagicDNS names are never forwarded.
	m = parse(t, r.Query(context.Background(), mkQuery(t, "bob.tc.internal.", dnsmessage.TypeA, false)))
	if m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("bob: rcode %v", m.RCode)
	}
}

func TestForwardTruncates(t *testing.T) {
	r := testResolver(fakeUpstream(t, 8)) // ~900 bytes: over 512 without EDNS
	m := parse(t, r.Query(context.Background(), mkQuery(t, "big.example.", dnsmessage.TypeTXT, false)))
	if !m.Truncated || len(m.Answers) != 0 {
		t.Fatalf("want truncated, empty response; got tc=%v answers=%d", m.Truncated, len(m.Answers))
	}
	m = parse(t, r.Query(context.Background(), mkQuery(t, "big.example.", dnsmessage.TypeTXT, true)))
	if m.Truncated || len(m.Answers) != 8 {
		t.Fatalf("EDNS client: tc=%v answers=%d", m.Truncated, len(m.Answers))
	}
}

func TestForwardAllDead(t *testing.T) {
	r := testResolver(deadUpstream(t))
	m := parse(t, r.Query(context.Background(), mkQuery(t, "example.com.", dnsmessage.TypeA, false)))
	if m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v, want SERVFAIL", m.RCode)
	}
}

func TestReverseZones(t *testing.T) {
	z := ReverseZones(pool4)
	if len(z) != 64 || z[0] != "64.100.in-addr.arpa" || z[63] != "127.100.in-addr.arpa" {
		t.Errorf("v4 zones: %d %v ... %v", len(z), z[0], z[len(z)-1])
	}
	if z := ReverseZones(netip.MustParsePrefix("10.1.2.0/24")); !slices.Equal(z, []string{"2.1.10.in-addr.arpa"}) {
		t.Errorf("/24: %v", z)
	}
	if z := ReverseZones(netip.MustParsePrefix("10.1.2.3/32")); !slices.Equal(z, []string{"2.1.10.in-addr.arpa"}) {
		t.Errorf("/32: %v", z)
	}
	if z := ReverseZones(pool6); !slices.Equal(z, []string{"0.e.1.a.e.0.c.7.c.7.d.f.ip6.arpa"}) {
		t.Errorf("v6 zones: %v", z)
	}
	for _, a := range alice {
		var name string
		if a.Is4() {
			b := a.As4()
			name = netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}).String() + ".in-addr.arpa."
		} else {
			name = reverse6(a)
		}
		if got, ok := parseReverse(name); !ok || got != a {
			t.Errorf("parseReverse(%s) = %v, %v", name, got, ok)
		}
	}
	for _, bad := range []string{"1.2.3.in-addr.arpa.", "01.2.3.4.in-addr.arpa.", "256.2.3.4.in-addr.arpa.", "a.b.ip6.arpa."} {
		if _, ok := parseReverse(bad); ok {
			t.Errorf("parseReverse(%s) should fail", bad)
		}
	}
}

func TestResolvConf(t *testing.T) {
	in := "# comment\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nsearch lan example.com\noptions edns0 trust-ad\n"
	rc := parseResolvConf([]byte(in))
	if !slices.Equal(rc.Nameservers, []netip.Addr{netip.MustParseAddr("192.168.1.1")}) ||
		!slices.Equal(rc.Search, []string{"lan", "example.com"}) || !slices.Equal(rc.Other, []string{"options edns0 trust-ad"}) {
		t.Fatalf("parsed %+v", rc)
	}
	out := string(rc.marshal("# hdr\n"))
	if out != "# hdr\nnameserver 192.168.1.1\nsearch lan example.com\noptions edns0 trust-ad\n" {
		t.Fatalf("marshal: %q", out)
	}
}
