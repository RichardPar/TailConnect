package dns

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// benchResolver answers for n machines, like a server with n peers.
func benchResolver(n int) *Resolver {
	r := NewResolver(nil)
	hosts := map[string][]netip.Addr{}
	for i := 0; i < n; i++ {
		v4 := netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)})
		hosts[fmt.Sprintf("host%d.acme.tc.internal", i)] = []netip.Addr{v4}
	}
	r.SetConfig(Config{Domain: "tc.internal", Hosts: hosts, ReversePrefixes: []netip.Prefix{pool4, pool6}})
	return r
}

func benchQuery(b *testing.B, r *Resolver, q []byte) {
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r.Query(ctx, q) == nil {
			b.Fatal("no answer")
		}
	}
}

func BenchmarkResolverA(b *testing.B) {
	r := benchResolver(1000)
	benchQuery(b, r, mkQueryB(b, "host500.acme.tc.internal.", dnsmessage.TypeA))
}

func BenchmarkResolverNXDOMAIN(b *testing.B) {
	r := benchResolver(1000)
	benchQuery(b, r, mkQueryB(b, "nope.acme.tc.internal.", dnsmessage.TypeA))
}

func BenchmarkResolverPTR(b *testing.B) {
	r := benchResolver(1000)
	benchQuery(b, r, mkQueryB(b, "244.1.64.100.in-addr.arpa.", dnsmessage.TypePTR))
}

// SetConfig runs on every network map; with many peers it must stay cheap.
func BenchmarkResolverSetConfig1000(b *testing.B) {
	r := benchResolver(1000)
	cfg := r.cfg
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.SetConfig(cfg)
	}
}

// Ordinary (non-DNS) packets pass the interceptor: the per-packet tax of MagicDNS.
func BenchmarkTUNPassthrough(b *testing.B) {
	pkt := make([]byte, 1280)
	copy(pkt, udpPacket(alice[0], netip.MustParseAddr("100.64.0.2"), 40000, 443, nil))
	ft := &loopTUN{pkt: pkt}
	w := WrapTUN(ft, benchResolver(10), res4, res6, nil)
	w.SetEnabled(true)
	bufs := [][]byte{make([]byte, 16+1500)}
	sizes := []int{0}
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, _ := w.Read(bufs, sizes, 16); n != 1 {
			b.Fatal("packet lost")
		}
	}
}

func mkQueryB(b *testing.B, name string, typ dnsmessage.Type) []byte {
	bd := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	bd.StartQuestions()
	bd.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	q, err := bd.Finish()
	if err != nil {
		b.Fatal(err)
	}
	return q
}
