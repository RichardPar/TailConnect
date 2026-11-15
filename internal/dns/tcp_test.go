package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// fakeUpstreamTCP answers every query over TCP with n 100-byte TXT records.
func fakeUpstreamTCP(t *testing.T, n int) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				q, err := readTCPMsg(c)
				if err != nil {
					return
				}
				var p dnsmessage.Parser
				h, _ := p.Start(q)
				qq, _ := p.Question()
				b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
				b.StartQuestions()
				b.Question(qq)
				b.StartAnswers()
				for i := 0; i < n; i++ {
					b.TXTResource(dnsmessage.ResourceHeader{Name: qq.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
						dnsmessage.TXTResource{TXT: []string{strings.Repeat("x", 100)}})
				}
				out, _ := b.Finish()
				writeTCPMsg(c, out)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// Over TCP, a large forwarded answer arrives whole (over UDP it is truncated).
func TestQueryTCPForwardsOverTCP(t *testing.T) {
	r := testResolver(fakeUpstreamTCP(t, 200)) // ~22 KB
	m := parse(t, r.QueryTCP(context.Background(), mkQuery(t, "big.example.", dnsmessage.TypeTXT, false)))
	if m.Truncated || len(m.Answers) != 200 {
		t.Fatalf("tc=%v answers=%d", m.Truncated, len(m.Answers))
	}
}

// A real TCP client on the host (here another in-process stack) queries
// the resolver address over TCP: several queries on one connection, local
// and a large forwarded one.
func TestTUNInterceptTCP(t *testing.T) {
	hostAddr := netip.MustParseAddr("100.64.0.1")
	hostDev, hostNet, err := netstack.CreateNetTUN([]netip.Addr{hostAddr}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	resolver := netip.MustParseAddr("100.100.100.100")
	w := WrapTUN(hostDev, testResolver(fakeUpstreamTCP(t, 200)), resolver, netip.Addr{}, t.Logf)
	w.SetEnabled(true)
	defer w.Close()
	// Drain what the host sends that isn't for the resolver (WireGuard's job).
	go func() {
		bufs, sizes := [][]byte{make([]byte, 16+65535)}, []int{0}
		for {
			if _, err := w.Read(bufs, sizes, 16); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := hostNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(resolver, 53))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	ask := func(name string, typ dnsmessage.Type) dnsmessage.Message {
		t.Helper()
		if err := writeTCPMsg(c, mkQuery(t, name, typ, false)); err != nil {
			t.Fatal(err)
		}
		b, err := readTCPMsg(c)
		if err != nil {
			t.Fatal(err)
		}
		return parse(t, b)
	}
	if m := ask("alice.tc.internal.", dnsmessage.TypeA); len(m.Answers) != 1 || answerAddrs(m)[0] != "100.64.0.1" {
		t.Fatalf("local answer over TCP: %+v", answerAddrs(m))
	}
	if m := ask("big.example.", dnsmessage.TypeTXT); m.Truncated || len(m.Answers) != 200 {
		t.Fatalf("forwarded answer over TCP: tc=%v answers=%d", m.Truncated, len(m.Answers))
	}

	// Other ports on the resolver address are refused, not left hanging.
	if _, err := hostNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(resolver, 80)); err == nil {
		t.Fatal("port 80 on the resolver accepted a connection")
	}
}
