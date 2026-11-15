package daemon

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailconnect/internal/localapi"
)

// benchPair brings up two machines of one account and returns them with
// their addresses. relayOnly makes the direct path impossible.
func benchPair(b *testing.B, relayOnly bool) (*testNode, *testNode, netip.Addr) {
	b.Helper()
	// No STUN in relay-only mode: it would reveal the loopback path.
	_, url, key := newControl(b, relayOnly)
	eps := loopbackEndpoints
	if relayOnly {
		eps = deadEndpoints
	}
	a, c := newTestNodeEP(b, "a", eps), newTestNodeEP(b, "c", eps)
	for _, n := range []struct {
		n    *testNode
		host string
	}{{a, "alpha"}, {c, "gamma"}} {
		if err := n.n.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: key, Hostname: n.host}); err != nil {
			b.Fatal(err)
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for !(running(a, 1)() && running(c, 1)()) {
		if time.Now().After(deadline) {
			b.Fatal("machines never saw each other")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return a, c, c.d.Status().Self.Addresses[0].Addr()
}

// sink accepts TCP connections on n's address and discards what it reads,
// echoing one byte per message for the latency benchmark.
func sink(b *testing.B, n *testNode, ip netip.Addr, echo bool) {
	ln, err := n.tnet().ListenTCPAddrPort(netip.AddrPortFrom(ip, 9000))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if !echo {
					io.Copy(io.Discard, conn)
					return
				}
				buf := make([]byte, 64)
				for {
					k, err := conn.Read(buf)
					if err != nil {
						return
					}
					conn.Write(buf[:k])
				}
			}(conn)
		}
	}()
}

func dial(b *testing.B, n *testNode, ip netip.Addr) net.Conn {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := n.tnet().DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, 9000))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { conn.Close() })
	return conn
}

// BenchmarkThroughput streams TCP through the tunnel (WireGuard encryption,
// magicsock, the packet filter, and for /relay the relay).
func BenchmarkThroughput(b *testing.B) {
	for _, mode := range []struct {
		name  string
		relay bool
	}{{"direct", false}, {"relay", true}} {
		b.Run(mode.name, func(b *testing.B) {
			a, c, ipC := benchPair(b, mode.relay)
			sink(b, c, ipC, false)
			conn := dial(b, a, ipC)
			chunk := make([]byte, 64<<10)
			// Warm up: handshake, path discovery.
			conn.Write(chunk)
			if !mode.relay {
				waitDirect(b, a)
			}
			b.SetBytes(int64(len(chunk)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := conn.Write(chunk); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkRoundTrip measures request/response latency through the tunnel.
func BenchmarkRoundTrip(b *testing.B) {
	for _, mode := range []struct {
		name  string
		relay bool
	}{{"direct", false}, {"relay", true}} {
		b.Run(mode.name, func(b *testing.B) {
			a, c, ipC := benchPair(b, mode.relay)
			sink(b, c, ipC, true)
			conn := dial(b, a, ipC)
			msg, buf := []byte("ping"), make([]byte, 64)
			if !mode.relay {
				waitDirect(b, a)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := conn.Write(msg); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(conn, buf[:len(msg)]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func waitDirect(b *testing.B, a *testNode) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		ps := a.d.Status().Peers
		if len(ps) == 1 && ps[0].CurrentEndpoint.IsValid() {
			return
		}
		if time.Now().After(deadline) {
			b.Fatal("no direct path")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
