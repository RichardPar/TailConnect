package dns

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The exit node's DNS server answers the machines allowed to use it (over
// UDP and TCP) by forwarding, and ignores everyone else.
func TestExitServer(t *testing.T) {
	r := NewResolver(t.Logf)
	// UDP queries are answered by the first, TCP ones by the second.
	r.SetConfig(Config{Upstream: []netip.AddrPort{fakeUpstream(t, 1), fakeUpstreamTCP(t, 1)}})
	var allowed atomic.Bool
	allowed.Store(true)
	s, err := ListenExit(netip.MustParseAddr("127.0.0.1"), r, func(a netip.Addr) bool {
		return a == netip.MustParseAddr("127.0.0.1") && allowed.Load()
	}, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := mkQuery(t, "example.com.", dnsmessage.TypeTXT, false)

	ask := func() ([]byte, error) {
		c, err := net.Dial("udp", s.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write(q)
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		return buf[:n], err
	}
	resp, err := ask()
	if err != nil {
		t.Fatalf("UDP: %v", err)
	}
	if m := parse(t, resp); len(m.Answers) != 1 {
		t.Fatalf("UDP: %d answers", len(m.Answers))
	}

	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeTCPMsg(c, q); err != nil {
		t.Fatal(err)
	}
	tresp, err := readTCPMsg(c)
	c.Close()
	if err != nil {
		t.Fatalf("TCP: %v", err)
	}
	if m := parse(t, tresp); len(m.Answers) != 1 {
		t.Fatalf("TCP: %d answers", len(m.Answers))
	}

	allowed.Store(false)
	if _, err := ask(); err == nil {
		t.Fatal("answered a machine that may not use this exit node")
	}
}
