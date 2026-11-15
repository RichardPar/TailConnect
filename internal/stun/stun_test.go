package stun

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	for _, s := range []string{"198.51.100.7:41641", "[2001:db8::1]:3478"} {
		ap := netip.MustParseAddrPort(s)
		tx := NewTxID()
		gotTx, got, err := ParseResponse(Response(tx, ap))
		if err != nil || gotTx != tx || got != ap {
			t.Errorf("%s: got %v %v %v", s, gotTx == tx, got, err)
		}
	}
}

func TestClassify(t *testing.T) {
	tx := NewTxID()
	req, resp := Request(tx), Response(tx, netip.MustParseAddrPort("1.2.3.4:5"))
	if !IsRequest(req) || IsResponse(req) || !IsResponse(resp) || IsRequest(resp) {
		t.Fatal("misclassified")
	}
	// A WireGuard transport packet must never look like STUN.
	wg := make([]byte, 64)
	wg[0] = 4
	if IsRequest(wg) || IsResponse(wg) {
		t.Fatal("WireGuard packet classified as STUN")
	}
	if _, _, err := ParseResponse(resp[:24]); err == nil {
		t.Fatal("truncated response accepted")
	}
}

// RFC 5769 section 2.2 sample IPv4 response (XOR-MAPPED-ADDRESS 192.0.2.1:32853).
func TestRFC5769Vector(t *testing.T) {
	b := []byte{
		0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
		0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
		0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
		0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
		0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
	}
	_, ap, err := ParseResponse(b)
	if err != nil || ap != netip.MustParseAddrPort("192.0.2.1:32853") {
		t.Fatalf("got %v %v", ap, err)
	}
}

func TestServe(t *testing.T) {
	srv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go Serve(srv)
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tx := NewTxID()
	c.WriteTo(Request(tx), srv.LocalAddr())
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	gotTx, ap, err := ParseResponse(buf[:n])
	if err != nil || gotTx != tx || ap != c.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("got %v %v (want %v)", ap, err, c.LocalAddr())
	}
}
