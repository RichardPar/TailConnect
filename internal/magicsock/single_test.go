package magicsock

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
)

// singleConn is what Windows uses; it must behave like a one-packet batch.
func TestSingleConn(t *testing.T) {
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ca, cb := &singleConn{pc: a}, &singleConn{pc: b}
	to := b.LocalAddr().(*net.UDPAddr).AddrPort()

	if err := writeBatch(a, ca, [][]byte{[]byte("one"), []byte("two")}, to); err != nil {
		t.Fatal(err)
	}
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	for _, want := range []string{"one", "two"} {
		buf := make([]byte, 64)
		ms := make([]ipv6.Message, 4)
		ms[0].Buffers = [][]byte{buf}
		n, err := cb.ReadBatch(ms, 0)
		if err != nil || n != 1 {
			t.Fatalf("ReadBatch = %d, %v", n, err)
		}
		if got := string(buf[:ms[0].N]); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
		from := unmap(ms[0].Addr.(*net.UDPAddr).AddrPort())
		if want := a.LocalAddr().(*net.UDPAddr).AddrPort(); from != netip.AddrPortFrom(want.Addr(), want.Port()) {
			t.Errorf("from %v, want %v", from, want)
		}
	}
}
