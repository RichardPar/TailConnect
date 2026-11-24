package dns

import (
	"encoding/binary"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN delivers queued packets from Read and records Writes.
type fakeTUN struct {
	in      chan []byte
	written chan []byte
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 16), written: make(chan []byte, 16)}
}

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return 1280, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return 4 }

// Read returns every queued packet (at least one, blocking for the first).
func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for n < len(bufs) {
		var p []byte
		if n == 0 {
			p = <-f.in
		} else {
			select {
			case p = <-f.in:
			default:
				return n, nil
			}
		}
		sizes[n] = copy(bufs[n][offset:], p)
		n++
	}
	return n, nil
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written <- slices.Clone(b[offset:])
	}
	return len(bufs), nil
}

var (
	res4 = netip.MustParseAddr("100.100.100.100")
	res6 = netip.MustParseAddr("fd7c:7c0e:a1e0::6464:6464")
)

func readBatch(t *testing.T, d tun.Device) [][]byte {
	t.Helper()
	bufs := make([][]byte, 4)
	for i := range bufs {
		bufs[i] = make([]byte, 16+1500)
	}
	sizes := make([]int, 4)
	n, err := d.Read(bufs, sizes, 16)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for i := 0; i < n; i++ {
		out = append(out, bufs[i][16:16+sizes[i]])
	}
	return out
}

func validChecksums(t *testing.T, pkt []byte) (src, dst netip.Addr, payload []byte) {
	t.Helper()
	var pseudo uint32
	var udp []byte
	if pkt[0]>>4 == 4 {
		if fold(sum16(pkt[:20], 0)) != 0xffff {
			t.Fatal("bad IPv4 header checksum")
		}
		src, dst = netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20]))
		udp = pkt[20:]
	} else {
		src, dst = netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
		udp = pkt[40:]
	}
	pseudo = sum16(src.AsSlice(), 0)
	pseudo = sum16(dst.AsSlice(), pseudo) + 17 + uint32(len(udp))
	if fold(sum16(udp, pseudo)) != 0xffff {
		t.Fatal("bad UDP checksum")
	}
	if binary.BigEndian.Uint16(udp[0:2]) != 53 || binary.BigEndian.Uint16(udp[2:4]) != 40000 {
		t.Fatalf("ports %d→%d", binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]))
	}
	return src, dst, udp[8:]
}

func TestTUNIntercept(t *testing.T) {
	ft := newFakeTUN()
	w := WrapTUN(ft, testResolver(), res4, res6, t.Logf)
	defer w.Close()

	client4, client6 := alice[0], alice[1]
	other := udpPacket(client4, netip.MustParseAddr("100.64.0.2"), 40000, 53, []byte("not for us"))
	q := mkQuery(t, "alice.tc.internal.", dnsmessage.TypeA, false)

	// Disabled: everything passes through.
	ft.in <- udpPacket(client4, res4, 40000, 53, q)
	if got := readBatch(t, w); len(got) != 1 {
		t.Fatalf("disabled: got %d packets", len(got))
	}

	w.SetEnabled(true)
	for _, c := range []struct{ client, resolver netip.Addr }{{client4, res4}, {client6, res6}} {
		ft.in <- udpPacket(c.client, c.resolver, 40000, 53, q)
		ft.in <- other
		got := readBatch(t, w)
		if len(got) != 1 || !slices.Equal(got[0], other) {
			t.Fatalf("%v: want only the non-DNS packet passed through, got %d packets", c.resolver, len(got))
		}
		select {
		case resp := <-ft.written:
			src, dst, payload := validChecksums(t, resp)
			if src != c.resolver || dst != c.client {
				t.Fatalf("response %v → %v", src, dst)
			}
			if a := answerAddrs(parse(t, payload)); !slices.Equal(a, []string{"100.64.0.1"}) {
				t.Fatalf("answers %v", a)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%v: no response written", c.resolver)
		}
	}

	// A batch of only DNS queries must not return an empty read.
	ft.in <- udpPacket(client4, res4, 40000, 53, q)
	ft.in <- other
	if got := readBatch(t, w); len(got) != 1 {
		t.Fatalf("got %d packets", len(got))
	}
	<-ft.written
}

// loopTUN returns the same packet from every Read and discards writes.
type loopTUN struct{ pkt []byte }

func (l *loopTUN) File() *os.File           { return nil }
func (l *loopTUN) MTU() (int, error)        { return 1280, nil }
func (l *loopTUN) Name() (string, error)    { return "loop", nil }
func (l *loopTUN) Events() <-chan tun.Event { return nil }
func (l *loopTUN) Close() error             { return nil }
func (l *loopTUN) BatchSize() int           { return 1 }
func (l *loopTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	sizes[0] = copy(bufs[0][offset:], l.pkt)
	return 1, nil
}
func (l *loopTUN) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

// closingLoop returns pkt from every Read until closed.
type closingLoop struct {
	loopTUN
	closed atomic.Bool
}

func (l *closingLoop) Close() error { l.closed.Store(true); return nil }
func (l *closingLoop) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if l.closed.Load() {
		return 0, os.ErrClosed
	}
	return l.loopTUN.Read(bufs, sizes, offset)
}

// Close while queries keep arriving must not race with Read starting new
// work (WaitGroup misuse panics, writes to a closed TCP stack).
func TestCloseDuringQueries(t *testing.T) {
	q := mkQuery(t, "alice.tc.internal.", dnsmessage.TypeA, false)
	for range 50 {
		dev := &closingLoop{loopTUN: loopTUN{pkt: udpPacket(alice[0], res4, 40000, 53, q)}}
		w := WrapTUN(dev, testResolver(), res4, res6, nil)
		w.SetEnabled(true)
		done := make(chan struct{})
		go func() {
			defer close(done)
			bufs, sizes := [][]byte{make([]byte, 2000)}, []int{0}
			for {
				if _, err := w.Read(bufs, sizes, 0); err != nil {
					return
				}
			}
		}()
		time.Sleep(time.Millisecond)
		w.Close()
		<-done
	}
}

// With an exit node in use, queries for names outside MagicDNS are
// readdressed to the exit node's DNS (and go on into the tunnel), MagicDNS
// names are still answered here, and the exit node's answers come back
// readdressed from MagicDNS.
func TestTUNExitDNS(t *testing.T) {
	ft := newFakeTUN()
	w := WrapTUN(ft, testResolver(), res4, res6, t.Logf)
	defer w.Close()
	w.SetEnabled(true)
	exit4, exit6 := netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr("fd7c:7c0e:a1e0::6440:9")
	w.SetExitDNS(exit4, exit6)
	client4, client6 := alice[0], alice[1]

	outside := mkQuery(t, "example.com.", dnsmessage.TypeA, false)
	for _, c := range []struct{ client, resolver, exit netip.Addr }{{client4, res4, exit4}, {client6, res6, exit6}} {
		ft.in <- udpPacket(c.client, c.resolver, 40000, 53, outside)
		got := readBatch(t, w)
		if len(got) != 1 {
			t.Fatalf("%v: got %d packets, want the query passed on", c.resolver, len(got))
		}
		u, ok := parseUDP(got[0])
		if !ok || u.src != c.client || u.dst != c.exit || u.srcPort != 40000 || u.dstPort != ExitPort || !slices.Equal(u.payload, outside) {
			t.Fatalf("readdressed query: %+v", u)
		}
		checkUDPChecksum(t, got[0])
		select {
		case p := <-ft.written:
			t.Fatalf("answered locally instead: %x", p)
		default:
		}

		// The exit node's answer, on its way to the host.
		answer := slices.Clone(outside)
		answer[2] |= 0x80
		bufs := [][]byte{append(make([]byte, 16), udpPacket(c.exit, c.client, ExitPort, 40000, answer)...)}
		if _, err := w.Write(bufs, 16); err != nil {
			t.Fatal(err)
		}
		src, dst, payload := validChecksums(t, <-ft.written)
		if src != c.resolver || dst != c.client || !slices.Equal(payload, answer) {
			t.Fatalf("answer %v → %v", src, dst)
		}
	}

	// MagicDNS names are still answered here.
	ft.in <- udpPacket(client4, res4, 40000, 53, mkQuery(t, "alice.tc.internal.", dnsmessage.TypeA, false))
	ft.in <- udpPacket(client4, netip.MustParseAddr("100.64.0.2"), 40000, 53, []byte("not for us"))
	if got := readBatch(t, w); len(got) != 1 {
		t.Fatalf("got %d packets", len(got))
	}
	select {
	case resp := <-ft.written:
		if src, _, _ := validChecksums(t, resp); src != res4 {
			t.Fatalf("MagicDNS answer from %v", src)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("MagicDNS name not answered locally")
	}

	// An answer from the exit node's DNS port to a query that wasn't
	// readdressed (sent there directly) is left alone, as is a second copy.
	stray := udpPacket(exit4, client4, ExitPort, 40000, outside)
	for range 2 {
		if _, err := w.Write([][]byte{append(make([]byte, 16), stray...)}, 16); err != nil {
			t.Fatal(err)
		}
		if got := <-ft.written; !slices.Equal(got, stray) {
			t.Fatal("answer to a query that wasn't readdressed was changed")
		}
	}

	// Other traffic from the exit node's address is left alone.
	other := udpPacket(exit4, client4, 5000, 40000, []byte("hello"))
	if _, err := w.Write([][]byte{append(make([]byte, 16), other...)}, 16); err != nil {
		t.Fatal(err)
	}
	if got := <-ft.written; !slices.Equal(got, other) {
		t.Fatal("unrelated packet from the exit node changed")
	}

	// Exit node off: queries are answered here again.
	w.SetExitDNS(netip.Addr{}, netip.Addr{})
	ft.in <- udpPacket(client4, res4, 40000, 53, outside)
	ft.in <- other
	if got := readBatch(t, w); len(got) != 1 || !slices.Equal(got[0], other) {
		t.Fatalf("exit off: %d packets", len(got))
	}
}

func checkUDPChecksum(t *testing.T, pkt []byte) {
	t.Helper()
	u, _ := parseUDP(pkt)
	var udp []byte
	if pkt[0]>>4 == 4 {
		if fold(sum16(pkt[:20], 0)) != 0xffff {
			t.Fatal("bad IPv4 header checksum")
		}
		udp = pkt[20:]
	} else {
		udp = pkt[40:]
	}
	sum := sum16(u.src.AsSlice(), 0)
	sum = sum16(u.dst.AsSlice(), sum) + 17 + uint32(len(udp))
	if fold(sum16(udp, sum)) != 0xffff {
		t.Fatal("bad UDP checksum")
	}
}
