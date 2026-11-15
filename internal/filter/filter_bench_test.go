package filter

import (
	"net/netip"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// nullTUN discards writes and returns the same packet from every Read, so
// benchmarks measure the filter, not the fake device.
type nullTUN struct{ pkt []byte }

func (n *nullTUN) File() *os.File           { return nil }
func (n *nullTUN) MTU() (int, error)        { return 1280, nil }
func (n *nullTUN) Name() (string, error)    { return "null", nil }
func (n *nullTUN) Events() <-chan tun.Event { return nil }
func (n *nullTUN) Close() error             { return nil }
func (n *nullTUN) BatchSize() int           { return 1 }
func (n *nullTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	sizes[0] = copy(bufs[0][offset:], n.pkt)
	return 1, nil
}
func (n *nullTUN) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

// fullSize pads a packet to a typical tunnel MTU-sized payload.
func fullSize(p []byte) []byte {
	out := make([]byte, 1280)
	copy(out, p)
	return out
}

func benchWrite(b *testing.B, w *TUN, pkt []byte) {
	buf := make([]byte, 16+len(pkt))
	copy(buf[16:], pkt)
	bufs := [][]byte{buf}
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(bufs, 16); err != nil {
			b.Fatal(err)
		}
	}
}

// No shares at all: the common case must cost (almost) nothing.
func BenchmarkWriteNoRestrictions(b *testing.B) {
	w := Wrap(&nullTUN{})
	benchWrite(b, w, fullSize(tcp(friend, me, 445, 50000, ack)))
}

// Shares exist, packet from an unrestricted (same-account) peer.
func BenchmarkWriteUnrestrictedPeer(b *testing.B) {
	w := Wrap(&nullTUN{})
	w.SetRestricted([]netip.Addr{shared, shrd6})
	benchWrite(b, w, fullSize(tcp(friend, me, 445, 50000, ack)))
}

// A reply from a shared machine on a flow we opened: lookup and refresh.
func BenchmarkWriteRestrictedReply(b *testing.B) {
	w := Wrap(&nullTUN{pkt: tcp(me, shared, 50000, 445, syn)})
	w.SetRestricted([]netip.Addr{shared, shrd6})
	readOnce(b, w)
	benchWrite(b, w, fullSize(tcp(shared, me, 445, 50000, ack)))
}

// A connection attempt from a shared machine: parse and drop.
func BenchmarkWriteRestrictedDrop(b *testing.B) {
	w := Wrap(&nullTUN{})
	w.SetRestricted([]netip.Addr{shared, shrd6})
	benchWrite(b, w, fullSize(tcp(shared, me, 40000, 22, syn)))
}

func readOnce(b *testing.B, w *TUN) {
	bufs := [][]byte{make([]byte, 16+1500)}
	sizes := []int{0}
	if _, err := w.Read(bufs, sizes, 16); err != nil {
		b.Fatal(err)
	}
}

// Sending to a shared machine: parse and track the flow.
func BenchmarkReadTrackFlow(b *testing.B) {
	w := Wrap(&nullTUN{pkt: fullSize(tcp(me, shared, 50000, 445, ack))})
	w.SetRestricted([]netip.Addr{shared, shrd6})
	bufs := [][]byte{make([]byte, 16+1500)}
	sizes := []int{0}
	b.SetBytes(1280)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Read(bufs, sizes, 16); err != nil {
			b.Fatal(err)
		}
	}
}
