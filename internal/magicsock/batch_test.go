package magicsock

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"tailconnect/internal/key"
)

// A burst of packets read in batches arrives complete, in order, intact,
// whatever the batch boundaries.
func TestBatchedReceiveBurst(t *testing.T) {
	c := New(Options{PrivateKey: key.NewPrivate[key.NodeKind]()})
	defer c.Close()
	fns, port, err := c.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	recv := fns[0] // IPv4 socket
	src, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)

	const total = 1000
	go func() {
		for i := 0; i < total; i++ {
			// A WireGuard transport packet (type 4) carrying its sequence number.
			p := make([]byte, 32+i%200)
			p[0] = 4
			binary.LittleEndian.PutUint32(p[16:], uint32(i))
			for j := 20; j < len(p); j++ {
				p[j] = byte(i)
			}
			src.WriteToUDPAddrPort(p, dst)
			if i%50 == 0 {
				time.Sleep(time.Millisecond) // vary the batch boundaries
			}
		}
	}()

	bufs := make([][]byte, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, batchSize)
	eps := make([]conn.Endpoint, batchSize)
	next := 0
	// Unblock the reader if packets go missing at the end.
	stop := time.AfterFunc(10*time.Second, func() { c.Close() })
	defer stop.Stop()
	for next < total {
		n, err := recv(bufs, sizes, eps)
		if err != nil {
			t.Fatalf("after %d packets: %v", next, err)
		}
		for k := 0; k < n; k++ {
			p := bufs[k][:sizes[k]]
			seq := int(binary.LittleEndian.Uint32(p[16:]))
			if seq < next {
				t.Fatalf("packet %d after %d", seq, next)
			}
			if seq != next {
				t.Fatalf("lost packets %d..%d", next, seq-1)
			}
			if len(p) != 32+seq%200 || p[len(p)-1] != byte(seq) {
				t.Fatalf("packet %d corrupt: len %d", seq, len(p))
			}
			if eps[k] == nil || eps[k].DstToString() != src.LocalAddr().String() {
				t.Fatalf("packet %d: endpoint %v", seq, eps[k])
			}
			next = seq + 1
		}
	}
	if next != total {
		t.Fatalf("received up to %d of %d", next, total)
	}
}
