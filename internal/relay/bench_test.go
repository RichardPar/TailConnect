package relay

import (
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"tailconnect/internal/key"
)

// BenchmarkForward measures relay throughput for WireGuard-sized packets
// between two clients over loopback, with a bounded number in flight so the
// relay's drop-when-slow policy doesn't skew the result.
func BenchmarkForward(b *testing.B) {
	for _, size := range []int{128, 1280} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) { benchForward(b, size, nil) })
	}
}

// BenchmarkForwardWithPolicy adds a per-packet allow check, as the relay
// built into tc-control has.
func BenchmarkForwardWithPolicy(b *testing.B) {
	benchForward(b, 1280, func(src, dst key.NodePublic) bool { return true })
}

func benchForward(b *testing.B, size int, allow AllowFunc) {
	s := NewServer(key.NewPrivate[key.RelayKind](), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetAllow(allow)
	ts := httptest.NewServer(s)
	defer func() { s.Close(); ts.Close() }()
	url := ts.URL + "/relay"

	const window = 64
	credit := make(chan struct{}, window)
	ka, kb := key.NewPrivate[key.NodeKind](), key.NewPrivate[key.NodeKind]()
	a, err := NewClient(ClientOptions{URL: url, NodeKey: ka, Recv: func(key.NodePublic, []byte) {}})
	if err != nil {
		b.Fatal(err)
	}
	defer a.Close()
	got := make(chan struct{}, window)
	bc, err := NewClient(ClientOptions{URL: url, NodeKey: kb, Recv: func(key.NodePublic, []byte) { got <- struct{}{} }})
	if err != nil {
		b.Fatal(err)
	}
	defer bc.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !a.Connected() || !bc.Connected() {
		if time.Now().After(deadline) {
			b.Fatal("clients never connected")
		}
		time.Sleep(5 * time.Millisecond)
	}

	pkt := make([]byte, size)
	dst := kb.Public()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	received := 0
	for sent := 0; sent < b.N; sent++ {
		select {
		case credit <- struct{}{}:
		case <-got: // free a slot
			received++
			<-credit
			credit <- struct{}{}
		}
		if err := a.Send(dst, pkt); err != nil {
			b.Fatal(err)
		}
	}
	timeout := time.After(10 * time.Second)
	for received < b.N {
		select {
		case <-got:
			received++
		case <-timeout:
			b.Fatalf("only %d of %d packets arrived", received, b.N)
		}
	}
}
