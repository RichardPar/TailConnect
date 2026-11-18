//go:build linux

package androidbridge

import (
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN delivers packets from in to Read and records writes in out.
type fakeTUN struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
}

func newFake() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 4), out: make(chan []byte, 4), closed: make(chan struct{})}
}

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-f.in:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-f.closed:
		return 0, os.ErrClosed
	}
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-f.closed:
		return 0, os.ErrClosed
	default:
	}
	for _, b := range bufs {
		f.out <- append([]byte(nil), b[offset:]...)
	}
	return len(bufs), nil
}

func (f *fakeTUN) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (*fakeTUN) File() *os.File           { return nil }
func (*fakeTUN) MTU() (int, error)        { return 1280, nil }
func (*fakeTUN) Name() (string, error)    { return "fake", nil }
func (*fakeTUN) Events() <-chan tun.Event { return nil }
func (*fakeTUN) BatchSize() int           { return 1 }

func TestSwapTUN(t *testing.T) {
	a, b := newFake(), newFake()
	s := NewSwapTUN(a)
	read := make(chan string, 4)
	errs := make(chan error, 1)
	go func() {
		bufs, sizes := [][]byte{make([]byte, 100)}, []int{0}
		for {
			n, err := s.Read(bufs, sizes, 0)
			if err != nil {
				errs <- err
				return
			}
			if n == 1 {
				read <- string(bufs[0][:sizes[0]])
			}
		}
	}()
	a.in <- []byte("one")
	if got := <-read; got != "one" {
		t.Fatalf("read %q", got)
	}
	// The reader is blocked on a; swapping closes a and moves it to b
	// without WireGuard seeing an error.
	s.Swap(b)
	b.in <- []byte("two")
	select {
	case got := <-read:
		if got != "two" {
			t.Fatalf("read after swap %q", got)
		}
	case err := <-errs:
		t.Fatalf("read failed across the swap: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("read stuck after swap")
	}
	if _, err := s.Write([][]byte{[]byte("out")}, 0); err != nil {
		t.Fatal(err)
	}
	if got := string(<-b.out); got != "out" {
		t.Fatalf("write went to %q", got)
	}
	// Closing ends the reader with an error, and closes the events channel.
	s.Close()
	select {
	case <-errs:
	case <-time.After(2 * time.Second):
		t.Fatal("read not ended by Close")
	}
	if _, ok := <-s.Events(); ok {
		t.Fatal("events channel open after Close")
	}
	// A swap after Close closes the new device instead.
	c := newFake()
	s.Swap(c)
	select {
	case <-c.closed:
	default:
		t.Fatal("device swapped in after Close left open")
	}
}

func TestExcludePrefixes(t *testing.T) {
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	pp := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	if got := ExcludePrefixes(all, nil); !slices.Equal(got, all) {
		t.Fatalf("no exclusions: %v", got)
	}
	got := ExcludePrefixes(pp("0.0.0.0/0"), pp("192.168.10.183/24"))
	// Everything but 192.168.10.0/24: 24 prefixes, none overlapping it,
	// covering 2^32 - 256 addresses.
	var total uint64
	for _, p := range got {
		if p.Overlaps(netip.MustParsePrefix("192.168.10.0/24")) {
			t.Fatalf("%v overlaps the excluded network", p)
		}
		total += 1 << (32 - p.Bits())
	}
	if len(got) != 24 || total != 1<<32-256 {
		t.Fatalf("%d prefixes covering %d addresses: %v", len(got), total, got)
	}
	// Each family is cut only by its own exclusions; the tunnel's range
	// stays routed.
	got = ExcludePrefixes(all, pp("10.0.0.0/8", "fe80::/10"))
	for _, a := range []string{"100.64.0.5", "1.1.1.1", "2001:db8::1"} {
		if !slices.ContainsFunc(got, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(a)) }) {
			t.Errorf("%s not routed: %v", a, got)
		}
	}
	for _, a := range []string{"10.1.2.3", "fe80::1"} {
		if slices.ContainsFunc(got, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(a)) }) {
			t.Errorf("%s routed although excluded", a)
		}
	}
}
