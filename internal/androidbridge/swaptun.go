//go:build linux

package androidbridge

import (
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// SwapTUN is a tun.Device whose underlying device can be replaced while
// WireGuard uses it. Android can only change a VPN's routes by creating a
// new interface (VpnService.Builder.establish), which replaces the old one;
// this keeps the tunnel, its peers and sessions, across that.
//
// A read or write that fails because its device was swapped out is retried
// on the new one, so WireGuard never sees the old device close. Events
// (none: Android's interfaces are unmonitored) come from SwapTUN itself.
type SwapTUN struct {
	mu     sync.RWMutex
	dev    tun.Device
	gen    uint64 // incremented by each Swap
	closed bool
	events chan tun.Event
}

func NewSwapTUN(dev tun.Device) *SwapTUN {
	return &SwapTUN{dev: dev, events: make(chan tun.Event)}
}

func (s *SwapTUN) current() (tun.Device, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dev, s.gen
}

// swappedSince reports whether the device changed after generation gen
// (and SwapTUN isn't closed): an error from the old one should be retried.
func (s *SwapTUN) swappedSince(gen uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.closed && s.gen != gen
}

// Swap makes dev the device and closes the previous one.
func (s *SwapTUN) Swap(dev tun.Device) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		dev.Close()
		return
	}
	old := s.dev
	s.dev = dev
	s.gen++
	s.mu.Unlock()
	old.Close() // unblocks a Read on it, which then moves to dev
}

func (s *SwapTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		d, gen := s.current()
		n, err := d.Read(bufs, sizes, offset)
		if err != nil && n == 0 && s.swappedSince(gen) {
			continue
		}
		return n, err
	}
}

func (s *SwapTUN) Write(bufs [][]byte, offset int) (int, error) {
	d, gen := s.current()
	n, err := d.Write(bufs, offset)
	if err != nil && s.swappedSince(gen) {
		m, err := s.Write(bufs[n:], offset) // the rest, on the new device
		return n + m, err
	}
	return n, err
}

func (s *SwapTUN) File() *os.File {
	d, _ := s.current()
	return d.File()
}

func (s *SwapTUN) MTU() (int, error) {
	d, _ := s.current()
	return d.MTU()
}

func (s *SwapTUN) Name() (string, error) {
	d, _ := s.current()
	return d.Name()
}

func (s *SwapTUN) BatchSize() int {
	d, _ := s.current()
	return d.BatchSize()
}

func (s *SwapTUN) Events() <-chan tun.Event { return s.events }

func (s *SwapTUN) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	d := s.dev
	close(s.events)
	s.mu.Unlock()
	return d.Close()
}
