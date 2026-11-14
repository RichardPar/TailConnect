// Package ipam allocates tunnel addresses for nodes.
//
// IPv4 addresses come from the CGNAT range 100.64.0.0/10. Each node's IPv6
// address is derived from its IPv4 address inside a ULA /48, so the pair is
// stable and only IPv4 needs tracking.
package ipam

import (
	"errors"
	"net/netip"
)

var (
	DefaultV4 = netip.MustParsePrefix("100.64.0.0/10")
	DefaultV6 = netip.MustParsePrefix("fd7c:7c0e:a1e0::/48")

	// reserved is never handed out: it holds MagicDNS (100.100.100.100) and
	// room for future in-tunnel services.
	reserved = netip.MustParsePrefix("100.100.100.0/24")
)

var ErrExhausted = errors.New("ipam: address pool exhausted")

type Allocator struct {
	v4 netip.Prefix
	v6 netip.Prefix
}

// New returns an allocator for the given pools. v4 must be IPv4 and v6 must be
// an IPv6 prefix of /96 or shorter.
func New(v4, v6 netip.Prefix) (*Allocator, error) {
	v4, v6 = v4.Masked(), v6.Masked()
	if !v4.Addr().Is4() || v4.Bits() > 30 {
		return nil, errors.New("ipam: v4 pool must be an IPv4 prefix of /30 or larger")
	}
	if !v6.Addr().Is6() || v6.Addr().Is4In6() || v6.Bits() > 96 {
		return nil, errors.New("ipam: v6 pool must be an IPv6 prefix of /96 or larger")
	}
	return &Allocator{v4: v4, v6: v6}, nil
}

// Default returns an allocator over DefaultV4 and DefaultV6.
func Default() *Allocator {
	a, err := New(DefaultV4, DefaultV6)
	if err != nil {
		panic(err)
	}
	return a
}

// Next returns the lowest free IPv4 address not in used, plus its derived IPv6.
// It skips the network and broadcast addresses and the reserved services range.
func (a *Allocator) Next(used map[netip.Addr]bool) (v4, v6 netip.Addr, err error) {
	first := a.v4.Addr().Next() // skip network address
	for ip := first; a.v4.Contains(ip); ip = ip.Next() {
		if !a.v4.Contains(ip.Next()) {
			break // last address is broadcast
		}
		if reserved.Contains(ip) || used[ip] {
			continue
		}
		return ip, a.V6For(ip), nil
	}
	return netip.Addr{}, netip.Addr{}, ErrExhausted
}

// V6For maps an IPv4 address into the v6 pool: the pool prefix followed by
// the four IPv4 bytes in the low 32 bits.
func (a *Allocator) V6For(v4 netip.Addr) netip.Addr {
	b := a.v6.Addr().As16()
	v := v4.As4()
	copy(b[12:], v[:])
	return netip.AddrFrom16(b)
}

// Contains reports whether ip belongs to one of the allocator's pools.
func (a *Allocator) Contains(ip netip.Addr) bool {
	return a.v4.Contains(ip) || a.v6.Contains(ip)
}
