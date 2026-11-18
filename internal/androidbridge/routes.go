//go:build linux

package androidbridge

import (
	"net/netip"
	"slices"
)

// ExcludePrefixes returns prefixes covering everything in all except what
// excl covers: the routes for "send everything except these" on Android
// before API 33, which has no VpnService.Builder.excludeRoute. Each part of
// all is split in halves until no half partly overlaps an exclusion.
func ExcludePrefixes(all, excl []netip.Prefix) []netip.Prefix {
	var masked []netip.Prefix
	for _, e := range excl {
		if e.IsValid() {
			masked = append(masked, e.Masked())
		}
	}
	var out []netip.Prefix
	var walk func(p netip.Prefix)
	walk = func(p netip.Prefix) {
		overlap := false
		for _, e := range masked {
			if e.Addr().Is4() != p.Addr().Is4() || !e.Overlaps(p) {
				continue
			}
			if e.Bits() <= p.Bits() {
				return // p is inside an exclusion
			}
			overlap = true
		}
		if !overlap {
			out = append(out, p)
			return
		}
		lo, hi := halves(p)
		walk(lo)
		walk(hi)
	}
	for _, p := range all {
		walk(p.Masked())
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}

// halves splits p into its two halves (p must be shorter than a host route).
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	b := p.Addr().AsSlice()
	i := p.Bits() / 8
	b[i] |= 0x80 >> (p.Bits() % 8)
	hiAddr, _ := netip.AddrFromSlice(b)
	return lo, netip.PrefixFrom(hiAddr, bits)
}
