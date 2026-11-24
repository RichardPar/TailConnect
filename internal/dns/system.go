package dns

import (
	"net/netip"
	"os"
	"slices"
)

// SystemResolvers returns the host's DNS servers from /etc/resolv.conf.
// When that names only a local stub (systemd-resolved's 127.0.0.53), the
// servers behind it come from resolved's own list instead, if there is one.
func SystemResolvers() []netip.Addr {
	stub := func(a netip.Addr) bool { return a.IsLoopback() }
	read := func(p string) []netip.Addr {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		return parseResolvConf(b).Nameservers
	}
	ns := read("/etc/resolv.conf")
	if len(ns) > 0 && !slices.ContainsFunc(ns, func(a netip.Addr) bool { return !stub(a) }) {
		if up := read("/run/systemd/resolve/resolv.conf"); len(up) > 0 {
			return up
		}
	}
	return ns
}
