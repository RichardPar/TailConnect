//go:build linux && !android

package engine

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// rtProto tags routes installed by tcd so stale ones can be found and removed
// without touching routes added by the kernel or the administrator.
const rtProto = netlink.RouteProtocol(124)

type linuxRouter struct {
	link   netlink.Link
	logf   func(string, ...any)
	v6Fail bool // IPv6 is disabled on this host; skip v6 config
	fwd    forwarder
}

// NewOSRouter configures addresses and routes on the named interface via netlink.
func NewOSRouter(ifname string, logf func(string, ...any)) (Router, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("router: find %s: %w", ifname, err)
	}
	r := &linuxRouter{link: link, logf: logf, fwd: forwarder{ifname: ifname, logf: logf, eg: egress{tun: ifname, logf: logf},
		// TC_EXIT_IPTABLES=1: NAT and forwarding with iptables even where
		// nftables works (for tests, or a kernel whose nftables misbehaves).
		nftOff: os.Getenv("TC_EXIT_IPTABLES") == "1"}}
	if err := r.clearExitRoutes(); err != nil { // left by a tcd that crashed
		logf("router: %v", err)
	}
	return r, nil
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func fromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones), true
}

func (r *linuxRouter) Set(cfg RouterConfig) error {
	if err := netlink.LinkSetUp(r.link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}

	// Addresses.
	want := map[netip.Prefix]bool{}
	var src4, src6 netip.Addr
	for _, p := range cfg.LocalAddrs {
		if p.Addr().Is6() && r.v6Fail {
			continue
		}
		a := &netlink.Addr{IPNet: ipNet(p)}
		if p.Addr().Is6() {
			a.Flags = unix.IFA_F_NODAD // don't delay usability for duplicate address detection
		}
		if err := netlink.AddrReplace(r.link, a); err != nil {
			if p.Addr().Is6() {
				r.logf("router: IPv6 unavailable (%v); continuing with IPv4 only", err)
				r.v6Fail = true
				continue
			}
			return fmt.Errorf("add address %s: %w", p, err)
		}
		want[p] = true
		if p.Addr().Is4() {
			src4 = p.Addr()
		} else {
			src6 = p.Addr()
		}
	}
	existing, err := netlink.AddrList(r.link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	for _, a := range existing {
		p, ok := fromIPNet(a.IPNet)
		if !ok || p.Addr().IsLinkLocalUnicast() || want[p] {
			continue
		}
		if err := netlink.AddrDel(r.link, &a); err != nil {
			r.logf("router: remove stale address %s: %v", p, err)
		}
	}

	// Routes.
	wantR := map[netip.Prefix]bool{}
	for _, p := range cfg.Routes {
		is6 := p.Addr().Is6()
		if is6 && (r.v6Fail || !src6.IsValid()) || !is6 && !src4.IsValid() {
			continue
		}
		rt := &netlink.Route{
			LinkIndex: r.link.Attrs().Index,
			Dst:       ipNet(p),
			Scope:     netlink.SCOPE_LINK,
			Protocol:  rtProto,
		}
		if is6 {
			rt.Src = src6.AsSlice()
		} else {
			rt.Src = src4.AsSlice()
		}
		if err := netlink.RouteReplace(rt); err != nil {
			return fmt.Errorf("add route %s: %w", p, err)
		}
		wantR[p] = true
	}
	if err := r.removeRoutes(func(p netip.Prefix) bool { return !wantR[p] }); err != nil {
		return err
	}
	r.fwd.set(cfg.Forward)
	return r.setExitRoutes(cfg.ExitNode, src4, src6)
}

func (r *linuxRouter) removeRoutes(match func(netip.Prefix) bool) error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{LinkIndex: r.link.Attrs().Index, Protocol: rtProto},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	var errs []error
	for _, rt := range routes {
		if rt.Dst == nil {
			continue
		}
		p, ok := fromIPNet(rt.Dst)
		if !ok || !match(p) {
			continue
		}
		if err := netlink.RouteDel(&rt); err != nil {
			errs = append(errs, fmt.Errorf("remove route %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// Close removes our routes. (Closing the TUN device removes the interface,
// and with it any remaining addresses and routes.)
func (r *linuxRouter) Close() error {
	r.fwd.set(false)
	return errors.Join(r.clearExitRoutes(), r.removeRoutes(func(netip.Prefix) bool { return true }))
}
