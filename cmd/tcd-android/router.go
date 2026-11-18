//go:build android

package main

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"tailconnect/internal/androidbridge"
	"tailconnect/internal/engine"
	"tailconnect/internal/ipam"
)

// exitAll is every destination: the VPN's routes while an exit node is in use.
var exitAll = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// alwaysDirect stays on the underlying network even with an exit node:
// link-local and multicast (DHCP, mDNS), as on Linux.
var alwaysDirect = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

// androidRouter uses exit nodes on Android. The VPN interface's routes are
// fixed when the app creates it, so changing them means asking the app for
// a new interface and swapping it in under WireGuard (SwapTUN). Without an
// exit node the VPN routes only the tunnel's ranges; with one it routes
// everything except this device's own networks, which stay direct as on
// Linux. tcd's own sockets bypass the VPN anyway: the app is excluded from
// it (addDisallowedApplication).
type androidRouter struct {
	b    *androidbridge.Bridge
	swap *androidbridge.SwapTUN
	base androidbridge.Message // the interface's settings, without routes
	logf func(string, ...any)

	mu       sync.Mutex
	wantExit bool
	exit     bool           // the current interface routes everything
	excl     []netip.Prefix // ... except these
	closed   bool
}

func newAndroidRouter(b *androidbridge.Bridge, swap *androidbridge.SwapTUN, base androidbridge.Message, logf func(string, ...any)) *androidRouter {
	r := &androidRouter{b: b, swap: swap, base: base, logf: logf}
	b.OnNetwork(r.networkChanged)
	return r
}

func (*androidRouter) SupportsExitNodes() bool { return true }

func (r *androidRouter) Set(cfg engine.RouterConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wantExit = cfg.ExitNode
	return r.applyLocked()
}

// networkChanged re-creates the interface when the device's own networks
// change while an exit node is in use, so the new LAN stays direct.
func (r *androidRouter) networkChanged() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.exit {
		if err := r.applyLocked(); err != nil {
			r.logf("exit node: %v", err)
		}
	}
}

// localNetworks are the device's own networks, to keep off the exit node.
func (r *androidRouter) localNetworks() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range r.b.Network().Addresses {
		a := p.Addr()
		if !a.IsValid() || ipam.DefaultV4.Contains(a) || ipam.DefaultV6.Contains(a) {
			continue
		}
		out = append(out, p.Masked())
	}
	out = append(out, alwaysDirect...)
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr())*64 + a.Bits() - b.Bits() })
	return slices.Compact(out)
}

func (r *androidRouter) applyLocked() error {
	if r.closed {
		return nil
	}
	var excl []netip.Prefix
	if r.wantExit {
		excl = r.localNetworks()
	}
	if r.wantExit == r.exit && slices.Equal(excl, r.excl) {
		return nil
	}
	req := r.base
	req.Routes = []netip.Prefix{ipam.DefaultV4, ipam.DefaultV6}
	if r.wantExit {
		req.Routes = androidbridge.ExcludePrefixes(exitAll, excl)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	fd, err := r.b.RequestTUN(ctx, req)
	if err != nil {
		return fmt.Errorf("change the VPN's routes: %w", err)
	}
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		syscall.Close(fd)
		return fmt.Errorf("change the VPN's routes: %w", err)
	}
	r.swap.Swap(dev)
	r.exit, r.excl = r.wantExit, excl
	if r.exit {
		r.logf("exit node: the VPN now carries all internet traffic (%d routes; direct: %v)", len(req.Routes), excl)
	} else {
		r.logf("exit node: the VPN carries only tunnel traffic again")
	}
	return nil
}

func (r *androidRouter) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.b.OnNetwork(nil)
	return nil
}
