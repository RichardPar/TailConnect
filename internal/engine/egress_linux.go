//go:build linux && !android

package engine

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"tailconnect/internal/netmark"
)

// An exit node's egress interface (tcd -exit-interface): internet traffic
// it forwards for its peers leaves through that interface only, e.g. a
// commercial VPN's tun0, instead of following the host's default route.
// Policy rules that match only packets arriving from the tunnel pick a
// separate routing table:
//
//	5260  iif tc0  lookup main suppress_prefixlength 1   LAN, tunnel peers and other specific routes
//	5261  iif tc0  lookup egressTable                     default → the egress interface
//	5262  fwmark egressMark  lookup egressTable           the exit node's DNS lookups for its clients
//
// suppress_prefixlength 1 ignores the main table's default route and also
// the 0.0.0.0/1 + 128.0.0.0/1 pair VPN clients such as OpenVPN install, so
// only the egress table decides where internet traffic goes.
//
// The egress table also holds an unreachable default route with a high
// metric: while the interface is down or missing, its own route is gone
// and that one answers, so forwarded traffic is refused, never leaked out
// of the host's normal connection (a kill switch). For IPv6 the same holds
// when the interface has no global IPv6 address: IPv6 is then refused and
// clients fall back to IPv4.
//
// The host's own traffic is untouched: the rules match only packets that
// came in on the tunnel interface, and the DNS lookups the exit node makes
// for its clients (dns.ExitServer), whose sockets carry egressMark, so they
// leave through the egress interface too and are blocked with it.
const (
	egressTable        = 125
	prioEgressSuppress = 5260
	prioEgress         = 5261
	prioEgressMark     = 5262
	egressMark         = 0x7d0000 // under netmark.Mask, but not netmark.Mark
	egressBlockMetric  = 4000
	egressCheck        = 5 * time.Second
)

type egress struct {
	name string // the egress interface ("" = none: the host's routes)
	tun  string // the tunnel interface (tc0)
	logf func(string, ...any)

	mu      sync.Mutex
	stopc   chan struct{} // nil while not running
	done    chan struct{}
	v6      bool
	via     string // where traffic leaves now, for status ("" = blocked)
	err     error  // why traffic is blocked
	logged  string // last state logged, to log changes only
	rpPath  string // rp_filter sysctl changed, and its previous value
	rpValue string
}

// start installs the rules and keeps the egress route in step with the
// interface until stop. v6: IPv6 is forwarded too.
func (g *egress) start(v6 bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopc != nil {
		return nil
	}
	g.v6 = v6
	// Block routes first, then rules, so the table is never empty (an
	// empty table would let lookups fall through to the main table).
	if err := g.installLocked(); err != nil {
		g.clearLocked()
		return err
	}
	g.syncLocked()
	g.stopc, g.done = make(chan struct{}), make(chan struct{})
	go g.loop(g.stopc, g.done)
	return nil
}

func (g *egress) families() []int {
	if g.v6 {
		return []int{unix.AF_INET, unix.AF_INET6}
	}
	return []int{unix.AF_INET}
}

func defaultDst(family int) *net.IPNet {
	if family == unix.AF_INET6 {
		return ipNet(netip.MustParsePrefix("::/0"))
	}
	return ipNet(netip.MustParsePrefix("0.0.0.0/0"))
}

func egressRules(family int, tun string) []*netlink.Rule {
	suppress := netlink.NewRule()
	suppress.Family, suppress.Priority, suppress.Table, suppress.IifName = family, prioEgressSuppress, unix.RT_TABLE_MAIN, tun
	suppress.SuppressPrefixlen = 1
	out := netlink.NewRule()
	out.Family, out.Priority, out.Table, out.IifName = family, prioEgress, egressTable, tun
	mask := uint32(netmark.Mask)
	marked := netlink.NewRule()
	marked.Family, marked.Priority, marked.Table, marked.Mark, marked.Mask = family, prioEgressMark, egressTable, egressMark, &mask
	return []*netlink.Rule{suppress, out, marked}
}

// egressDialer makes sockets carrying egressMark (see egressRules).
func egressDialer() *net.Dialer {
	return &net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, egressMark)
		}); err != nil {
			return err
		}
		return serr // unmarked, the lookup would leave by the default route: fail instead
	}}
}

// installLocked adds the block routes and the rules (missing ones only).
func (g *egress) installLocked() error {
	for _, fam := range g.families() {
		block := &netlink.Route{
			Family: fam, Dst: defaultDst(fam), Table: egressTable, Type: unix.RTN_UNREACHABLE,
			Priority: egressBlockMetric, Protocol: rtProto,
		}
		if err := netlink.RouteReplace(block); err != nil {
			return fmt.Errorf("exit interface: add blocking route: %w", err)
		}
		have, err := netlink.RuleList(fam)
		if err != nil {
			return fmt.Errorf("exit interface: list rules: %w", err)
		}
		for _, want := range egressRules(fam, g.tun) {
			if hasRule(have, want) {
				continue
			}
			if err := netlink.RuleAdd(want); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("exit interface: add rule %d: %w", want.Priority, err)
			}
		}
	}
	return nil
}

func (g *egress) loop(stop, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(egressCheck)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			g.mu.Lock()
			if g.stopc == stop {
				if err := g.installLocked(); err != nil { // someone flushed them
					g.logf("%v", err)
				}
				g.syncLocked()
			}
			g.mu.Unlock()
		}
	}
}

// syncLocked points the egress table's default routes at the interface,
// as it is now: it may have gone, come back with a new index (a VPN client
// restarting recreates tun0) or a new gateway.
func (g *egress) syncLocked() {
	via, err := g.routeLocked()
	g.via, g.err = via, err
	state := "through " + via
	if err != nil {
		state = err.Error()
	}
	if state != g.logged {
		g.logged = state
		if err != nil {
			g.logf("exit node: %v", err)
		} else {
			g.logf("exit node: internet traffic leaves through %s", via)
		}
	}
}

func (g *egress) routeLocked() (string, error) {
	link, err := netlink.LinkByName(g.name)
	if err != nil {
		g.dropRoutesLocked()
		return "", fmt.Errorf("%s not found: exit traffic is blocked until it is back", g.name)
	}
	a := link.Attrs()
	if a.Flags&net.FlagUp == 0 {
		g.dropRoutesLocked()
		return "", fmt.Errorf("%s is down: exit traffic is blocked until it is up", g.name)
	}
	g.looseRPFilterLocked()
	via := g.name
	for _, fam := range g.families() {
		gw, ok := gateway(link, fam)
		if !ok {
			// No address of this family on the interface: nothing could
			// be masqueraded to it, so this family stays blocked.
			g.dropRouteLocked(fam)
			continue
		}
		rt := &netlink.Route{
			Family: fam, LinkIndex: a.Index, Dst: defaultDst(fam), Table: egressTable, Protocol: rtProto,
		}
		if gw.IsValid() {
			rt.Gw = gw.AsSlice()
		} else {
			rt.Scope = netlink.SCOPE_LINK
		}
		if err := netlink.RouteReplace(rt); err != nil {
			g.dropRoutesLocked()
			return "", fmt.Errorf("route exit traffic through %s: %v (exit traffic is blocked)", g.name, err)
		}
		if fam == unix.AF_INET && gw.IsValid() {
			via = fmt.Sprintf("%s (gateway %s)", g.name, gw)
		}
	}
	return via, nil
}

// gateway finds the next hop for family on link: the gateway of its
// default route (or the widest route with one, like OpenVPN's 0.0.0.0/1)
// in the main table, or none for a point-to-point interface (tun, wg,
// ppp). ok is false when the link has no usable address of the family.
func gateway(link netlink.Link, family int) (gw netip.Addr, ok bool) {
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, ad := range addrs {
		// IPv4: any address. IPv6: not just link-local.
		if a, valid := netip.AddrFromSlice(ad.IP); valid && (family == unix.AF_INET || a.IsGlobalUnicast()) {
			ok = true
			break
		}
	}
	if !ok {
		return netip.Addr{}, false
	}
	routes, err := netlink.RouteList(link, family)
	if err != nil {
		return netip.Addr{}, true
	}
	best := 129
	for _, rt := range routes {
		if rt.Gw == nil {
			continue
		}
		bits := 0
		if rt.Dst != nil {
			bits, _ = rt.Dst.Mask.Size()
		}
		if bits < best {
			if a, valid := netip.AddrFromSlice(rt.Gw); valid {
				gw, best = a.Unmap(), bits
			}
		}
	}
	return gw, true
}

// dropRouteLocked removes the egress route of family (the block route
// stays).
func (g *egress) dropRouteLocked(family int) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: egressTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return
	}
	for _, rt := range routes {
		if rt.Type != unix.RTN_UNREACHABLE {
			_ = netlink.RouteDel(&rt)
		}
	}
}

func (g *egress) dropRoutesLocked() {
	for _, fam := range g.families() {
		g.dropRouteLocked(fam)
	}
}

// looseRPFilterLocked sets reverse-path filtering on the interface to
// loose: replies to forwarded traffic come in on it from addresses the
// main table routes elsewhere, which strict filtering would drop.
func (g *egress) looseRPFilterLocked() {
	p := filepath.Join(sysctlDir, "ipv4/conf", g.name, "rp_filter")
	v, err := readSysctl(p)
	if err != nil || v == "0" || v == "2" {
		return
	}
	if err := os.WriteFile(p, []byte("2"), 0o644); err != nil {
		g.logf("exit node: loose reverse-path filtering on %s: %v", g.name, err)
		return
	}
	if g.rpPath != p {
		g.rpPath, g.rpValue = p, v
	}
}

// stop removes the rules and routes and restores reverse-path filtering.
func (g *egress) stop() {
	g.mu.Lock()
	stop, done := g.stopc, g.done
	g.stopc, g.done = nil, nil
	g.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.clearLocked()
	if g.rpPath != "" {
		if err := os.WriteFile(g.rpPath, []byte(g.rpValue), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
			g.logf("exit node: restore %s: %v", g.rpPath, err)
		}
		g.rpPath = ""
	}
	g.via, g.err, g.logged = "", nil, ""
}

// clearLocked removes the egress rules and table.
func (g *egress) clearLocked() { clearEgress() }

// clearEgress removes the egress rules and table (also any left by a tcd
// that crashed).
func clearEgress() {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		have, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, h := range have {
			if (h.Priority == prioEgressSuppress && h.Table == unix.RT_TABLE_MAIN) ||
				((h.Priority == prioEgress || h.Priority == prioEgressMark) && h.Table == egressTable) {
				_ = netlink.RuleDel(&h)
			}
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: egressTable}, netlink.RT_FILTER_TABLE)
	if err == nil {
		for _, rt := range routes {
			_ = netlink.RouteDel(&rt)
		}
	}
}

// status is where forwarded traffic leaves, or why it is blocked.
func (g *egress) status() (via string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.via, g.err
}
