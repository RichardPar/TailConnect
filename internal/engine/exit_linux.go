//go:build linux && !android

package engine

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"tailconnect/internal/netmark"
)

// Using an exit node: the default routes go into the tunnel through a
// separate routing table, selected by policy rules, so nothing in the main
// table changes:
//
//	5270  fwmark netmark.Mark/Mask  lookup main     tcd's own sockets bypass the tunnel
//	5271  lookup main suppress_prefixlength 0      every route but the default (LAN, tunnel peers)
//	5272  lookup exitTable                          default → tunnel
//
// The same as wg-quick: the LAN stays reachable, and tcd's WireGuard, relay
// and control connections (marked by package netmark) use the real network.
const (
	exitTable    = 124
	prioMark     = 5270
	prioSuppress = 5271
	prioExit     = 5272
)

// Being an exit node: IP forwarding on, and an nftables table per family
// that masquerades traffic from the tunnel going out of other interfaces
// and accepts it in the forward hook.
const nftTable = "tailconnect-exit"

func (*linuxRouter) SupportsExitNodes() bool { return true }

func exitRules(family int) []*netlink.Rule {
	mask := uint32(netmark.Mask)
	mark := netlink.NewRule()
	mark.Family, mark.Priority, mark.Table, mark.Mark, mark.Mask = family, prioMark, unix.RT_TABLE_MAIN, netmark.Mark, &mask
	suppress := netlink.NewRule()
	suppress.Family, suppress.Priority, suppress.Table, suppress.SuppressPrefixlen = family, prioSuppress, unix.RT_TABLE_MAIN, 0
	exit := netlink.NewRule()
	exit.Family, exit.Priority, exit.Table = family, prioExit, exitTable
	return []*netlink.Rule{mark, suppress, exit}
}

// setExitRoutes sends default traffic into the tunnel (on) or stops it.
func (r *linuxRouter) setExitRoutes(on bool, src4, src6 netip.Addr) error {
	if !on {
		return r.clearExitRoutes()
	}
	type fam struct {
		family int
		dst    netip.Prefix
		src    netip.Addr
	}
	fams := []fam{{unix.AF_INET, netip.MustParsePrefix("0.0.0.0/0"), src4}}
	if !r.v6Fail && src6.IsValid() {
		fams = append(fams, fam{unix.AF_INET6, netip.MustParsePrefix("::/0"), src6})
	}
	for _, f := range fams {
		if !f.src.IsValid() {
			continue
		}
		// Route first, then rules, so traffic never meets an empty table.
		rt := &netlink.Route{
			LinkIndex: r.link.Attrs().Index, Dst: ipNet(f.dst), Src: f.src.AsSlice(),
			Scope: netlink.SCOPE_LINK, Protocol: rtProto, Table: exitTable,
		}
		if err := netlink.RouteReplace(rt); err != nil {
			return fmt.Errorf("exit node: add default route %s: %w", f.dst, err)
		}
		have, err := netlink.RuleList(f.family)
		if err != nil {
			return fmt.Errorf("exit node: list rules: %w", err)
		}
		for _, want := range exitRules(f.family) {
			if hasRule(have, want) {
				continue
			}
			if err := netlink.RuleAdd(want); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("exit node: add rule %d: %w", want.Priority, err)
			}
		}
	}
	return nil
}

func hasRule(have []netlink.Rule, want *netlink.Rule) bool {
	for _, h := range have {
		if h.Priority == want.Priority && h.Table == want.Table {
			return true
		}
	}
	return false
}

// clearExitRoutes removes the policy rules and the exit table's routes
// (also any left by a tcd that crashed).
func (r *linuxRouter) clearExitRoutes() error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		have, err := netlink.RuleList(family)
		if err != nil {
			continue // e.g. IPv6 disabled
		}
		for _, h := range have {
			if (h.Priority == prioMark || h.Priority == prioSuppress || h.Priority == prioExit) &&
				(h.Table == exitTable || h.Table == unix.RT_TABLE_MAIN) {
				if err := netlink.RuleDel(&h); err != nil {
					errs = append(errs, fmt.Errorf("exit node: remove rule %d: %w", h.Priority, err))
				}
			}
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: exitTable}, netlink.RT_FILTER_TABLE)
	if err == nil {
		for _, rt := range routes {
			if err := netlink.RouteDel(&rt); err != nil {
				errs = append(errs, fmt.Errorf("exit node: remove route: %w", err))
			}
		}
	}
	return errors.Join(errs...)
}

// forwarder turns this machine into an exit node and back, restoring the
// sysctls it changed.
type forwarder struct {
	ifname  string
	on      bool
	restore map[string]string // sysctl path → value before we changed it
	v6      bool              // IPv6 is forwarded too
	logf    func(string, ...any)
	lastErr error
	cleaned bool
}

const sysctlDir = "/proc/sys/net"

func readSysctl(p string) (string, error) {
	b, err := os.ReadFile(p)
	return strings.TrimSpace(string(b)), err
}

func (f *forwarder) setSysctl(p, v string) error {
	old, err := readSysctl(p)
	if err != nil {
		return err
	}
	if old == v {
		return nil
	}
	if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
		return err
	}
	if _, ok := f.restore[p]; !ok {
		f.restore[p] = old
	}
	return nil
}

// set turns forwarding on or off. Errors are kept for status rather than
// failing the network map: the tunnel itself works without forwarding.
func (f *forwarder) set(on bool) {
	if !f.cleaned {
		f.cleaned = true
		f.deleteTables() // left by a tcd that crashed
	}
	if on == f.on {
		return
	}
	if !on {
		f.stop()
		return
	}
	if f.restore == nil {
		f.restore = map[string]string{}
	}
	f.lastErr = nil
	if err := f.setSysctl(filepath.Join(sysctlDir, "ipv4/ip_forward"), "1"); err != nil {
		f.fail(fmt.Errorf("enable IPv4 forwarding: %w", err))
		return
	}
	f.v6 = f.enableV6()
	if err := f.addTables(); err != nil {
		f.fail(fmt.Errorf("set up NAT: %w", err))
		return
	}
	f.on = true
	v6 := "IPv4 only"
	if f.v6 {
		v6 = "IPv4 and IPv6"
	}
	f.logf("exit node: forwarding internet traffic from the tunnel (%s)", v6)
}

func (f *forwarder) fail(err error) {
	f.logf("exit node: %v", err)
	f.stop()
	f.lastErr = err
}

// enableV6 turns on IPv6 forwarding. Forwarding makes Linux ignore router
// advertisements on interfaces with accept_ra=1, which would drop the
// host's own IPv6 addresses and routes, so those are moved to accept_ra=2
// (accept even when forwarding) first.
func (f *forwarder) enableV6() bool {
	conf := filepath.Join(sysctlDir, "ipv6/conf")
	if _, err := os.Stat(conf); err != nil {
		return false
	}
	ifaces, _ := os.ReadDir(conf)
	for _, i := range ifaces {
		name := i.Name()
		if name == "all" || name == "default" || name == "lo" || name == f.ifname {
			continue
		}
		p := filepath.Join(conf, name, "accept_ra")
		if v, err := readSysctl(p); err == nil && v == "1" {
			if err := f.setSysctl(p, "2"); err != nil {
				f.logf("exit node: keep router advertisements on %s: %v", name, err)
			}
		}
	}
	if err := f.setSysctl(filepath.Join(conf, "all/forwarding"), "1"); err != nil {
		f.logf("exit node: IPv6 forwarding unavailable (%v); IPv4 only", err)
		return false
	}
	return true
}

func (f *forwarder) stop() {
	f.deleteTables()
	// Restore in reverse dependency order: forwarding off before accept_ra.
	for _, p := range []string{filepath.Join(sysctlDir, "ipv6/conf/all/forwarding"), filepath.Join(sysctlDir, "ipv4/ip_forward")} {
		if v, ok := f.restore[p]; ok {
			if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
				f.logf("exit node: restore %s: %v", p, err)
			}
			delete(f.restore, p)
		}
	}
	for p, v := range f.restore {
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
			f.logf("exit node: restore %s: %v", p, err)
		}
		delete(f.restore, p)
	}
	if f.on {
		f.logf("exit node: stopped forwarding")
	}
	f.on, f.v6, f.lastErr = false, false, nil
}

func ifname(n string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, n+"\x00")
	return b
}

func (f *forwarder) families() []nftables.TableFamily {
	if f.v6 {
		return []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6}
	}
	return []nftables.TableFamily{nftables.TableFamilyIPv4}
}

// addTables installs, per address family:
//
//	table tailconnect-exit {
//	  chain postrouting { type nat hook postrouting priority srcnat
//	    iifname "tc0" oifname != "tc0" masquerade }
//	  chain forward { type filter hook forward priority filter
//	    iifname "tc0" accept
//	    oifname "tc0" ct state established,related accept }
//	}
//
// The forward chain only accepts; it can't override a drop in another
// firewall's forward chain (e.g. ufw's or Docker's), which must allow the
// traffic itself.
func (f *forwarder) addTables() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	tun := ifname(f.ifname)
	established := binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED)
	for _, fam := range f.families() {
		t := c.AddTable(&nftables.Table{Family: fam, Name: nftTable})
		post := c.AddChain(&nftables.Chain{
			Name: "postrouting", Table: t, Type: nftables.ChainTypeNAT,
			Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource,
		})
		c.AddRule(&nftables.Rule{Table: t, Chain: post, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: tun},
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: tun},
			&expr.Masq{},
		}})
		fwd := c.AddChain(&nftables.Chain{
			Name: "forward", Table: t, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
		})
		c.AddRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: tun},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}})
		c.AddRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: tun},
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: established, Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}})
	}
	return c.Flush()
}

func (f *forwarder) deleteTables() {
	c, err := nftables.New()
	if err != nil {
		return
	}
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		tables, err := c.ListTablesOfFamily(fam)
		if err != nil {
			continue
		}
		for _, t := range tables {
			if t.Name == nftTable {
				c.DelTable(t)
			}
		}
	}
	if err := c.Flush(); err != nil {
		f.logf("exit node: remove NAT table: %v", err)
	}
}

// ForwardError is why this machine isn't forwarding although it should
// ("" when fine).
func (r *linuxRouter) ForwardError() string {
	if r.fwd.lastErr != nil {
		return r.fwd.lastErr.Error()
	}
	return ""
}
