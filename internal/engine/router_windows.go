package engine

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Firewall rule names. tcd uninstall removes them (RemoveFirewallRules).
const (
	fwRuleUDP    = "TailConnect (WireGuard)" // inbound UDP to tcd.exe: direct connections
	fwRuleTunnel = "TailConnect (tunnel)"    // inbound to this node's tunnel addresses
)

// interfaceMetric puts the tunnel ahead of physical adapters (whose
// automatic metrics start at 5 for fast Ethernet), which also makes Windows
// prefer its DNS servers.
const interfaceMetric = 5

type windowsRouter struct {
	luid   uint64
	logf   func(string, ...any)
	v6Fail bool         // IPv6 is disabled on the adapter; skip v6 config
	fwAddr []netip.Addr // addresses fwRuleTunnel currently allows
}

// NewOSRouter configures addresses and routes on the named (Wintun)
// adapter through the IP Helper API.
func NewOSRouter(ifname string, logf func(string, ...any)) (Router, error) {
	luid, err := interfaceAliasToLUID(ifname)
	if err != nil {
		return nil, fmt.Errorf("router: find %s: %w", ifname, err)
	}
	r := &windowsRouter{luid: luid, logf: logf}
	if err := r.setInterface(windows.AF_INET); err != nil {
		return nil, fmt.Errorf("router: configure %s: %w", ifname, err)
	}
	if err := r.setInterface(windows.AF_INET6); err != nil {
		logf("router: IPv6 unavailable on %s (%v); continuing with IPv4 only", ifname, err)
		r.v6Fail = true
	}
	if exe, err := os.Executable(); err != nil {
		logf("router: firewall: %v", err)
	} else if err := netsh("add", "rule", "name="+fwRuleUDP, "dir=in", "action=allow", "protocol=udp",
		"program="+exe, "profile=any", "enable=yes"); err != nil {
		logf("router: firewall: %v (direct connections from other machines may be blocked)", err)
	}
	return r, nil
}

// setInterface sets the MTU and metric for one address family.
func (r *windowsRouter) setInterface(family uint16) error {
	row := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: r.luid}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return err
	}
	row.NlMtu = DefaultMTU
	row.UseAutomaticMetric = 0
	row.Metric = interfaceMetric
	if family == windows.AF_INET {
		row.SitePrefixLength = 0 // must be 0 for IPv4, or the call fails
	}
	return setIpInterfaceEntry(&row)
}

func (r *windowsRouter) Set(cfg RouterConfig) error {
	// Addresses.
	want := map[netip.Prefix]bool{}
	var has4, has6 bool
	var addrs []netip.Addr
	for _, p := range cfg.LocalAddrs {
		if p.Addr().Is6() && r.v6Fail {
			continue
		}
		want[p] = true
		addrs = append(addrs, p.Addr())
		has4 = has4 || p.Addr().Is4()
		has6 = has6 || p.Addr().Is6()
	}
	have, err := r.addresses()
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	for _, row := range have {
		a, _ := sockaddrAddr((*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address)))
		p := netip.PrefixFrom(a, int(row.OnLinkPrefixLength))
		if a.IsLinkLocalUnicast() {
			continue
		}
		if want[p] {
			delete(want, p)
			continue
		}
		if err := deleteUnicastIpAddressEntry(&row); err != nil {
			r.logf("router: remove stale address %s: %v", p, err)
		}
	}
	for p := range want {
		var row windows.MibUnicastIpAddressRow
		initializeUnicastIpAddressEntry(&row)
		row.InterfaceLuid = r.luid
		putSockaddr((*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address)), p.Addr())
		row.OnLinkPrefixLength = uint8(p.Bits())
		row.DadState = windows.IpDadStatePreferred // usable at once, no duplicate address detection
		if err := createUnicastIpAddressEntry(&row); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			if p.Addr().Is6() {
				r.logf("router: IPv6 unavailable (%v); continuing with IPv4 only", err)
				r.v6Fail, has6 = true, false
				continue
			}
			return fmt.Errorf("add address %s: %w", p, err)
		}
	}

	// Routes.
	wantR := map[netip.Prefix]bool{}
	for _, p := range cfg.Routes {
		if p.Addr().Is6() && !has6 || p.Addr().Is4() && !has4 {
			continue
		}
		wantR[p.Masked()] = true
	}
	routes, err := r.routes()
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	for _, row := range routes {
		p, _ := routePrefix(&row)
		if wantR[p] {
			delete(wantR, p)
			continue
		}
		if err := deleteIpForwardEntry2(&row); err != nil {
			return fmt.Errorf("remove route %s: %w", p, err)
		}
	}
	for p := range wantR {
		var row windows.MibIpForwardRow2
		initializeIpForwardEntry(&row)
		row.InterfaceLuid = r.luid
		putSockaddr(&row.DestinationPrefix.Prefix, p.Addr())
		row.DestinationPrefix.PrefixLength = uint8(p.Bits())
		if p.Addr().Is4() { // on-link: next hop 0.0.0.0 or ::
			putSockaddr(&row.NextHop, netip.IPv4Unspecified())
		} else {
			putSockaddr(&row.NextHop, netip.IPv6Unspecified())
		}
		row.Metric = 0
		row.Protocol = windows.MIB_IPPROTO_NETMGMT
		if err := createIpForwardEntry2(&row); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return fmt.Errorf("add route %s: %w", p, err)
		}
	}

	r.setTunnelFirewall(addrs)
	return nil
}

// setTunnelFirewall allows inbound traffic to the node's tunnel addresses,
// so peers can reach this machine's services as they can on Linux; the
// engine's packet filter applies the network's ACLs. Windows' strong host
// model drops packets for these addresses that arrive on other adapters.
func (r *windowsRouter) setTunnelFirewall(addrs []netip.Addr) {
	slices.SortFunc(addrs, netip.Addr.Compare)
	if slices.Equal(addrs, r.fwAddr) {
		return
	}
	_ = netsh("delete", "rule", "name="+fwRuleTunnel)
	r.fwAddr = nil
	if len(addrs) == 0 {
		return
	}
	var ips []string
	for _, a := range addrs {
		ips = append(ips, a.String())
	}
	if err := netsh("add", "rule", "name="+fwRuleTunnel, "dir=in", "action=allow",
		"localip="+strings.Join(ips, ","), "profile=any", "enable=yes"); err != nil {
		r.logf("router: firewall: %v (other machines may not be able to reach this one)", err)
		return
	}
	r.fwAddr = addrs
}

// addresses lists the unicast addresses on the adapter.
func (r *windowsRouter) addresses() ([]windows.MibUnicastIpAddressRow, error) {
	var t *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &t); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	var out []windows.MibUnicastIpAddressRow
	for _, row := range unsafe.Slice(&t.Table[0], t.NumEntries) {
		if row.InterfaceLuid == r.luid {
			out = append(out, row)
		}
	}
	return out, nil
}

// routes lists the routes tcd added to the adapter (static, manual), not
// those Windows derives from its addresses.
func (r *windowsRouter) routes() ([]windows.MibIpForwardRow2, error) {
	var t *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &t); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	var out []windows.MibIpForwardRow2
	for _, row := range t.Rows() {
		if row.InterfaceLuid == r.luid && row.Protocol == windows.MIB_IPPROTO_NETMGMT && row.Origin == windows.NlroManual {
			out = append(out, row)
		}
	}
	return out, nil
}

func routePrefix(row *windows.MibIpForwardRow2) (netip.Prefix, bool) {
	a, ok := sockaddrAddr(&row.DestinationPrefix.Prefix)
	return netip.PrefixFrom(a, int(row.DestinationPrefix.PrefixLength)), ok
}

// Close removes the tunnel firewall rule. (Closing the TUN device removes
// the adapter, and with it its addresses and routes.)
func (r *windowsRouter) Close() error {
	r.setTunnelFirewall(nil)
	return nil
}

// RemoveFirewallRules deletes the rules NewOSRouter and Set create.
func RemoveFirewallRules() {
	_ = netsh("delete", "rule", "name="+fwRuleUDP)
	_ = netsh("delete", "rule", "name="+fwRuleTunnel)
}

// netsh runs `netsh advfirewall firewall ARGS`. "add rule" first deletes any
// rule of the same name, so the rule is replaced rather than duplicated.
func netsh(args ...string) error {
	if len(args) > 2 && args[0] == "add" {
		_ = netsh("delete", "rule", args[2])
	}
	out, err := exec.Command("netsh", append([]string{"advfirewall", "firewall"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
