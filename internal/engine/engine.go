// Package engine drives the WireGuard data plane: it owns a wireguard-go
// device on a TUN interface and turns network maps into peer configuration,
// interface addresses and routes.
//
// Peer changes are applied as diffs, so a map update never tears down
// sessions with unchanged peers. Transport and path selection (direct UDP
// or relay) are handled by magicsock: each WireGuard peer's endpoint is the
// peer's node key, and roaming is disabled.
package engine

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"tailconnect/internal/dns"
	"tailconnect/internal/filter"
	"tailconnect/internal/ipam"
	"tailconnect/internal/key"
	"tailconnect/internal/magicsock"
	"tailconnect/internal/protocol"
)

// DefaultMTU leaves room for WireGuard overhead on links with MTU ≥ 1360,
// including IPv6 underlays and PPPoE.
const DefaultMTU = 1280

// DefaultPort is the default WireGuard UDP port.
const DefaultPort = 41641

// Handshakes are started by traffic; there is no persistent keepalive (idle
// peers cost nothing, which matters on mobile). The one exception: when the
// engine starts, it kicks a handshake with every peer in its first network
// map, so peers holding a session from before a restart switch to fresh keys
// immediately instead of after WireGuard's 15s dead-peer timeout. The kick is
// jittered to make simultaneous initiations (which make both sides wait out
// the 5s retry timer) unlikely when two nodes start together.
const maxKickJitter = time.Second

type RouterConfig struct {
	LocalAddrs []netip.Prefix // this node's tunnel addresses
	Routes     []netip.Prefix // destinations to send into the tunnel
	// ExitNode sends all other traffic (the default routes) into the
	// tunnel too, to the exit node, except tcd's own (package netmark).
	ExitNode bool
	// Forward makes this machine an exit node: it forwards and NATs
	// traffic from the tunnel to the internet.
	Forward bool
}

func (c RouterConfig) equal(o RouterConfig) bool {
	return slices.Equal(c.LocalAddrs, o.LocalAddrs) && slices.Equal(c.Routes, o.Routes) &&
		c.ExitNode == o.ExitNode && c.Forward == o.Forward
}

// ExitRouter is implemented by routers that can use exit nodes and be one
// (Linux, with a kernel TUN). Others ignore RouterConfig.ExitNode and Forward.
type ExitRouter interface {
	SupportsExitNodes() bool
	// ForwardError says why forwarding failed, if it did.
	ForwardError() string
}

// exitAll is what an exit node's peer entry adds: every destination.
var exitAll = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// Router applies addresses and routes to the OS.
type Router interface {
	Set(RouterConfig) error
	Close() error
}

// NoopRouter is used with userspace (netstack) TUNs, which need no OS config.
type NoopRouter struct{}

func (NoopRouter) Set(RouterConfig) error { return nil }
func (NoopRouter) Close() error           { return nil }

type Config struct {
	TUN        tun.Device
	Router     Router // nil = NoopRouter
	ListenPort uint16 // 0 = random
	// DiscoKey enables NAT traversal (disco path discovery).
	DiscoKey key.DiscoPrivate
	// OnEndpointsChanged is called when this node's advertised endpoints or
	// home relay change (e.g. STUN learned a new public address).
	OnEndpointsChanged func()
	// DNS points the host's resolver at MagicDNS (nil = leave host DNS alone;
	// the in-tunnel resolver still answers at 100.100.100.100).
	DNS     dns.OSConfigurator
	Logf    func(format string, args ...any)
	Verbose bool // log wireguard-go internals
}

type peerState struct {
	allowed []netip.Prefix
}

type Engine struct {
	dev    *device.Device
	magic  *magicsock.Conn
	router Router
	logf   func(string, ...any)
	pub    key.NodePublic

	resolver *dns.Resolver
	dnsTUN   *dns.TUN
	filter   *filter.TUN
	osDNS    dns.OSConfigurator

	mu         sync.Mutex
	peers      map[key.NodePublic]peerState
	lastRouter RouterConfig
	lastOSDNS  dns.OSConfig
	restricted map[netip.Addr][]protocol.PortRange // peers limited by shares or access rules
	dnsErr     string
	dnsDomain  string // this machine's own domain (tenant), for status
	dnsBase    string // the domain routed to MagicDNS
	sawMap     bool
	closed     bool

	lastMap   *protocol.MapResponse // the map applied last, and the local prefixes with it
	lastLocal []netip.Prefix

	exitPref   string // the exit node chosen on this machine ("" = none)
	exitUsing  string // the exit node in use (its name), if any
	exitErr    string // why exitPref isn't in use
	exitServes bool   // this machine is an exit node for its account
}

// New brings up a WireGuard device with the node's private key.
func New(cfg Config, priv key.NodePrivate) (*Engine, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Router == nil {
		cfg.Router = NoopRouter{}
	}
	if cfg.DNS == nil {
		cfg.DNS = dns.NoopConfigurator{}
	}
	resolver := dns.NewResolver(cfg.Logf)
	dnsTUN := dns.WrapTUN(cfg.TUN, resolver, protocol.MagicDNSAddr, protocol.MagicDNSAddr6, cfg.Logf)
	magic := magicsock.New(magicsock.Options{PrivateKey: priv, DiscoKey: cfg.DiscoKey, Logf: cfg.Logf, OnEndpointsChanged: cfg.OnEndpointsChanged})
	wgLog := &device.Logger{Verbosef: device.DiscardLogf, Errorf: prefixed(cfg.Logf, "wg: ")}
	if cfg.Verbose {
		wgLog.Verbosef = prefixed(cfg.Logf, "wg: ")
	}
	// WireGuard ↔ packet filter (one-way sharing) ↔ MagicDNS interception ↔ TUN.
	filt := filter.Wrap(dnsTUN)
	dev := device.NewDevice(filt, magic, wgLog)
	// Peers' endpoints are node keys interpreted by magicsock; WireGuard must
	// not replace them with the source address of received packets.
	dev.DisableSomeRoamingForBrokenMobileSemantics()
	raw := priv.Raw()
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(raw[:]), cfg.ListenPort)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		magic.Shutdown()
		return nil, fmt.Errorf("engine: configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		magic.Shutdown()
		return nil, fmt.Errorf("engine: bring device up: %w", err)
	}
	return &Engine{
		dev: dev, magic: magic, router: cfg.Router, logf: cfg.Logf, pub: priv.Public(),
		resolver: resolver, dnsTUN: dnsTUN, filter: filt, osDNS: cfg.DNS,
		peers: map[key.NodePublic]peerState{},
	}, nil
}

func prefixed(logf func(string, ...any), p string) func(string, ...any) {
	return func(f string, a ...any) { logf(p+f, a...) }
}

// Close tears down the device and OS configuration.
func (e *Engine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	e.mu.Unlock()
	if err := e.osDNS.Close(); err != nil {
		e.logf("dns: revert host configuration: %v", err)
	}
	if err := e.router.Close(); err != nil {
		e.logf("router close: %v", err)
	}
	e.dev.Close()
	e.magic.Shutdown()
}

// SetControlURL tells magicsock where the embedded relay lives (relative
// relay URLs are resolved against the control URL).
func (e *Engine) SetControlURL(u string) error { return e.magic.SetRelayBase(u) }

// HomeRelay is the relay region this node is reachable through (0 = none).
func (e *Engine) HomeRelay() int { return e.magic.HomeRelay() }

// RelayConnected reports whether the home relay connection is up.
func (e *Engine) RelayConnected() bool { return e.magic.RelayConnected() }

// SetLocalEndpoints records this host's local interface endpoints.
func (e *Engine) SetLocalEndpoints(eps []netip.AddrPort) { e.magic.SetLocalEndpoints(eps) }

// Endpoints returns the endpoints to advertise: local plus public (STUN).
func (e *Engine) Endpoints() []netip.AddrPort { return e.magic.Endpoints() }

// Reconfig applies a network map. local lists this host's interface prefixes,
// used to choose each peer's best-guess direct address.
func (e *Engine) Reconfig(nm *protocol.MapResponse, local []netip.Prefix) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reconfigLocked(nm, local)
}

func (e *Engine) reconfigLocked(nm *protocol.MapResponse, local []netip.Prefix) error {
	if e.closed {
		return fmt.Errorf("engine closed")
	}
	e.lastMap, e.lastLocal = nm, local

	// magicsock must know the peers before WireGuard parses their endpoints.
	e.magic.SetNetworkMap(nm.Peers, nm.Relays, local)

	var b strings.Builder
	var kick []key.NodePublic
	firstMap := !e.sawMap
	e.sawMap = true
	want := map[key.NodePublic]bool{}
	var routes []netip.Prefix
	restricted := map[netip.Addr][]protocol.PortRange{}
	exitRouter, canExit := e.router.(ExitRouter)
	canExit = canExit && exitRouter.SupportsExitNodes()
	e.exitUsing, e.exitErr = "", ""
	var exitKey key.NodePublic
	if e.exitPref != "" {
		switch exit, err := FindExitNode(nm, e.exitPref); {
		case !canExit:
			e.exitErr = "this client can't use exit nodes (only Linux with a kernel TUN can)"
		case err != nil:
			e.exitErr = err.Error()
		default:
			exitKey, e.exitUsing = exit.NodeKey, exit.Name
		}
		if e.exitErr != "" {
			e.logf("exit node %q not used: %s; internet traffic goes direct", e.exitPref, e.exitErr)
		}
	}
	for _, p := range nm.Peers {
		if p.NodeKey.IsZero() || p.NodeKey.Equal(e.pub) {
			continue
		}
		want[p.NodeKey] = true
		if p.NoInitiate {
			for _, a := range p.Addresses {
				restricted[a.Addr()] = p.Inbound
			}
		}
		allowed := slices.Clone(p.Addresses)
		routes = append(routes, allowed...)
		if p.NodeKey == exitKey {
			allowed = append(allowed, exitAll...)
		}
		slices.SortFunc(allowed, comparePrefix)

		old, exists := e.peers[p.NodeKey]
		if exists && slices.Equal(old.allowed, allowed) {
			continue
		}
		raw := p.NodeKey.Raw()
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(raw[:]))
		if exists {
			b.WriteString("update_only=true\n")
		} else {
			fmt.Fprintf(&b, "endpoint=%s\n", p.NodeKey.String())
			if firstMap {
				kick = append(kick, p.NodeKey)
			}
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range allowed {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
		e.peers[p.NodeKey] = peerState{allowed: allowed}
		e.logf("peer %s (%s): allowed=%v endpoints=%v relay=%d", p.Name, p.NodeKey.ShortString(), allowed, p.Endpoints, p.HomeRelay)
	}
	for k := range e.peers {
		if !want[k] {
			raw := k.Raw()
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", hex.EncodeToString(raw[:]))
			delete(e.peers, k)
			e.logf("peer %s removed", k.ShortString())
		}
	}
	// Change the filter around the peer update so no packet slips through:
	// restrictions for new shared machines apply before they are added, and
	// restrictions for removed ones are lifted only after they are gone.
	transition := maps.Clone(restricted)
	for a, r := range e.restricted {
		if _, ok := transition[a]; !ok {
			transition[a] = r // a peer on its way out keeps its restriction until removed
		}
	}
	e.filter.SetPolicies(transition)
	if b.Len() > 0 {
		if err := e.dev.IpcSet(b.String()); err != nil {
			return fmt.Errorf("engine: apply peers: %w", err)
		}
	}
	e.filter.SetPolicies(restricted)
	e.restricted = restricted
	for _, k := range kick {
		time.AfterFunc(rand.N(maxKickJitter), func() { e.kickHandshake(k) })
	}

	magicDNS := nm.DNS.MagicDNS && nm.DNS.Domain != ""
	if magicDNS {
		routes = append(routes, netip.PrefixFrom(protocol.MagicDNSAddr, 32), netip.PrefixFrom(protocol.MagicDNSAddr6, 128))
	}
	slices.SortFunc(routes, comparePrefix)
	self := slices.Clone(nm.Self.Addresses)
	slices.SortFunc(self, comparePrefix)
	e.exitServes = canExit && nm.Self.ExitNode
	rc := RouterConfig{LocalAddrs: self, Routes: routes, ExitNode: !exitKey.IsZero(), Forward: e.exitServes}
	if !rc.equal(e.lastRouter) {
		if err := e.router.Set(rc); err != nil {
			return fmt.Errorf("engine: router: %w", err)
		}
		e.lastRouter = rc
	}
	e.reconfigDNSLocked(nm, magicDNS)
	return nil
}

// ErrNoSuchMachine: FindExitNode found no machine of that name.
var ErrNoSuchMachine = errors.New("no such machine in this network")

// FindExitNode finds the exit node pref names in nm: a peer's short name,
// MagicDNS name, hostname or tunnel address. It must have its exit node
// role turned on.
func FindExitNode(nm *protocol.MapResponse, pref string) (protocol.Node, error) {
	pref = strings.TrimSuffix(strings.ToLower(pref), ".")
	if nm.Self.ExitNode && matchesNode(nm.Self, pref) {
		return protocol.Node{}, fmt.Errorf("%s is this machine", pref)
	}
	for _, p := range nm.Peers {
		if !matchesNode(p, pref) {
			continue
		}
		if !p.ExitNode {
			return protocol.Node{}, fmt.Errorf("%s is not an exit node (turn it on in the web portal: Machines)", pref)
		}
		if nm.Self.ExitNode {
			return protocol.Node{}, errors.New("this machine is itself an exit node, so it can't use one")
		}
		return p, nil
	}
	return protocol.Node{}, fmt.Errorf("%s: %w", pref, ErrNoSuchMachine)
}

func matchesNode(n protocol.Node, pref string) bool {
	name := strings.ToLower(n.Name)
	if name == pref || strings.ToLower(n.Hostinfo.Hostname) == pref {
		return true
	}
	if short, _, ok := strings.Cut(name, "."); ok && short == pref {
		return true
	}
	for _, a := range n.Addresses {
		if a.Addr().String() == pref {
			return true
		}
	}
	return false
}

// SetExitNode chooses the exit node for this machine's internet traffic
// ("" = none), applying it to the current map at once if there is one.
func (e *Engine) SetExitNode(pref string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if pref == e.exitPref {
		return nil
	}
	e.exitPref = pref
	if e.lastMap == nil {
		return nil
	}
	return e.reconfigLocked(e.lastMap, e.lastLocal)
}

// ExitStatus describes exit nodes on this machine.
type ExitStatus struct {
	Chosen       string // the exit node chosen ("" = none)
	Using        string // MagicDNS name of the exit node carrying internet traffic ("" = none)
	Error        string // why Chosen isn't in use
	Serving      bool   // this machine is an exit node
	ServingError string // why it isn't forwarding although it should
}

func (e *Engine) ExitStatus() ExitStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := ExitStatus{Chosen: e.exitPref, Using: e.exitUsing, Error: e.exitErr, Serving: e.exitServes}
	if r, ok := e.router.(ExitRouter); ok && e.exitServes {
		st.ServingError = r.ForwardError()
	}
	return st
}

// reconfigDNSLocked updates the in-tunnel resolver and then the host's DNS
// settings (after routes, so the resolver is reachable once the host uses
// it). Host DNS failures are reported in status but don't fail the map:
// the tunnel itself works without them.
func (e *Engine) reconfigDNSLocked(nm *protocol.MapResponse, on bool) {
	var osc dns.OSConfig
	if on {
		domain := strings.TrimSuffix(strings.ToLower(nm.DNS.Domain), ".")
		resolver := nm.DNS.Resolver
		if !resolver.IsValid() {
			resolver = protocol.MagicDNSAddr
		}
		// Search the tenant domain first so "laptop" finds this tenant's
		// laptop; route the whole base domain so every name resolves.
		search := []string{}
		for _, d := range nm.DNS.Search {
			if d = strings.TrimSuffix(strings.ToLower(d), "."); d != "" {
				search = append(search, d)
			}
		}
		if len(search) == 0 {
			search = []string{domain}
		}
		osc = dns.OSConfig{Nameservers: []netip.Addr{resolver}, SearchDomains: search}
		if len(nm.DNS.Nameservers) == 0 && e.osDNS.SupportsSplitDNS() {
			// Split DNS: only MagicDNS names and reverse lookups of tunnel
			// addresses; the host keeps its resolvers for everything else.
			osc.MatchDomains = append(magicDomains(nm.DNS), reverseZones()...)
		}
	}
	var dnsErr string
	if !osc.Equal(e.lastOSDNS) {
		if err := e.osDNS.Set(osc); err != nil {
			e.logf("dns: configure host (%s): %v", e.osDNS.Mode(), err)
			dnsErr = err.Error()
		} else {
			e.lastOSDNS = osc
			if on && e.osDNS.Mode() != dns.ModeOff {
				e.logf("dns: host uses MagicDNS for %v via %s", orAll(osc.MatchDomains), e.osDNS.Mode())
			}
		}
	} else if e.dnsErr != "" {
		dnsErr = e.dnsErr
	}
	e.dnsErr = dnsErr

	cfg := dns.Config{ReversePrefixes: []netip.Prefix{ipam.DefaultV4, ipam.DefaultV6}, Hosts: map[string][]netip.Addr{}}
	if on {
		cfg.Domain = nm.DNS.Domain
		cfg.Domains = magicDomains(nm.DNS)
		add := func(n protocol.Node) {
			if n.Name == "" {
				return
			}
			for _, p := range n.Addresses {
				name := strings.ToLower(n.Name)
				cfg.Hosts[name] = append(cfg.Hosts[name], p.Addr())
			}
		}
		add(nm.Self)
		for _, p := range nm.Peers {
			add(p)
		}
		cfg.Upstream = upstreams(nm.DNS.Nameservers)
		if len(nm.DNS.Nameservers) == 0 && !e.osDNS.SupportsSplitDNS() {
			// Everything comes to us; pass it on to the host's resolvers,
			// looked up at each query as they change with the network.
			osDNS := e.osDNS
			cfg.HostUpstream = func() []netip.AddrPort { return upstreams(osDNS.HostResolvers()) }
		}
		e.dnsBase = strings.TrimSuffix(strings.ToLower(cfg.Domain), ".")
		e.dnsDomain = e.dnsBase
		if len(osc.SearchDomains) > 0 {
			e.dnsDomain = osc.SearchDomains[0]
		}
	} else {
		e.dnsDomain, e.dnsBase = "", ""
	}
	e.resolver.SetConfig(cfg)
	e.dnsTUN.SetEnabled(on)
}

// magicDomains lists the domains MagicDNS answers: the base domain, then
// tenants' own domains.
func magicDomains(c protocol.DNSConfig) []string {
	var out []string
	for _, d := range append([]string{c.Domain}, c.Domains...) {
		if d = strings.TrimSuffix(strings.ToLower(d), "."); d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// upstreams turns resolver addresses into port-53 upstreams, leaving out
// MagicDNS itself: forwarding to ourselves would loop.
func upstreams(addrs []netip.Addr) []netip.AddrPort {
	var out []netip.AddrPort
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || a == protocol.MagicDNSAddr || a == protocol.MagicDNSAddr6 {
			continue
		}
		out = append(out, netip.AddrPortFrom(a, 53))
	}
	return out
}

func orAll(d []string) any {
	if len(d) == 0 {
		return "all names"
	}
	if len(d) > 3 {
		return fmt.Sprintf("%s and %d reverse zones", d[0], len(d)-1)
	}
	return d
}

// reverseZones covers PTR lookups for all tunnel addresses.
func reverseZones() []string {
	return append(dns.ReverseZones(ipam.DefaultV4), dns.ReverseZones(ipam.DefaultV6)...)
}

// SetRelayTLS sets how relays' HTTPS certificates are checked (nil = the
// usual checks); see tlspin for pinned self-signed certificates.
func (e *Engine) SetRelayTLS(cfg *tls.Config) { e.magic.SetRelayTLS(cfg) }

// DNSStatus describes MagicDNS on this node.
type DNSStatus struct {
	Domain string // this machine's domain, e.g. "acme.home.internal" ("" when MagicDNS is off)
	Base   string // the domain sent to MagicDNS, e.g. "home.internal"
	Mode   string // how the host is configured ("systemd-resolved", "file", "off")
	Split  bool   // only MagicDNS names are sent to the resolver
	Error  string // last host configuration error
}

func (e *Engine) DNSStatus() DNSStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return DNSStatus{Domain: e.dnsDomain, Base: e.dnsBase, Mode: e.osDNS.Mode(), Split: len(e.lastOSDNS.MatchDomains) > 0, Error: e.dnsErr}
}

// kickHandshake makes WireGuard send a keepalive to k, which starts a
// handshake if there is no current session. wireguard-go has no direct API
// for this: turning persistent keepalive on sends one immediately, and we
// turn it straight off again.
func (e *Engine) kickHandshake(k key.NodePublic) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.peers[k]; !ok || e.closed {
		return
	}
	raw := k.Raw()
	pk := hex.EncodeToString(raw[:])
	if err := e.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=25\n", pk)); err != nil {
		e.logf("kick handshake with %s: %v", k.ShortString(), err)
		return
	}
	_ = e.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=0\n", pk))
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// ListenPort returns the UDP port WireGuard is bound to.
func (e *Engine) ListenPort() uint16 {
	s, err := e.dev.IpcGet()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			p, _ := strconv.ParseUint(v, 10, 16)
			return uint16(p)
		}
	}
	return 0
}

type PeerStats struct {
	// Endpoint is the trusted direct address, if any; otherwise Relay is the
	// relay region carrying the traffic.
	Endpoint      netip.AddrPort
	Relay         int
	Latency       time.Duration // disco round trip on the direct path, if measured
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Stats reports per-peer WireGuard counters and the current path.
func (e *Engine) Stats() map[key.NodePublic]PeerStats {
	out := map[key.NodePublic]PeerStats{}
	defer func() {
		for k, pi := range e.magic.Paths() {
			st := out[k]
			st.Endpoint, st.Relay, st.Latency = pi.Direct, pi.Relay, pi.Latency
			out[k] = st
		}
	}()
	s, err := e.dev.IpcGet()
	if err != nil {
		return out
	}
	var cur key.NodePublic
	var st PeerStats
	var hsSec, hsNsec int64
	flush := func() {
		if !cur.IsZero() {
			if hsSec != 0 || hsNsec != 0 {
				st.LastHandshake = time.Unix(hsSec, hsNsec)
			}
			out[cur] = st
		}
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			var raw [32]byte
			if b, err := hex.DecodeString(v); err == nil && len(b) == 32 {
				copy(raw[:], b)
			}
			cur, st, hsSec, hsNsec = key.PublicFromRaw[key.NodeKind](raw), PeerStats{}, 0, 0
		case "last_handshake_time_sec":
			hsSec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			hsNsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	flush()
	return out
}

// FilterDropped counts packets the one-way sharing filter refused.
func (e *Engine) FilterDropped() int64 { return e.filter.Dropped() }
