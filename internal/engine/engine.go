// Package engine drives the WireGuard data plane: it owns a wireguard-go
// device on a TUN interface and turns network maps into peer configuration,
// interface addresses and routes.
//
// Peer changes are applied as diffs, so a map update never tears down
// sessions with unchanged peers. In milestone 2 each peer gets a static
// endpoint chosen from the addresses it reported; WireGuard's own roaming
// then follows the peer if it sends from elsewhere. Milestones 3–4 replace
// this with magicsock (relay fallback and NAT traversal).
package engine

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

// DefaultMTU leaves room for WireGuard overhead on links with MTU ≥ 1360,
// including IPv6 underlays and PPPoE.
const DefaultMTU = 1280

// DefaultPort is the default WireGuard UDP port.
const DefaultPort = 41641

// keepalive keeps NAT/firewall mappings open. (Battery tuning for Android comes later.)
const keepalive = 25

type RouterConfig struct {
	LocalAddrs []netip.Prefix // this node's tunnel addresses
	Routes     []netip.Prefix // destinations to send into the tunnel
}

func (c RouterConfig) equal(o RouterConfig) bool {
	return slices.Equal(c.LocalAddrs, o.LocalAddrs) && slices.Equal(c.Routes, o.Routes)
}

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
	Router     Router    // nil = NoopRouter
	Bind       conn.Bind // nil = OS UDP sockets
	ListenPort uint16    // 0 = random
	Logf       func(format string, args ...any)
	Verbose    bool // log wireguard-go internals
}

type peerState struct {
	allowed    []netip.Prefix
	candidates []netip.AddrPort
}

type Engine struct {
	dev    *device.Device
	router Router
	logf   func(string, ...any)
	pub    key.NodePublic

	mu         sync.Mutex
	peers      map[key.NodePublic]peerState
	lastRouter RouterConfig
	closed     bool
}

// New brings up a WireGuard device with the node's private key.
func New(cfg Config, priv key.NodePrivate) (*Engine, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Router == nil {
		cfg.Router = NoopRouter{}
	}
	if cfg.Bind == nil {
		cfg.Bind = conn.NewDefaultBind()
	}
	wgLog := &device.Logger{Verbosef: device.DiscardLogf, Errorf: prefixed(cfg.Logf, "wg: ")}
	if cfg.Verbose {
		wgLog.Verbosef = prefixed(cfg.Logf, "wg: ")
	}
	dev := device.NewDevice(cfg.TUN, cfg.Bind, wgLog)
	raw := priv.Raw()
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(raw[:]), cfg.ListenPort)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("engine: configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("engine: bring device up: %w", err)
	}
	return &Engine{dev: dev, router: cfg.Router, logf: cfg.Logf, pub: priv.Public(), peers: map[key.NodePublic]peerState{}}, nil
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
	if err := e.router.Close(); err != nil {
		e.logf("router close: %v", err)
	}
	e.dev.Close()
}

// Reconfig applies a network map. local lists this host's interface prefixes,
// used to prefer a peer endpoint on a directly attached subnet.
func (e *Engine) Reconfig(nm *protocol.MapResponse, local []netip.Prefix) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return fmt.Errorf("engine closed")
	}

	var b strings.Builder
	want := map[key.NodePublic]bool{}
	var routes []netip.Prefix
	for _, p := range nm.Peers {
		if p.NodeKey.IsZero() || p.NodeKey.Equal(e.pub) {
			continue
		}
		want[p.NodeKey] = true
		allowed := slices.Clone(p.Addresses)
		slices.SortFunc(allowed, comparePrefix)
		routes = append(routes, allowed...)
		cands := slices.Clone(p.Endpoints)

		old, exists := e.peers[p.NodeKey]
		allowedChanged := !exists || !slices.Equal(old.allowed, allowed)
		candsChanged := !exists || !slices.Equal(old.candidates, cands)
		if !allowedChanged && !candsChanged {
			continue
		}
		raw := p.NodeKey.Raw()
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(raw[:]))
		if exists {
			b.WriteString("update_only=true\n")
		} else {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
		}
		if allowedChanged {
			b.WriteString("replace_allowed_ips=true\n")
			for _, a := range allowed {
				fmt.Fprintf(&b, "allowed_ip=%s\n", a)
			}
		}
		// Only (re)set the endpoint when the peer's reported addresses change,
		// so we don't undo WireGuard's roaming to where the peer actually is.
		if candsChanged {
			if ep, ok := PickEndpoint(cands, local); ok {
				fmt.Fprintf(&b, "endpoint=%s\n", ep)
			}
		}
		e.peers[p.NodeKey] = peerState{allowed: allowed, candidates: cands}
		e.logf("peer %s (%s): allowed=%v endpoints=%v", p.Name, p.NodeKey.ShortString(), allowed, cands)
	}
	for k := range e.peers {
		if !want[k] {
			raw := k.Raw()
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", hex.EncodeToString(raw[:]))
			delete(e.peers, k)
			e.logf("peer %s removed", k.ShortString())
		}
	}
	if b.Len() > 0 {
		if err := e.dev.IpcSet(b.String()); err != nil {
			return fmt.Errorf("engine: apply peers: %w", err)
		}
	}

	slices.SortFunc(routes, comparePrefix)
	self := slices.Clone(nm.Self.Addresses)
	slices.SortFunc(self, comparePrefix)
	rc := RouterConfig{LocalAddrs: self, Routes: routes}
	if !rc.equal(e.lastRouter) {
		if err := e.router.Set(rc); err != nil {
			return fmt.Errorf("engine: router: %w", err)
		}
		e.lastRouter = rc
	}
	return nil
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// PickEndpoint chooses one address to send to among a peer's reported
// endpoints: one on a directly attached subnet if possible, else the first
// usable IPv4, else the first usable address.
func PickEndpoint(cands []netip.AddrPort, local []netip.Prefix) (netip.AddrPort, bool) {
	usable := func(ap netip.AddrPort) bool {
		a := ap.Addr()
		return ap.IsValid() && ap.Port() != 0 && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLinkLocalUnicast()
	}
	for _, c := range cands {
		if !usable(c) {
			continue
		}
		for _, l := range local {
			if l.Contains(c.Addr().Unmap()) {
				return c, true
			}
		}
	}
	for _, c := range cands {
		if usable(c) && c.Addr().Unmap().Is4() {
			return c, true
		}
	}
	for _, c := range cands {
		if usable(c) {
			return c, true
		}
	}
	return netip.AddrPort{}, false
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
	Endpoint      netip.AddrPort
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Stats reports per-peer WireGuard counters.
func (e *Engine) Stats() map[key.NodePublic]PeerStats {
	out := map[key.NodePublic]PeerStats{}
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
		case "endpoint":
			st.Endpoint, _ = netip.ParseAddrPort(v)
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
