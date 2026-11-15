// Package magicsock is TailConnect's WireGuard transport (a conn.Bind). It
// decides, packet by packet, how to reach each peer:
//
//   - directly over UDP, once a direct path is trusted: confirmed by a disco
//     pong or by the peer's WireGuard packets arriving on it, or
//   - via the peer's relay server, while path discovery (see discovery.go)
//     looks for a direct path, including through NATs.
//
// WireGuard is configured with each peer's endpoint set to the peer's node
// key (see Endpoint) and with roaming disabled, so every packet for a peer
// comes through Send and path selection stays here.
//
// Received UDP packets are attributed to peers by WireGuard session index,
// not by source address: magicsock records the sender index in every
// handshake message it sends to a peer, and the peer's responses, cookie
// replies and data packets carry that index as their receiver index. This
// stays correct when several peers share an external address (NAT), and it
// lets a NAT-mapped address become a direct path.
//
// The WireGuard UDP socket also carries STUN (to learn public addresses)
// and disco (path discovery) packets; they are demultiplexed on receive.
package magicsock

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"tailconnect/internal/disco"
	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
	"tailconnect/internal/relay"
	"tailconnect/internal/stun"
)

// A direct path is trusted (used exclusively) while both hold:
//   - a packet arrived on it within TrustWindow, and
//   - we have not been sending on it for longer than UnansweredLimit without
//     anything coming back.
//
// The second rule detects a path that died mid-session in ~3s: live traffic
// (TCP ACKs, ping replies, WireGuard's passive keepalives) answers quickly.
const (
	TrustWindow     = 15 * time.Second
	UnansweredLimit = 3 * time.Second
)

var errNoPath = errors.New("magicsock: no path to peer")

type Options struct {
	PrivateKey key.NodePrivate
	// DiscoKey enables path discovery (disco). Without it, magicsock still
	// works but only finds direct paths that peers' traffic reveals.
	DiscoKey key.DiscoPrivate
	Logf     func(format string, args ...any)
	// OnEndpointsChanged is called (in its own goroutine) when this node's
	// advertised endpoints change, e.g. a new public address from STUN.
	OnEndpointsChanged func()
}

type Conn struct {
	logf        func(string, ...any)
	priv        key.NodePrivate
	disco       key.DiscoPrivate
	onEndpoints func()
	stop        chan struct{}
	loopDone    chan struct{}

	relayRecv chan relayPacket // from all relay clients; persists across Open/Close

	mu        sync.Mutex
	peers     map[key.NodePublic]*peer
	indexes   map[uint32]indexEntry // our WireGuard session indices → peer
	relayBase *url.URL
	relayMap  protocol.RelayMap
	relays    map[int]*relay.Client
	home      int
	pconn     *net.UDPConn
	closing   chan struct{} // closed by Close; ends the current ReceiveFuncs
	shutdown  bool

	byDisco       map[key.DiscoPublic]*peer
	pings         map[disco.TxID]pendingPing
	local         []netip.AddrPort // local interface endpoints
	stunTx        map[stun.TxID]stunRequest
	stunAddrs     map[int]netip.AddrPort // public address seen by each region's STUN server
	regionLatency map[int]time.Duration
	lastSTUN      time.Time
}

type indexEntry struct {
	peer    key.NodePublic
	created time.Time
}

// indexTTL bounds how long a session index is remembered. WireGuard
// keypairs are rejected after 180s, so older indices are dead.
const indexTTL = 5 * time.Minute

type relayPacket struct {
	src  key.NodePublic
	data []byte
}

type peer struct {
	key        key.NodePublic
	ep         *Endpoint
	discoKey   key.DiscoPublic
	candidates []netip.AddrPort // as reported through control
	best       netip.AddrPort   // best guess among candidates, before discovery
	homeRelay  int
	eps        map[netip.AddrPort]*epState

	lastActive      time.Time // data sent to or received from the peer
	lastPingAll     time.Time
	lastCallMeMaybe time.Time
	latency         time.Duration // of directAddr, from disco

	directAddr      netip.AddrPort
	lastDirectRecv  time.Time
	firstUnanswered time.Time // first direct send since the last direct receive
	lastRelayRecv   time.Time
	txDirect        uint64
	txRelay         uint64
}

func New(opts Options) *Conn {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	c := &Conn{
		logf:          opts.Logf,
		priv:          opts.PrivateKey,
		disco:         opts.DiscoKey,
		onEndpoints:   opts.OnEndpointsChanged,
		stop:          make(chan struct{}),
		loopDone:      make(chan struct{}),
		relayRecv:     make(chan relayPacket, 512),
		peers:         map[key.NodePublic]*peer{},
		indexes:       map[uint32]indexEntry{},
		relays:        map[int]*relay.Client{},
		byDisco:       map[key.DiscoPublic]*peer{},
		pings:         map[disco.TxID]pendingPing{},
		stunTx:        map[stun.TxID]stunRequest{},
		stunAddrs:     map[int]netip.AddrPort{},
		regionLatency: map[int]time.Duration{},
	}
	go c.loop()
	return c
}

func newPeer(k key.NodePublic) *peer {
	return &peer{key: k, ep: &Endpoint{key: k}, eps: map[netip.AddrPort]*epState{}}
}

// ---- endpoints ----

// Endpoint identifies a peer by node key. WireGuard holds one per peer.
type Endpoint struct{ key key.NodePublic }

func (e *Endpoint) ClearSrc()           {}
func (e *Endpoint) SrcToString() string { return "" }
func (e *Endpoint) DstToString() string { return e.key.String() }
func (e *Endpoint) DstToBytes() []byte  { r := e.key.Raw(); return r[:] }
func (e *Endpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// rawEndpoint is a UDP address not (yet) attributed to a peer. WireGuard
// only uses it to answer handshakes under load (cookie replies).
type rawEndpoint struct{ ap netip.AddrPort }

func (e *rawEndpoint) ClearSrc()           {}
func (e *rawEndpoint) SrcToString() string { return "" }
func (e *rawEndpoint) DstToString() string { return e.ap.String() }
func (e *rawEndpoint) DstToBytes() []byte  { b, _ := e.ap.MarshalBinary(); return b }
func (e *rawEndpoint) DstIP() netip.Addr   { return e.ap.Addr() }
func (e *rawEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// ---- network map ----

// SetRelayBase sets the URL that relative relay URLs (the relay embedded in
// tc-control) are resolved against: the control server URL.
func (c *Conn) SetRelayBase(controlURL string) error {
	u, err := url.Parse(controlURL)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.relayBase = u
	return nil
}

// SetNetworkMap updates peers, their candidate endpoints and the relay map.
// local lists this host's attached prefixes, used to choose a peer's
// best-guess direct address.
func (c *Conn) SetNetworkMap(peers []protocol.Node, relays protocol.RelayMap, local []netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shutdown {
		return
	}
	if !relayMapEqual(c.relayMap, relays) {
		c.relayMap = relays
		c.lastSTUN = time.Time{} // measure the new regions soon
		for id := range c.regionLatency {
			if _, ok := c.regionURL(id); !ok {
				delete(c.regionLatency, id)
				delete(c.stunAddrs, id)
			}
		}
	}
	c.updateRelaysLocked()

	want := map[key.NodePublic]bool{}
	for _, n := range peers {
		if n.NodeKey.IsZero() {
			continue
		}
		want[n.NodeKey] = true
		p := c.peers[n.NodeKey]
		if p == nil {
			p = newPeer(n.NodeKey)
			c.peers[n.NodeKey] = p
		}
		if !slices.Equal(p.candidates, n.Endpoints) && p.candidates != nil {
			// The peer's network changed (restart, new port, Wi-Fi switch):
			// its old direct path is suspect until confirmed again.
			p.directAddr, p.firstUnanswered = netip.AddrPort{}, time.Time{}
			p.lastPingAll = time.Time{}
			for _, ep := range p.eps {
				ep.lastPong, ep.latency = time.Time{}, 0
			}
		}
		p.candidates = slices.Clone(n.Endpoints)
		p.best, _ = PickEndpoint(n.Endpoints, local)
		p.homeRelay = n.HomeRelay
		p.discoKey = n.DiscoKey
		for _, ep := range p.eps {
			ep.netmap = false
		}
		for _, a := range n.Endpoints {
			a = unmap(a)
			if !usableAddr(a) {
				continue
			}
			if p.eps[a] == nil {
				p.eps[a] = &epState{}
			}
			p.eps[a].netmap = true
		}
	}
	for k := range c.peers {
		if !want[k] {
			delete(c.peers, k)
		}
	}
	c.byDisco = map[key.DiscoPublic]*peer{}
	for _, p := range c.peers {
		if !p.discoKey.IsZero() {
			c.byDisco[p.discoKey] = p
		}
	}
}

func relayMapEqual(a, b protocol.RelayMap) bool {
	return slices.EqualFunc(a.Regions, b.Regions, func(x, y protocol.RelayRegion) bool {
		return x.ID == y.ID && slices.Equal(x.Nodes, y.Nodes)
	})
}

// HomeRelay is the relay region this node is reachable through (0 = none).
func (c *Conn) HomeRelay() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.home
}

// RelayConnected reports whether the home relay connection is up.
func (c *Conn) RelayConnected() bool {
	c.mu.Lock()
	rc := c.relays[c.home]
	c.mu.Unlock()
	return rc != nil && rc.Connected()
}

func (c *Conn) regionURL(id int) (string, bool) {
	for _, r := range c.relayMap.Regions {
		if r.ID != id || len(r.Nodes) == 0 {
			continue
		}
		ref, err := url.Parse(r.Nodes[0].URL)
		if err != nil {
			return "", false
		}
		if !ref.IsAbs() {
			if c.relayBase == nil {
				return "", false
			}
			ref = c.relayBase.ResolveReference(ref)
		}
		return ref.String(), true
	}
	return "", false
}

// updateRelaysLocked picks the home region (see chooseHomeLocked), connects
// to it, and drops clients for removed regions.
func (c *Conn) updateRelaysLocked() {
	home := c.chooseHomeLocked()
	if home != c.home {
		if lat, ok := c.regionLatency[home]; ok {
			c.logf("magicsock: home relay region %d → %d (%v)", c.home, home, lat.Round(time.Millisecond))
		} else {
			c.logf("magicsock: home relay region %d → %d", c.home, home)
		}
		c.home = home
		c.notifyEndpointsLocked() // the home relay is advertised alongside endpoints
	}
	for id, rc := range c.relays {
		u, ok := c.regionURL(id)
		if !ok || u != rc.URL() {
			go rc.Close()
			delete(c.relays, id)
		}
	}
	if home != 0 {
		c.relayClientLocked(home)
	}
}

// relayClientLocked returns (creating if needed) the client for region id.
func (c *Conn) relayClientLocked(id int) *relay.Client {
	if id == 0 {
		id = c.home
	}
	if id == 0 {
		return nil
	}
	if rc := c.relays[id]; rc != nil {
		return rc
	}
	u, ok := c.regionURL(id)
	if !ok {
		return nil
	}
	rc, err := relay.NewClient(relay.ClientOptions{
		URL:     u,
		NodeKey: c.priv,
		Logf:    c.logf,
		Recv: func(src key.NodePublic, pkt []byte) {
			select {
			case c.relayRecv <- relayPacket{src: src, data: slices.Clone(pkt)}:
			default: // WireGuard is not keeping up; drop
			}
		},
	})
	if err != nil {
		c.logf("magicsock: relay region %d: %v", id, err)
		return nil
	}
	c.relays[id] = rc
	return rc
}

// ---- conn.Bind ----

var _ conn.Bind = (*Conn)(nil)

func (c *Conn) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shutdown {
		return nil, 0, net.ErrClosed
	}
	if c.pconn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)}) // dual-stack where available
	if err != nil {
		if pc, err = net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)}); err != nil {
			return nil, 0, err
		}
	}
	c.pconn = pc
	c.closing = make(chan struct{})
	actual := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{c.receiveUDP(pc), c.receiveRelay(c.closing)}, actual, nil
}

func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pconn != nil {
		c.pconn.Close()
		c.pconn = nil
	}
	if c.closing != nil {
		close(c.closing)
		c.closing = nil
	}
	return nil
}

// Shutdown closes the bind and all relay connections. The Conn is unusable afterwards.
func (c *Conn) Shutdown() {
	c.Close()
	c.mu.Lock()
	if c.shutdown {
		c.mu.Unlock()
		return
	}
	close(c.stop)
	c.shutdown = true
	rs := c.relays
	c.relays = map[int]*relay.Client{}
	c.mu.Unlock()
	for _, rc := range rs {
		rc.Close()
	}
	<-c.loopDone
}

func (c *Conn) SetMark(uint32) error { return nil }
func (c *Conn) BatchSize() int       { return 1 }

func (c *Conn) ParseEndpoint(s string) (conn.Endpoint, error) {
	if k, err := key.ParsePublic[key.NodeKind](s); err == nil && !k.IsZero() {
		c.mu.Lock()
		defer c.mu.Unlock()
		p := c.peers[k]
		if p == nil {
			p = newPeer(k)
			c.peers[k] = p
		}
		return p.ep, nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("magicsock: bad endpoint %q", s)
	}
	return &rawEndpoint{ap: unmap(ap)}, nil
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (c *Conn) receiveUDP(pc *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, ap, err := pc.ReadFromUDPAddrPort(packets[0])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return 0, net.ErrClosed
				}
				return 0, err
			}
			ap = unmap(ap)
			b := packets[0][:n]
			c.mu.Lock()
			switch {
			case stun.IsResponse(b):
				c.handleSTUNLocked(b)
				c.mu.Unlock()
				continue
			case disco.Looks(b):
				c.handleDiscoLocked(b, ap, false, key.NodePublic{})
				c.mu.Unlock()
				continue
			}
			sizes[0] = n
			if p := c.attributeLocked(b); p != nil {
				now := time.Now()
				// The peer's WireGuard traffic proves this path. Adopt it unless
				// discovery has already chosen a (better) path that still works.
				if ap == p.directAddr || !p.trusted(now) {
					p.directAddr, p.lastDirectRecv, p.firstUnanswered = ap, now, time.Time{}
				}
				if wgType(b) == wgTransport {
					p.lastActive = now
				}
				eps[0] = p.ep
			} else {
				eps[0] = &rawEndpoint{ap: ap}
			}
			c.mu.Unlock()
			return 1, nil
		}
	}
}

func (c *Conn) receiveRelay(closing chan struct{}) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			select {
			case <-closing:
				return 0, net.ErrClosed
			case rp := <-c.relayRecv:
				c.mu.Lock()
				if disco.Looks(rp.data) {
					c.handleDiscoLocked(rp.data, netip.AddrPort{}, true, rp.src)
					c.mu.Unlock()
					continue
				}
				sizes[0] = copy(packets[0], rp.data)
				if p := c.peers[rp.src]; p != nil {
					now := time.Now()
					p.lastRelayRecv = now
					if wgType(rp.data) == wgTransport {
						p.lastActive = now
					}
					if p.noteRelayRecv(now) {
						c.logf("magicsock: %s is using the relay; direct path to it suspect", p.key.ShortString())
					}
					eps[0] = p.ep
				} else {
					eps[0] = &Endpoint{key: rp.src}
				}
				c.mu.Unlock()
				return 1, nil
			}
		}
	}
}

func (c *Conn) Send(bufs [][]byte, ep conn.Endpoint) error {
	switch e := ep.(type) {
	case *Endpoint:
		return c.sendPeer(e.key, bufs)
	case *rawEndpoint:
		c.mu.Lock()
		pc := c.pconn
		c.mu.Unlock()
		if pc == nil {
			return net.ErrClosed
		}
		for _, b := range bufs {
			if _, err := pc.WriteToUDPAddrPort(b, e.ap); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("magicsock: unexpected endpoint type %T", ep)
	}
}

func (c *Conn) sendPeer(k key.NodePublic, bufs [][]byte) error {
	c.mu.Lock()
	p := c.peers[k]
	if p == nil {
		c.mu.Unlock()
		return errNoPath
	}
	pc := c.pconn
	now := time.Now()
	for _, b := range bufs {
		c.noteSentLocked(k, b, now)
		if wgType(b) == wgTransport {
			p.lastActive = now
		}
	}
	if p.trusted(now) {
		addr := p.directAddr
		if p.firstUnanswered.IsZero() {
			p.firstUnanswered = now
		}
		p.txDirect += uint64(len(bufs))
		c.mu.Unlock()
		if pc == nil {
			return net.ErrClosed
		}
		for _, b := range bufs {
			if _, err := pc.WriteToUDPAddrPort(b, addr); err != nil {
				return err
			}
		}
		return nil
	}
	// Keep trying the last working direct address (or the best guess) so the
	// direct path recovers as soon as it works again.
	spray := p.best
	if p.directAddr.IsValid() {
		spray = p.directAddr
	}
	rc := c.relayClientLocked(p.homeRelay)
	c.discoverLocked(p, now, true) // look for a direct path now, not at the next tick
	c.mu.Unlock()

	sent := false
	var lastErr error = errNoPath
	if spray.IsValid() && pc != nil {
		for _, b := range bufs {
			if _, err := pc.WriteToUDPAddrPort(b, spray); err == nil {
				sent = true
			} else {
				lastErr = err
			}
		}
	}
	viaRelay := false
	if rc != nil {
		for _, b := range bufs {
			if err := rc.Send(k, b); err == nil {
				viaRelay = true
			} else {
				lastErr = err
			}
		}
	}
	if viaRelay {
		c.mu.Lock()
		p.txRelay += uint64(len(bufs))
		c.mu.Unlock()
	}
	if sent || viaRelay {
		return nil
	}
	return lastErr
}

// ---- status ----

type PathInfo struct {
	// Direct is the trusted direct address, if the peer is reachable directly.
	Direct netip.AddrPort
	// Relay is the relay region in use when there is no trusted direct path.
	Relay int
	// Latency is the disco round-trip time on the direct path, if measured.
	Latency        time.Duration
	LastDirectRecv time.Time
	LastRelayRecv  time.Time
	TxDirect       uint64
	TxRelay        uint64
}

// Paths reports the current path to each peer.
func (c *Conn) Paths() map[key.NodePublic]PathInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	out := make(map[key.NodePublic]PathInfo, len(c.peers))
	for k, p := range c.peers {
		pi := PathInfo{LastDirectRecv: p.lastDirectRecv, LastRelayRecv: p.lastRelayRecv, TxDirect: p.txDirect, TxRelay: p.txRelay}
		if p.trusted(now) {
			pi.Direct = p.directAddr
			if ep := p.eps[p.directAddr]; ep != nil && now.Sub(ep.lastPong) < TrustWindow {
				pi.Latency = ep.latency
			}
		} else {
			pi.Relay = p.homeRelay
			if pi.Relay == 0 {
				pi.Relay = c.home
			}
		}
		out[k] = pi
	}
	return out
}

// WireGuard message types and where they carry session indices
// (little-endian): initiation and response have the sender's index at
// [4:8]; the response has the receiver's index at [8:12]; cookie replies and
// data packets have the receiver's index at [4:8].
const (
	wgInitiation = 1
	wgResponse   = 2
	wgCookie     = 3
	wgTransport  = 4
)

func wgType(b []byte) byte {
	if len(b) < 4 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0
	}
	return b[0]
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// noteSentLocked records the session index in a handshake message we send to k.
func (c *Conn) noteSentLocked(k key.NodePublic, b []byte, now time.Time) {
	switch wgType(b) {
	case wgInitiation, wgResponse:
		if len(b) < 8 {
			return
		}
		if len(c.indexes) > 4096 {
			for i, e := range c.indexes {
				if now.Sub(e.created) > indexTTL {
					delete(c.indexes, i)
				}
			}
		}
		c.indexes[le32(b[4:8])] = indexEntry{peer: k, created: now}
	}
}

// attributeLocked returns the peer a received WireGuard packet belongs to,
// by the receiver index it carries, or nil.
func (c *Conn) attributeLocked(b []byte) *peer {
	var idx uint32
	switch wgType(b) {
	case wgTransport, wgCookie:
		if len(b) < 8 {
			return nil
		}
		idx = le32(b[4:8])
	case wgResponse:
		if len(b) < 12 {
			return nil
		}
		idx = le32(b[8:12])
	default:
		return nil // initiations carry no index of ours
	}
	e, ok := c.indexes[idx]
	if !ok || time.Since(e.created) > indexTTL {
		return nil
	}
	return c.peers[e.peer]
}

// relayGrace: a peer that sent us a packet directly this recently can still
// use the direct path, even if it is also sending through the relay (as it
// does while discovering paths).
const relayGrace = time.Second

// noteRelayRecv handles a WireGuard packet from p that came through the
// relay. A peer only uses the relay when it doesn't trust the direct path,
// so if nothing has arrived directly for a while, stop trusting it too:
// otherwise we keep sending into a dead path until our own UnansweredLimit
// runs out, doubling the failover time. If the path does work for us, our
// next direct packet makes the peer adopt it again. Reports whether trust
// was withdrawn.
func (p *peer) noteRelayRecv(now time.Time) bool {
	if !p.trusted(now) || now.Sub(p.lastDirectRecv) < relayGrace {
		return false
	}
	p.firstUnanswered = now.Add(-UnansweredLimit)
	return true
}

func (p *peer) trusted(now time.Time) bool {
	return p.directAddr.IsValid() && now.Sub(p.lastDirectRecv) < TrustWindow &&
		(p.firstUnanswered.IsZero() || now.Sub(p.firstUnanswered) < UnansweredLimit)
}

// PickEndpoint chooses a best-guess direct address among a peer's reported
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
				return unmap(c), true
			}
		}
	}
	for _, c := range cands {
		if usable(c) && c.Addr().Unmap().Is4() {
			return unmap(c), true
		}
	}
	for _, c := range cands {
		if usable(c) {
			return unmap(c), true
		}
	}
	return netip.AddrPort{}, false
}
