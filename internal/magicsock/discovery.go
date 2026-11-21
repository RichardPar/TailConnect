package magicsock

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"time"

	"tailconnect/internal/disco"
	"tailconnect/internal/key"
	"tailconnect/internal/stun"
)

// Path discovery.
//
// While a peer is active (we exchanged data in the last activeWindow) and
// has no trusted direct path, magicsock pings every candidate endpoint with
// disco pings and asks the peer, via the relay, to ping ours (CallMeMaybe).
// Both sides sending at once opens NAT mappings in both directions; the
// first authenticated pong confirms a path, with its latency. Pings received
// from a peer teach us its address as seen from here (often a NAT mapping)
// and are answered and pinged back. Once a path is trusted, a heartbeat ping
// every few seconds keeps it, and the NAT mapping, alive while active.
//
// STUN requests to each relay region, sent from the WireGuard socket, reveal
// this node's public address(es); they are advertised as endpoints and
// their round-trip times choose the home relay.
const (
	activeWindow        = 45 * time.Second
	heartbeatInterval   = 3 * time.Second
	discoverInterval    = 3 * time.Second
	callMeMaybeInterval = 5 * time.Second
	pingTimeout         = 5 * time.Second
	learnedTTL          = 2 * time.Minute
	// pongFresh: only endpoints that answered this recently compete to be
	// the direct path (a bit over two heartbeats).
	pongFresh        = 6500 * time.Millisecond
	stunInterval     = 23 * time.Second
	maxPeerEndpoints = 64
	// homeRelayHysteresis: switch home relay only if another region is this
	// much faster, so the home region doesn't flap between similar regions.
	homeRelayHysteresis = 0.7
)

type epState struct {
	netmap   bool      // reported by the peer through control
	learned  time.Time // last seen in a ping from the peer or a CallMeMaybe
	lastPing time.Time
	lastPong time.Time
	latency  time.Duration
}

type pendingPing struct {
	peer key.NodePublic
	to   netip.AddrPort
	sent time.Time
}

type stunRequest struct {
	region int
	server netip.Addr
	sent   time.Time
}

// cgnatPrefix is the shared address space (RFC 6598) carriers use for CGNAT.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isPublicAddr reports whether a is globally routable: not private, CGNAT,
// loopback, link-local or unspecified.
func isPublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() && !cgnatPrefix.Contains(a)
}

// debugDisco logs every disco message when TC_DISCO_DEBUG is set.
var debugDisco = os.Getenv("TC_DISCO_DEBUG") != ""

func usableAddr(ap netip.AddrPort) bool {
	a := ap.Addr()
	return ap.IsValid() && ap.Port() != 0 && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLinkLocalUnicast()
}

func (c *Conn) loop() {
	defer close(c.loopDone)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.tick()
		}
	}
}

func (c *Conn) tick() {
	now := time.Now()
	c.mu.Lock()
	if c.shutdown {
		c.mu.Unlock()
		return
	}
	for tx, pp := range c.pings {
		if now.Sub(pp.sent) > pingTimeout {
			delete(c.pings, tx)
		}
	}
	for tx, sr := range c.stunTx {
		if now.Sub(sr.sent) > pingTimeout {
			delete(c.stunTx, tx)
		}
	}
	for _, p := range c.peers {
		for a, ep := range p.eps {
			if !ep.netmap && a != p.directAddr && now.Sub(ep.learned) > learnedTTL {
				delete(p.eps, a)
			}
		}
		if p.discoKey.IsZero() || now.Sub(p.lastActive) > activeWindow {
			continue
		}
		if p.trusted(now) {
			if ep := p.eps[p.directAddr]; ep == nil || now.Sub(ep.lastPing) >= heartbeatInterval {
				c.sendPingLocked(p, p.directAddr, now)
			}
		} else {
			c.discoverLocked(p, now, false)
		}
	}
	var targets []stunTarget
	if now.Sub(c.lastSTUN) >= stunInterval {
		c.lastSTUN = now
		targets = c.stunTargetsLocked()
	}
	c.mu.Unlock()
	if len(targets) > 0 {
		go c.sendSTUN(targets)
	}
}

// discoverLocked pings all of p's candidate endpoints and, via the relay,
// asks p to ping ours. force (a CallMeMaybe or the first packet to an
// untrusted peer) bypasses the normal interval but not a 1s floor.
func (c *Conn) discoverLocked(p *peer, now time.Time, force bool) {
	if p.discoKey.IsZero() {
		return
	}
	since := now.Sub(p.lastPingAll)
	if since < time.Second || (!force && since < discoverInterval) {
		return
	}
	p.lastPingAll = now
	for a := range p.eps {
		if usableAddr(a) {
			c.sendPingLocked(p, a, now)
		}
	}
	if now.Sub(p.lastCallMeMaybe) >= callMeMaybeInterval {
		if eps := c.endpointsLocked(); len(eps) > 0 {
			p.lastCallMeMaybe = now
			c.sendDiscoRelayLocked(p, &disco.CallMeMaybe{Endpoints: eps})
		}
	}
}

func (c *Conn) sendPingLocked(p *peer, to netip.AddrPort, now time.Time) {
	if c.socks == nil || p.discoKey.IsZero() || c.disco.IsZero() {
		return
	}
	tx := disco.NewTxID()
	c.pings[tx] = pendingPing{peer: p.key, to: to, sent: now}
	if ep := p.eps[to]; ep != nil {
		ep.lastPing = now
	}
	pkt := disco.Seal(c.disco, p.discoKey, &disco.Ping{TxID: tx, NodeKey: c.priv.Public()})
	err := c.socks.write([][]byte{pkt}, to)
	if debugDisco {
		c.logf("disco: ping → %s at %v (err=%v)", p.key.ShortString(), to, err)
	}
}

func (c *Conn) sendDiscoRelayLocked(p *peer, m disco.Message) {
	if c.disco.IsZero() {
		return
	}
	if rc := c.relayClientLocked(p.homeRelay); rc != nil {
		err := rc.Send(p.key, disco.Seal(c.disco, p.discoKey, m))
		if debugDisco {
			c.logf("disco: %T → %s via relay (err=%v)", m, p.key.ShortString(), err)
		}
	}
}

// handleDiscoLocked processes a disco packet received directly from src, or
// via the relay from node relaySrc (the relay authenticated that node key).
func (c *Conn) handleDiscoLocked(pkt []byte, src netip.AddrPort, viaRelay bool, relaySrc key.NodePublic) {
	sender, ok := disco.Sender(pkt)
	if !ok || c.disco.IsZero() {
		return
	}
	p := c.byDisco[sender]
	if p == nil || (viaRelay && !p.key.Equal(relaySrc)) {
		if debugDisco {
			c.logf("disco: packet from unknown disco key %v (known=%d)", sender.ShortString(), len(c.byDisco))
		}
		return
	}
	msg, err := disco.Open(c.disco, sender, pkt)
	if err != nil {
		if debugDisco {
			c.logf("disco: bad packet from %s: %v", p.key.ShortString(), err)
		}
		return
	}
	if debugDisco {
		c.logf("disco: %T ← %s from %v (relay=%v)", msg, p.key.ShortString(), src, viaRelay)
	}
	now := time.Now()
	switch m := msg.(type) {
	case *disco.Ping:
		if viaRelay || !m.NodeKey.Equal(p.key) {
			return
		}
		// Each ping has a fresh random TxID. One seen recently is a
		// recording sent again (perhaps from a forged source, to aim our
		// pong at someone): ignore it.
		if !c.notePingLocked(m.TxID, now) {
			return
		}
		ep := c.learnLocked(p, src, now)
		if c.socks != nil {
			c.socks.write([][]byte{disco.Seal(c.disco, p.discoKey, &disco.Pong{TxID: m.TxID, Src: src})}, src)
		}
		// Ping back: completes hole punching from our side.
		if ep != nil && !p.trusted(now) && now.Sub(ep.lastPing) >= time.Second {
			c.sendPingLocked(p, src, now)
		}
	case *disco.Pong:
		pp, ok := c.pings[m.TxID]
		if !ok || viaRelay || !pp.peer.Equal(p.key) || pp.to != src {
			return
		}
		delete(c.pings, m.TxID)
		ep := p.eps[src]
		if ep == nil {
			ep = c.learnLocked(p, src, now)
			if ep == nil {
				return
			}
		}
		ep.lastPong, ep.latency = now, now.Sub(pp.sent)
		c.updateBestLocked(p, now)
	case *disco.CallMeMaybe:
		// Peers send it through the relay, where the sender is known. One
		// arriving over UDP may be a recording aimed at making us ping.
		if !viaRelay {
			return
		}
		for _, a := range m.Endpoints {
			c.learnLocked(p, a, now)
		}
		c.discoverLocked(p, now, true)
	}
}

// seenPingTTL is how long a ping's TxID is remembered. Older replays only
// get a pong to the address they came from, at most once per TTL.
const seenPingTTL = time.Minute

// notePingLocked records a received ping's TxID, reporting false if it was
// seen within seenPingTTL.
func (c *Conn) notePingLocked(tx disco.TxID, now time.Time) bool {
	if at, ok := c.seenPings[tx]; ok && now.Sub(at) < seenPingTTL {
		return false
	}
	if len(c.seenPings) >= 4096 {
		for k, at := range c.seenPings {
			if now.Sub(at) >= seenPingTTL {
				delete(c.seenPings, k)
			}
		}
		if len(c.seenPings) >= 4096 {
			clear(c.seenPings) // only under a flood of fresh pings
		}
	}
	c.seenPings[tx] = now
	return true
}

// learnLocked records a candidate endpoint for p discovered at runtime.
func (c *Conn) learnLocked(p *peer, a netip.AddrPort, now time.Time) *epState {
	a = unmap(a)
	if !usableAddr(a) {
		return nil
	}
	ep := p.eps[a]
	if ep == nil {
		if len(p.eps) >= maxPeerEndpoints {
			return nil
		}
		ep = &epState{}
		p.eps[a] = ep
	}
	ep.learned = now
	return ep
}

// updateBestLocked picks the lowest-latency endpoint that answered a ping
// recently as p's direct path.
func (c *Conn) updateBestLocked(p *peer, now time.Time) {
	var best netip.AddrPort
	var bestLat time.Duration
	for a, ep := range p.eps {
		if ep.lastPong.IsZero() || now.Sub(ep.lastPong) >= pongFresh {
			continue
		}
		if !best.IsValid() || ep.latency < bestLat {
			best, bestLat = a, ep.latency
		}
	}
	if !best.IsValid() {
		return
	}
	// Stick with the current path unless the new one is clearly better.
	if cur := p.eps[p.directAddr]; cur != nil && best != p.directAddr &&
		now.Sub(cur.lastPong) < pongFresh && float64(bestLat) > homeRelayHysteresis*float64(cur.latency) {
		best, bestLat = p.directAddr, cur.latency
	}
	if best != p.directAddr || !p.trusted(now) {
		c.logf("magicsock: direct path to %s via %v (%v)", p.key.ShortString(), best, bestLat.Round(time.Millisecond))
	}
	p.directAddr, p.latency = best, bestLat
	p.lastDirectRecv, p.firstUnanswered = now, time.Time{}
}

// ---- STUN and home relay ----

type stunTarget struct {
	region int
	host   string
	port   int
}

func (c *Conn) stunTargetsLocked() []stunTarget {
	var out []stunTarget
	for _, r := range c.relayMap.Regions {
		if len(r.Nodes) == 0 || r.Nodes[0].STUNPort == 0 {
			continue
		}
		n := r.Nodes[0]
		host := n.HostName
		if host == "" {
			u, ok := c.regionURL(r.ID)
			if !ok {
				continue
			}
			pu, err := url.Parse(u)
			if err != nil {
				continue
			}
			host = pu.Hostname()
		}
		out = append(out, stunTarget{region: r.ID, host: host, port: n.STUNPort})
	}
	return out
}

func (c *Conn) sendSTUN(targets []stunTarget) {
	for _, t := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", t.host)
		cancel()
		if err != nil || len(ips) == 0 {
			continue
		}
		// Prefer IPv4 (most NATs are IPv4; IPv6 addresses are usually
		// global anyway), but only a family we have a socket for: an
		// IPv6-only host must ask over IPv6.
		c.mu.Lock()
		has4, has6 := c.socks != nil && c.socks.v4 != nil, c.socks != nil && c.socks.v6 != nil
		c.mu.Unlock()
		var ip netip.Addr
		for _, a := range ips {
			a = a.Unmap()
			if a.Is4() && has4 {
				ip = a
				break
			}
			if a.Is6() && has6 && !ip.IsValid() {
				ip = a
			}
		}
		if !ip.IsValid() {
			continue
		}
		to := netip.AddrPortFrom(ip, uint16(t.port))
		tx := stun.NewTxID()
		c.mu.Lock()
		ss := c.socks
		if ss != nil {
			c.stunTx[tx] = stunRequest{region: t.region, server: ip, sent: time.Now()}
		}
		c.mu.Unlock()
		if ss != nil {
			ss.write([][]byte{stun.Request(tx)}, to)
		}
	}
}

func (c *Conn) handleSTUNLocked(b []byte) {
	tx, mapped, err := stun.ParseResponse(b)
	if err != nil {
		return
	}
	sr, ok := c.stunTx[stun.TxID(tx)]
	if !ok {
		return
	}
	delete(c.stunTx, tx)
	c.regionLatency[sr.region] = time.Since(sr.sent)
	mapped = unmap(mapped)
	before := c.endpointsLocked()
	if isPublicAddr(sr.server) && !isPublicAddr(mapped.Addr()) {
		// A public STUN server that sees a private source address was
		// reached through the router's NAT loopback (hairpin): the address
		// is the router's LAN side, not ours on the internet, and its port
		// changes every query. Advertising it would only churn endpoints.
		delete(c.stunAddrs, sr.region)
	} else {
		c.stunAddrs[sr.region] = mapped
	}
	if after := c.endpointsLocked(); !slices.Equal(before, after) {
		if a, ok := c.stunAddrs[sr.region]; ok {
			c.logf("magicsock: public address %v (via relay region %d STUN)", a, sr.region)
		}
		c.notifyEndpointsLocked()
	}
	c.updateRelaysLocked()
}

// chooseHomeLocked returns the home relay region: the lowest STUN latency
// (with hysteresis), or the lowest region ID before any measurement.
func (c *Conn) chooseHomeLocked() int {
	lowest, best := 0, 0
	var bestLat time.Duration
	for _, r := range c.relayMap.Regions {
		if _, ok := c.regionURL(r.ID); !ok {
			continue
		}
		if lowest == 0 || r.ID < lowest {
			lowest = r.ID
		}
		if lat, ok := c.regionLatency[r.ID]; ok && (best == 0 || lat < bestLat) {
			best, bestLat = r.ID, lat
		}
	}
	if best == 0 {
		if _, ok := c.regionURL(c.home); ok && c.home != 0 {
			return c.home
		}
		return lowest
	}
	if cur, ok := c.regionLatency[c.home]; ok && c.home != best {
		if _, stillThere := c.regionURL(c.home); stillThere && float64(bestLat) > homeRelayHysteresis*float64(cur) {
			return c.home
		}
	}
	return best
}

// endpointsLocked returns this node's candidate endpoints: local addresses
// plus public addresses learned via STUN, sorted and de-duplicated.
func (c *Conn) endpointsLocked() []netip.AddrPort {
	out := slices.Clone(c.local)
	for _, a := range c.stunAddrs {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b netip.AddrPort) int { return a.Compare(b) })
	out = slices.Compact(out)
	if len(out) > disco.MaxEndpoints {
		out = out[:disco.MaxEndpoints]
	}
	return out
}

func (c *Conn) notifyEndpointsLocked() {
	if c.onEndpoints != nil {
		go c.onEndpoints()
	}
}

// SetLocalEndpoints records this host's local interface endpoints (from the
// daemon's interface scan).
func (c *Conn) SetLocalEndpoints(eps []netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Equal(c.local, eps) {
		c.local = slices.Clone(eps)
		c.notifyEndpointsLocked()
	}
}

// Endpoints returns the endpoints to advertise to peers.
func (c *Conn) Endpoints() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.endpointsLocked()
}
