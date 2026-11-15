// Package daemon is the core of tcd: it keeps the node's keys and
// registration, holds a map stream to tc-control and applies every network
// map to the WireGuard engine.
//
// If control becomes unreachable the tunnel keeps running with the last map;
// the daemon reconnects with backoff.
package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"tailconnect/internal/controlclient"
	"tailconnect/internal/engine"
	"tailconnect/internal/ipam"
	"tailconnect/internal/key"
	"tailconnect/internal/localapi"
	"tailconnect/internal/protocol"
)

// Version is reported to control in Hostinfo.
var Version = "dev"

type Options struct {
	StateDir   string
	TUNName    string // shown in status, excluded from endpoint discovery
	ListenPort uint16 // preferred WireGuard port; falls back to random if busy
	Logf       func(format string, args ...any)
	// NewEngine creates the data plane once the node's addresses are known.
	NewEngine func(EngineParams) (*engine.Engine, error)
	// Endpoints discovers this host's candidate endpoints and attached
	// prefixes (nil = LocalEndpoints).
	Endpoints func(port uint16) ([]netip.AddrPort, []netip.Prefix)
	// EndpointInterval is how often endpoints are re-discovered (default 15s).
	EndpointInterval time.Duration
	// TrafficInterval is how often traffic counters are reported to the
	// control server, when they changed (default 30s).
	TrafficInterval time.Duration
}

// EngineParams is what the daemon passes to Options.NewEngine.
type EngineParams struct {
	NodeKey  key.NodePrivate
	DiscoKey key.DiscoPrivate
	Addrs    []netip.Prefix // this node's tunnel addresses
	Name     string         // this node's MagicDNS name, e.g. "tablet.alice.home.internal"
	Search   []string       // DNS search domains from the last network map (nil before the first)
	Port     uint16         // preferred WireGuard port (0 = random)
	// OnEndpointsChanged must be passed to engine.Config so the daemon
	// re-reports endpoints when STUN finds a new public address.
	OnEndpointsChanged func()
}

// persist is the on-disk state (state.json, mode 0600).
type persist struct {
	ControlURL  string            `json:",omitempty"`
	ServerKey   key.MachinePublic `json:",omitempty"`
	MachineKey  key.MachinePrivate
	NodeKey     key.NodePrivate
	DiscoKey    key.DiscoPrivate
	Hostname    string `json:",omitempty"`
	Registered  bool
	WantRunning bool
	Self        *protocol.Node `json:",omitempty"`
	ExitNode    string         `json:",omitempty"` // chosen exit node ("" = none)
	// DNSSearch is the last network map's search domains, for platforms
	// that fix them when the tunnel starts (Android).
	DNSSearch []string `json:",omitempty"`
}

type Daemon struct {
	opts Options
	path string

	opMu sync.Mutex // serialises Up/Down/Logout/Start

	mu      sync.Mutex
	st      persist
	state   string
	lastErr string
	netmap  *protocol.MapResponse
	eng     *engine.Engine
	port    uint16
	local   []netip.Prefix
	cancel  context.CancelFunc
	done    chan struct{}
}

func New(opts Options) (*Daemon, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.NewEngine == nil {
		return nil, errors.New("daemon: NewEngine is required")
	}
	if opts.Endpoints == nil {
		name := opts.TUNName
		opts.Endpoints = func(port uint16) ([]netip.AddrPort, []netip.Prefix) { return LocalEndpoints(port, name) }
	}
	if opts.EndpointInterval <= 0 {
		opts.EndpointInterval = 15 * time.Second
	}
	if opts.TrafficInterval <= 0 {
		opts.TrafficInterval = 30 * time.Second
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: state dir: %w", err)
	}
	d := &Daemon{opts: opts, path: filepath.Join(opts.StateDir, "state.json")}
	b, err := os.ReadFile(d.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("daemon: read state: %w", err)
	default:
		if err := json.Unmarshal(b, &d.st); err != nil {
			return nil, fmt.Errorf("daemon: parse %s: %w", d.path, err)
		}
	}
	d.state = localapi.StateNeedsLogin
	if d.st.Registered {
		d.state = localapi.StateStopped
	}
	return d, nil
}

// Start resumes the previous session if the node was up when tcd last stopped.
func (d *Daemon) Start() {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	d.mu.Lock()
	resume := d.st.Registered && d.st.WantRunning
	d.mu.Unlock()
	if resume {
		d.startLocked()
	}
}

// Close stops the tunnel (keeping WantRunning, so the next start resumes).
func (d *Daemon) Close() {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	d.stopLocked()
}

func (d *Daemon) save() error {
	b, err := json.MarshalIndent(d.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.path)
}

func (d *Daemon) running() bool {
	if d.done == nil {
		return false
	}
	select {
	case <-d.done:
		return false
	default:
		return true
	}
}

// startLocked launches the run loop. Caller holds opMu.
func (d *Daemon) startLocked() {
	d.mu.Lock()
	if d.running() {
		d.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel, d.done = cancel, make(chan struct{})
	d.state = localapi.StateStarting
	st, done := d.st, d.done
	d.mu.Unlock()
	go d.run(ctx, st, done)
}

// stopLocked stops the run loop and waits for it. Caller holds opMu.
func (d *Daemon) stopLocked() {
	d.mu.Lock()
	cancel, done := d.cancel, d.done
	d.cancel = nil
	d.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (d *Daemon) setErr(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil {
		d.lastErr = ""
	} else {
		d.lastErr = err.Error()
	}
}

func (d *Daemon) hostinfo(st persist) protocol.Hostinfo {
	return protocol.Hostinfo{Hostname: st.Hostname, OS: runtime.GOOS, ClientVersion: Version}
}

// ---- local API backend ----

var _ localapi.Backend = (*Daemon)(nil)

func (d *Daemon) Up(req localapi.UpRequest) error {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	d.mu.Lock()
	st := d.st
	d.mu.Unlock()

	url := strings.TrimRight(req.ControlURL, "/")
	if url == "" {
		url = st.ControlURL
	}
	if url == "" {
		return errors.New("no control server configured: pass --server URL")
	}
	if st.ControlURL != "" && url != st.ControlURL {
		d.stopLocked()
		if d.sameServer(url, st.ServerKey) {
			// The same server at a new address (new port, hostname or TLS).
			// Safe to trust: the Noise handshake still authenticates the
			// pinned key, whatever /key returned.
			d.opts.Logf("control server moved %s → %s (same server key); keeping registration", st.ControlURL, url)
		} else {
			d.opts.Logf("switching control server %s → %s; starting with a fresh identity", st.ControlURL, url)
			st = persist{Hostname: st.Hostname}
		}
	}
	if st.MachineKey.IsZero() {
		st.MachineKey = key.NewPrivate[key.MachineKind]()
	}
	if st.NodeKey.IsZero() {
		st.NodeKey = key.NewPrivate[key.NodeKind]()
		st.DiscoKey = key.NewPrivate[key.DiscoKind]()
	}
	if req.Hostname != "" {
		st.Hostname = req.Hostname
	}
	if st.Hostname == "" {
		st.Hostname, _ = os.Hostname()
	}
	st.ControlURL = url
	if req.ExitNode != nil {
		pref := strings.TrimSpace(*req.ExitNode)
		d.mu.Lock()
		nm := d.netmap
		d.mu.Unlock()
		if pref != "" && nm != nil && !nm.Self.ExitNode {
			// Catch typos now; an exit node that is offline or not yet in
			// the map is still accepted (and reported in status).
			if _, err := engine.FindExitNode(nm, pref); err != nil && !errors.Is(err, engine.ErrNoSuchMachine) {
				return fmt.Errorf("--exit-node: %w", err)
			}
		}
		st.ExitNode = pref
	}

	if !st.Registered || req.AuthKey != "" {
		if !st.Registered && req.AuthKey == "" {
			return errors.New("this machine is not registered: pass --authkey (create one in the admin UI or with `tc-control keys create`)")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		sk := req.ServerKey
		if sk.IsZero() {
			sk = st.ServerKey
		}
		if sk.IsZero() {
			var err error
			if sk, err = controlclient.FetchServerKey(ctx, url, nil); err != nil {
				return err
			}
			if strings.HasPrefix(url, "http://") {
				d.opts.Logf("pinned control server key %s (fetched over plain HTTP: trust on first use)", sk.ShortString())
			}
		}
		cc, err := controlclient.New(controlclient.Options{ServerURL: url, ServerKey: sk, MachineKey: st.MachineKey})
		if err != nil {
			return err
		}
		defer cc.Close()
		// Register before touching the running tunnel, so a failed attempt
		// (say, a mistyped auth key) leaves the device connected.
		resp, err := cc.Register(ctx, protocol.RegisterRequest{
			NodeKey: st.NodeKey.Public(), DiscoKey: st.DiscoKey.Public(), AuthKey: req.AuthKey, Hostinfo: d.hostinfo(st),
		})
		if controlclient.IsUnauthorized(err) {
			return fmt.Errorf("registration refused: %w", err)
		}
		if err != nil {
			return fmt.Errorf("register: %w", err)
		}
		d.stopLocked()
		st.ServerKey, st.Registered, st.Self = sk, true, &resp.Node
		d.opts.Logf("registered as %s (%v)", resp.Node.Name, resp.Node.Addresses)
	}
	st.WantRunning = true

	d.mu.Lock()
	d.st = st
	d.lastErr = ""
	err := d.save()
	eng := d.eng
	d.mu.Unlock()
	if err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	if eng != nil {
		// Already running: switch exit nodes on the current map.
		if err := eng.SetExitNode(st.ExitNode); err != nil {
			return fmt.Errorf("apply exit node: %w", err)
		}
	}
	d.startLocked()
	return nil
}

func (d *Daemon) Down() error {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	d.stopLocked()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st.WantRunning = false
	if d.st.Registered {
		d.state = localapi.StateStopped
	} else {
		d.state = localapi.StateNeedsLogin
	}
	return d.save()
}

func (d *Daemon) Logout() error {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	d.stopLocked()
	d.mu.Lock()
	st := d.st
	d.mu.Unlock()
	if st.Registered && !st.ServerKey.IsZero() {
		if cc, err := controlclient.New(controlclient.Options{ServerURL: st.ControlURL, ServerKey: st.ServerKey, MachineKey: st.MachineKey}); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := cc.Logout(ctx, st.NodeKey.Public()); err != nil {
				d.opts.Logf("logout: server not informed: %v", err)
			}
			cancel()
			cc.Close()
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// Keep the server URL so the next `tc up --authkey` needs no --server. The
	// pinned key is dropped and fetched again on rejoin: after a logout, a
	// rebuilt server (new key) must not lock the device out.
	d.st = persist{ControlURL: st.ControlURL, Hostname: st.Hostname}
	d.state, d.lastErr, d.netmap = localapi.StateNeedsLogin, "", nil
	return d.save()
}

func (d *Daemon) Status() localapi.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := localapi.Status{
		State: d.state, Error: d.lastErr, ControlURL: d.st.ControlURL, TUN: d.opts.TUNName, ListenPort: d.port,
		Peers: []localapi.PeerStatus{},
	}
	var stats map[key.NodePublic]engine.PeerStats
	if d.eng != nil {
		stats = d.eng.Stats()
		s.HomeRelay, s.RelayConnected = d.eng.HomeRelay(), d.eng.RelayConnected()
		s.FilterDropped = d.eng.FilterDropped()
		if es := d.eng.ExitStatus(); es.Chosen != "" || es.Serving {
			s.ExitNode = &localapi.ExitStatus{Chosen: es.Chosen, Using: es.Using, Error: es.Error, Serving: es.Serving, ServingError: es.ServingError}
		}
		if ds := d.eng.DNSStatus(); ds.Domain != "" {
			s.DNS = &localapi.DNSStatus{
				Domain: ds.Domain, Base: ds.Base, Resolver: protocol.MagicDNSAddr, HostConfig: ds.Mode, SplitDNS: ds.Split, Error: ds.Error,
			}
		}
	}
	self := d.st.Self
	if d.netmap != nil {
		self = &d.netmap.Self
		s.Domain = d.netmap.DNS.Domain
		if len(d.netmap.DNS.Search) > 0 {
			s.Domain = d.netmap.DNS.Search[0] // short names are relative to the tenant domain
		}
		s.Notice = d.netmap.Notice
		for _, p := range d.netmap.Peers {
			ps := peerStatus(p)
			if st, ok := stats[p.NodeKey]; ok {
				ps.CurrentEndpoint, ps.Relay, ps.RxBytes, ps.TxBytes = st.Endpoint, st.Relay, st.RxBytes, st.TxBytes
				ps.LatencyMS = float64(st.Latency.Microseconds()) / 1000
				if !st.LastHandshake.IsZero() {
					t := st.LastHandshake
					ps.LastHandshake = &t
					ps.Active = time.Since(t) < 3*time.Minute
				}
			}
			s.Peers = append(s.Peers, ps)
		}
	}
	if self != nil && d.st.Registered {
		ps := peerStatus(*self)
		s.Self = &ps
	}
	return s
}

func peerStatus(n protocol.Node) localapi.PeerStatus {
	return localapi.PeerStatus{
		Name: n.Name, HostName: n.Hostinfo.Hostname, User: n.User, OS: n.Hostinfo.OS,
		Addresses: n.Addresses, NodeKey: n.NodeKey, Endpoints: n.Endpoints,
		Shared: n.Shared, NoInitiate: n.NoInitiate, Inbound: n.Inbound, Tags: n.Tags, ExitNode: n.ExitNode, KeyExpiry: n.KeyExpiry,
	}
}

// ---- run loop ----

func (d *Daemon) run(ctx context.Context, st persist, done chan struct{}) {
	defer close(done)
	logf := d.opts.Logf
	fail := func(state string, err error) {
		logf("%v", err)
		d.mu.Lock()
		d.state, d.lastErr = state, err.Error()
		d.mu.Unlock()
	}
	if st.Self == nil {
		fail(localapi.StateNeedsLogin, errors.New("no registration data; run `tc up --authkey ...`"))
		return
	}
	cc, err := controlclient.New(controlclient.Options{ServerURL: st.ControlURL, ServerKey: st.ServerKey, MachineKey: st.MachineKey})
	if err != nil {
		fail(localapi.StateStopped, err)
		return
	}
	defer cc.Close()

	kick := make(chan struct{}, 1) // re-report endpoints now
	kickNow := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	params := EngineParams{NodeKey: st.NodeKey, DiscoKey: st.DiscoKey, Addrs: st.Self.Addresses, Name: st.Self.Name, Search: st.DNSSearch, Port: d.opts.ListenPort, OnEndpointsChanged: kickNow}
	eng, err := d.opts.NewEngine(params)
	if err != nil && d.opts.ListenPort != 0 {
		logf("port %d unavailable (%v); using a random port", d.opts.ListenPort, err)
		params.Port = 0
		eng, err = d.opts.NewEngine(params)
	}
	if err != nil {
		fail(localapi.StateStopped, fmt.Errorf("start tunnel: %w", err))
		return
	}
	_ = eng.SetExitNode(st.ExitNode) // no map yet: nothing to apply
	if err := eng.SetControlURL(st.ControlURL); err != nil {
		logf("relay base URL: %v", err)
	}
	port := eng.ListenPort()
	d.mu.Lock()
	d.eng, d.port = eng, port
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.eng, d.netmap, d.port = nil, nil, 0
		if d.state != localapi.StateNeedsLogin {
			d.state = localapi.StateStopped
		}
		d.mu.Unlock()
		eng.Close()
	}()
	logf("tunnel up, WireGuard on UDP port %d", port)

	nk, dk := st.NodeKey.Public(), st.DiscoKey.Public()
	hi := d.hostinfo(st)

	var repMu sync.Mutex
	var reported []netip.AddrPort
	reportedRelay := 0
	// discover scans local interfaces and returns what to advertise: local
	// endpoints plus public ones learned by STUN.
	discover := func() []netip.AddrPort {
		eps, local := d.opts.Endpoints(port)
		d.mu.Lock()
		d.local = local
		d.mu.Unlock()
		eng.SetLocalEndpoints(eps)
		return eng.Endpoints()
	}

	// Re-report endpoints when interfaces change (DHCP renewals, Wi-Fi switches).
	go func() {
		t := time.NewTicker(d.opts.EndpointInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-kick:
			}
			eps := discover()
			home := eng.HomeRelay()
			repMu.Lock()
			same := slices.Equal(eps, reported) && home == reportedRelay
			repMu.Unlock()
			if same {
				continue
			}
			if err := cc.UpdateStatus(ctx, protocol.MapRequest{NodeKey: nk, DiscoKey: dk, Endpoints: eps, HomeRelay: home}); err != nil {
				if ctx.Err() == nil {
					logf("report endpoints: %v", err)
				}
				continue
			}
			logf("reported endpoints %v, home relay %d", eps, home)
			repMu.Lock()
			reported, reportedRelay = eps, home
			repMu.Unlock()
		}
	}()

	go d.reportTraffic(ctx, cc, eng, nk)

	backoff := time.Second
	for {
		eps := discover()
		home := eng.HomeRelay()
		repMu.Lock()
		reported, reportedRelay = eps, home
		repMu.Unlock()
		err := cc.StreamMap(ctx, protocol.MapRequest{NodeKey: nk, DiscoKey: dk, Endpoints: eps, Hostinfo: &hi, HomeRelay: home},
			func(m *protocol.MapResponse) error {
				backoff = time.Second
				d.mu.Lock()
				local := d.local
				d.mu.Unlock()
				rerr := eng.Reconfig(m, local)
				if rerr != nil {
					logf("apply network map: %v", rerr)
				}
				repMu.Lock()
				relayChanged := eng.HomeRelay() != reportedRelay
				repMu.Unlock()
				if relayChanged {
					kickNow()
				}
				d.mu.Lock()
				d.netmap, d.state = m, localapi.StateRunning
				if len(m.DNS.Search) > 0 && !slices.Equal(m.DNS.Search, d.st.DNSSearch) {
					d.st.DNSSearch = slices.Clone(m.DNS.Search)
					_ = d.save()
				}
				if rerr != nil {
					d.lastErr = rerr.Error()
				} else {
					d.lastErr = ""
				}
				d.mu.Unlock()
				return nil
			})
		if ctx.Err() != nil {
			return
		}
		if controlclient.IsUnauthorized(err) {
			logf("control no longer recognises this node (%v); login required", err)
			d.mu.Lock()
			d.st.Registered, d.st.Self = false, nil
			d.state = localapi.StateNeedsLogin
			d.lastErr = "this machine was removed from the network; run `tc up --authkey ...` to rejoin"
			_ = d.save()
			d.mu.Unlock()
			return
		}
		// Keep the tunnel running on the last map while we reconnect.
		logf("control connection lost: %v (retrying in %v)", err, backoff)
		d.setErr(fmt.Errorf("control unreachable: %w", err))
		cc.Close()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// ---- endpoint discovery ----

// LocalEndpoints lists this host's usable unicast addresses (excluding
// loopback, link-local and the tunnel interface itself) paired with port, plus
// the prefixes they belong to. Results are sorted for stable comparison.
// isTunnelIface reports whether an interface is a TailConnect tunnel (ours
// under another name, or another tcd's): it carries an address from the
// tunnel IPv6 range. Its addresses are only reachable through a tunnel, so
// advertising them would send WireGuard traffic into WireGuard.
func isTunnelIface(addrs []net.Addr) bool {
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ipam.DefaultV6.Contains(ip.Unmap()) {
				return true
			}
		}
	}
	return false
}

func LocalEndpoints(port uint16, excludeIface string) ([]netip.AddrPort, []netip.Prefix) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	var eps []netip.AddrPort
	var prefixes []netip.Prefix
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Name == excludeIface {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil || isTunnelIface(addrs) {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			eps = append(eps, netip.AddrPortFrom(ip, port))
			prefixes = append(prefixes, netip.PrefixFrom(ip, ones).Masked())
		}
	}
	slices.SortFunc(eps, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return eps, prefixes
}

// sameServer reports whether the control server at url has the pinned key.
func (d *Daemon) sameServer(url string, pinned key.MachinePublic) bool {
	if pinned.IsZero() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sk, err := controlclient.FetchServerKey(ctx, url, nil)
	return err == nil && sk.Equal(pinned)
}

// reportTraffic sends the control server this machine's per-peer WireGuard
// counters when they change, for the web portal's traffic view. It stops if
// the server doesn't support it.
func (d *Daemon) reportTraffic(ctx context.Context, cc *controlclient.Client, eng *engine.Engine, nk key.NodePublic) {
	t := time.NewTicker(d.opts.TrafficInterval)
	defer t.Stop()
	var last []protocol.PeerTraffic
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var peers []protocol.PeerTraffic
		for k, st := range eng.Stats() {
			if st.RxBytes > 0 || st.TxBytes > 0 {
				peers = append(peers, protocol.PeerTraffic{NodeKey: k, RxBytes: st.RxBytes, TxBytes: st.TxBytes})
			}
		}
		slices.SortFunc(peers, func(a, b protocol.PeerTraffic) int {
			ka, kb := a.NodeKey.Raw(), b.NodeKey.Raw()
			return bytes.Compare(ka[:], kb[:])
		})
		if slices.Equal(peers, last) {
			continue // idle: nothing new to say
		}
		err := cc.ReportTraffic(ctx, protocol.TrafficRequest{NodeKey: nk, Peers: peers})
		switch {
		case err == nil:
			last = peers
		case controlclient.IsNotFound(err):
			return // an older server
		case ctx.Err() == nil:
			d.opts.Logf("report traffic: %v", err)
		}
	}
}
