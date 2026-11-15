package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"tailconnect/internal/control"
	"tailconnect/internal/db"
	"tailconnect/internal/engine"
	"tailconnect/internal/key"
	"tailconnect/internal/localapi"
	"tailconnect/internal/stun"
)

// testNode is a daemon whose engine runs on a userspace netstack TUN.
type testNode struct {
	d   *Daemon
	mu  sync.Mutex
	net *netstack.Net
}

func (n *testNode) tnet() *netstack.Net {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.net
}

// loopbackEndpoints makes nodes on this host reach each other over loopback.
func loopbackEndpoints(port uint16) ([]netip.AddrPort, []netip.Prefix) {
	return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)},
		[]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
}

// deadEndpoints advertises an address where nothing listens, so the only
// working path between nodes is the relay.
func deadEndpoints(uint16) ([]netip.AddrPort, []netip.Prefix) {
	return []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9")}, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
}

func newTestNode(t *testing.T, name string) *testNode {
	return newTestNodeEP(t, name, loopbackEndpoints)
}

func newTestNodeEP(t testing.TB, name string, eps func(uint16) ([]netip.AddrPort, []netip.Prefix)) *testNode {
	t.Helper()
	n := &testNode{}
	d, err := New(Options{
		StateDir: filepath.Join(t.TempDir(), name),
		Logf:     func(f string, a ...any) { t.Logf("[%s] "+f, append([]any{name}, a...)...) },
		NewEngine: func(ep EngineParams) (*engine.Engine, error) {
			var ips []netip.Addr
			for _, p := range ep.Addrs {
				ips = append(ips, p.Addr())
			}
			tdev, tnet, err := netstack.CreateNetTUN(ips, nil, engine.DefaultMTU)
			if err != nil {
				return nil, err
			}
			e, err := engine.New(engine.Config{
				TUN: tdev, ListenPort: 0, DiscoKey: ep.DiscoKey, OnEndpointsChanged: ep.OnEndpointsChanged,
				Verbose: os.Getenv("TC_WG_VERBOSE") != "",
				Logf:    func(f string, a ...any) { t.Logf("[%s] "+f, append([]any{name}, a...)...) },
			}, ep.NodeKey)
			if err != nil {
				return nil, err
			}
			n.mu.Lock()
			n.net = tnet
			n.mu.Unlock()
			return e, nil
		},
		Endpoints: eps,
	})
	if err != nil {
		t.Fatal(err)
	}
	n.d = d
	t.Cleanup(d.Close)
	return n
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func running(n *testNode, peers int) func() bool {
	return func() bool {
		s := n.d.Status()
		return s.State == localapi.StateRunning && len(s.Peers) == peers
	}
}

func selfIP(t *testing.T, n *testNode) netip.Addr {
	t.Helper()
	s := n.d.Status()
	if s.Self == nil {
		t.Fatal("no self in status")
	}
	return s.Self.Addresses[0].Addr()
}

// echo starts a TCP server on n's tunnel address that replies "pong:<msg>".
func echo(t *testing.T, n *testNode, ip netip.Addr) {
	t.Helper()
	ln, err := n.tnet().ListenTCPAddrPort(netip.AddrPortFrom(ip, 7000))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				k, _ := c.Read(buf)
				fmt.Fprintf(c, "pong:%s", buf[:k])
			}(c)
		}
	}()
}

func ping(n *testNode, dst netip.Addr, msg string) (out string, err error) {
	start := time.Now()
	defer func() {
		if d := time.Since(start); d > time.Second {
			fmt.Printf("slow ping %s → %s: %v (err=%v)\n", msg, dst, d.Round(time.Millisecond), err)
		}
	}()
	// Allow for one WireGuard handshake retry (5s) on a cold path.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	c, err := n.tnet().DialContextTCPAddrPort(ctx, netip.AddrPortFrom(dst, 7000))
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	b, err := io.ReadAll(c)
	return string(b), err
}

// newControl starts tc-control with its embedded relay (and a STUN server
// unless noSTUN) and returns the database, URL and a reusable auth key.
func newControl(t testing.TB, noSTUN ...bool) (*db.DB, string, string) {
	t.Helper()
	relays := control.EmbeddedRelayMap(0)
	if len(noSTUN) == 0 || !noSTUN[0] {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		go stun.Serve(pc)
		relays = control.EmbeddedRelayMap(pc.LocalAddr().(*net.UDPAddr).Port)
	}
	cdb, err := db.Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rs, err := control.NewEmbeddedRelay(context.Background(), cdb, log)
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := control.New(context.Background(), cdb, control.Config{
		BaseDomain: "e2e.internal", PollInterval: 50 * time.Millisecond, Relays: relays,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	rs.SetAllow(ctl.RelayAllowed)
	mux := http.NewServeMux()
	mux.Handle(control.EmbeddedRelayPath, rs)
	mux.Handle("/", ctl.Handler())
	ts := httptest.NewServer(mux)
	t.Cleanup(func() { ctl.Close(); rs.Close(); ts.Close(); cdb.Close() })
	u, _ := cdb.CreateUser(context.Background(), "alice")
	authKey, _, _ := cdb.CreatePreAuthKey(context.Background(), db.CreatePreAuthKeyParams{UserID: u.ID, Reusable: true, TTL: time.Hour})
	return cdb, ts.URL, authKey
}

func TestEndToEndMesh(t *testing.T) {
	cdb, url, authKey := newControl(t)
	ts := struct{ URL string }{url}

	a, b := newTestNode(t, "alpha"), newTestNode(t, "beta")

	// Up without an auth key on an unregistered machine fails clearly.
	if err := a.d.Up(localapi.UpRequest{ControlURL: ts.URL}); err == nil {
		t.Fatal("expected error without auth key")
	}
	if err := a.d.Up(localapi.UpRequest{ControlURL: ts.URL, AuthKey: "tc-auth-nope", Hostname: "alpha"}); err == nil {
		t.Fatal("expected error with bad auth key")
	}

	for _, n := range []struct {
		n    *testNode
		host string
	}{{a, "alpha"}, {b, "beta"}} {
		if err := n.n.d.Up(localapi.UpRequest{ControlURL: ts.URL, AuthKey: authKey, Hostname: n.host}); err != nil {
			t.Fatalf("up %s: %v", n.host, err)
		}
	}
	waitFor(t, "alpha running with 1 peer", running(a, 1))
	waitFor(t, "beta running with 1 peer", running(b, 1))

	ipA, ipB := selfIP(t, a), selfIP(t, b)
	t.Logf("alpha=%s beta=%s", ipA, ipB)
	if st := a.d.Status(); st.Self.Name != "alpha.alice.e2e.internal" || st.Peers[0].Name != "beta.alice.e2e.internal" {
		t.Fatalf("names: self=%s peer=%s", st.Self.Name, st.Peers[0].Name)
	}

	// Traffic flows both ways through WireGuard.
	echo(t, b, ipB)
	echo(t, a, ipA)
	if got, err := ping(a, ipB, "hi-beta"); err != nil || got != "pong:hi-beta" {
		dump(t, a, b)
		t.Fatalf("alpha→beta: %q %v", got, err)
	}
	if got, err := ping(b, ipA, "hi-alpha"); err != nil || got != "pong:hi-alpha" {
		t.Fatalf("beta→alpha: %q %v", got, err)
	}
	st := a.d.Status()
	if !st.Peers[0].Active || st.Peers[0].TxBytes == 0 || st.Peers[0].RxBytes == 0 {
		t.Fatalf("peer stats not populated: %+v", st.Peers[0])
	}
	// Loopback is reachable, so the path must settle on direct once each side
	// has the other's endpoints and traffic flows.
	waitFor(t, "direct path", func() bool {
		ping(a, ipB, "x")
		ps := a.d.Status().Peers
		return len(ps) == 1 && ps[0].CurrentEndpoint.IsValid()
	})
	if st.HomeRelay != 1 || !st.RelayConnected {
		t.Fatalf("home relay: %d connected=%v", st.HomeRelay, st.RelayConnected)
	}

	// Down/Up cycle: registration survives, tunnel comes back.
	if err := a.d.Down(); err != nil {
		t.Fatal(err)
	}
	if s := a.d.Status(); s.State != localapi.StateStopped {
		t.Fatalf("after down: %s", s.State)
	}
	if err := a.d.Up(localapi.UpRequest{}); err != nil {
		t.Fatalf("up again (no args): %v", err)
	}
	waitFor(t, "alpha running again", running(a, 1))
	if selfIP(t, a) != ipA {
		t.Fatal("address changed across down/up")
	}
	echo(t, a, ipA) // new netstack instance
	if got, err := ping(b, ipA, "again"); err != nil || got != "pong:again" {
		t.Fatalf("beta→alpha after down/up: %q %v", got, err)
	}

	// An admin deleting beta: beta needs login again; alpha loses the peer.
	nodes, _ := cdb.ListNodes(context.Background(), 0)
	for _, n := range nodes {
		if n.GivenName == "beta" {
			if err := cdb.DeleteNode(context.Background(), n.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	waitFor(t, "alpha sees beta removed", running(a, 0))
	waitFor(t, "beta needs login", func() bool { return b.d.Status().State == localapi.StateNeedsLogin })

	// Logout removes alpha from control.
	if err := a.d.Logout(); err != nil {
		t.Fatal(err)
	}
	if nodes, _ := cdb.ListNodes(context.Background(), 0); len(nodes) != 0 {
		t.Fatalf("%d nodes left after logout", len(nodes))
	}
	// Logout forgets the pinned server key (a rebuilt server must not lock the
	// device out) but remembers the URL: an auth key alone rejoins.
	a.d.mu.Lock()
	pinned := a.d.st.ServerKey
	a.d.mu.Unlock()
	if !pinned.IsZero() {
		t.Fatal("server key still pinned after logout")
	}
	if err := a.d.Up(localapi.UpRequest{AuthKey: authKey}); err != nil {
		t.Fatalf("rejoin: %v", err)
	}
	waitFor(t, "alpha rejoined", func() bool { return a.d.Status().State == localapi.StateRunning })
}

func TestStatePersists(t *testing.T) {
	dir := t.TempDir()
	d, err := New(Options{StateDir: dir, NewEngine: func(EngineParams) (*engine.Engine, error) {
		return nil, fmt.Errorf("unused")
	}})
	if err != nil {
		t.Fatal(err)
	}
	d.st = persist{ControlURL: "http://x", MachineKey: key.NewPrivate[key.MachineKind](), Registered: true}
	if err := d.save(); err != nil {
		t.Fatal(err)
	}
	d2, err := New(Options{StateDir: dir, NewEngine: d.opts.NewEngine})
	if err != nil {
		t.Fatal(err)
	}
	if !d2.st.MachineKey.Equal(d.st.MachineKey) || d2.Status().State != localapi.StateStopped {
		t.Fatalf("state not restored: %+v", d2.Status())
	}
}

func TestRelayFallback(t *testing.T) {
	// No STUN: it would reveal the loopback path and discovery would use it.
	cdb, url, authKey := newControl(t, true)
	a, b := newTestNodeEP(t, "alpha", deadEndpoints), newTestNodeEP(t, "beta", deadEndpoints)
	for _, n := range []struct {
		n    *testNode
		host string
	}{{a, "alpha"}, {b, "beta"}} {
		if err := n.n.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: authKey, Hostname: n.host}); err != nil {
			t.Fatalf("up %s: %v", n.host, err)
		}
	}
	waitFor(t, "alpha running", running(a, 1))
	waitFor(t, "beta running", running(b, 1))
	// Both nodes must have told control their home relay before they can find each other.
	waitFor(t, "home relays reported", func() bool {
		nodes, _ := cdb.ListNodes(context.Background(), 0)
		return len(nodes) == 2 && nodes[0].HomeRelay == 1 && nodes[1].HomeRelay == 1
	})
	ipA, ipB := selfIP(t, a), selfIP(t, b)
	echo(t, b, ipB)
	echo(t, a, ipA)
	if got, err := ping(a, ipB, "via-relay"); err != nil || got != "pong:via-relay" {
		t.Fatalf("alpha→beta via relay: %q %v", got, err)
	}
	if got, err := ping(b, ipA, "back"); err != nil || got != "pong:back" {
		t.Fatalf("beta→alpha via relay: %q %v", got, err)
	}
	st := a.d.Status()
	p := st.Peers[0]
	if p.CurrentEndpoint.IsValid() || p.Relay != 1 || !p.Active {
		t.Fatalf("expected relay path: endpoint=%v relay=%d active=%v", p.CurrentEndpoint, p.Relay, p.Active)
	}
}

func dump(t *testing.T, ns ...*testNode) {
	for _, n := range ns {
		b, _ := json.MarshalIndent(n.d.Status(), "", " ")
		t.Logf("status: %s", b)
	}
}

// resolver returns a Go resolver that sends its queries through n's tunnel
// to the MagicDNS address, as the host's stub resolver would.
func resolver(n *testNode) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return n.tnet().DialContext(ctx, "udp", "100.100.100.100:53")
	}}
}

func TestMagicDNS(t *testing.T) {
	cdb, url, authKey := newControl(t)
	a, b := newTestNode(t, "alpha"), newTestNode(t, "beta")
	for _, n := range []struct {
		n    *testNode
		host string
	}{{a, "alpha"}, {b, "beta"}} {
		if err := n.n.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: authKey, Hostname: n.host}); err != nil {
			t.Fatalf("up %s: %v", n.host, err)
		}
	}
	waitFor(t, "alpha running with 1 peer", running(a, 1))
	waitFor(t, "beta running with 1 peer", running(b, 1))
	ipA, ipB := selfIP(t, a), selfIP(t, b)

	if d := a.d.Status().DNS; d == nil || d.Domain != "alice.e2e.internal" || d.Base != "e2e.internal" || d.HostConfig != "off" {
		t.Fatalf("DNS status: %+v", d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := resolver(a)
	addrs, err := r.LookupNetIP(ctx, "ip", "Beta.Alice.E2E.internal")
	if err != nil {
		t.Fatalf("lookup beta: %v", err)
	}
	if len(addrs) != 2 || !slices.Contains(addrs, ipB) {
		t.Fatalf("beta resolves to %v, want %v and its IPv6 address", addrs, ipB)
	}
	if self, err := r.LookupNetIP(ctx, "ip4", "alpha.alice.e2e.internal"); err != nil || len(self) != 1 || self[0] != ipA {
		t.Fatalf("self lookup: %v %v", self, err)
	}
	if names, err := r.LookupAddr(ctx, ipB.String()); err != nil || len(names) != 1 || names[0] != "beta.alice.e2e.internal." {
		t.Fatalf("reverse lookup of %s: %v %v", ipB, names, err)
	}
	var dnsErr *net.DNSError
	if _, err := r.LookupNetIP(ctx, "ip", "gamma.alice.e2e.internal"); !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("unknown name: want NXDOMAIN, got %v", err)
	}

	// Renaming a node in control reaches every client's resolver.
	nodes, _ := cdb.ListNodes(context.Background(), 0)
	for _, n := range nodes {
		if n.GivenName == "beta" {
			if err := cdb.RenameNode(context.Background(), n.ID, "db-server"); err != nil {
				t.Fatal(err)
			}
		}
	}
	waitFor(t, "renamed node resolves", func() bool {
		got, err := r.LookupNetIP(ctx, "ip4", "db-server.alice.e2e.internal")
		return err == nil && len(got) == 1 && got[0] == ipB
	})
	if _, err := r.LookupNetIP(ctx, "ip4", "beta.alice.e2e.internal"); err == nil {
		t.Fatal("old name still resolves after rename")
	}
}

func TestControlServerMoved(t *testing.T) {
	_, url, authKey := newControl(t)
	a := newTestNode(t, "alpha")
	if err := a.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: authKey, Hostname: "alpha"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha running", running(a, 0))
	ip := selfIP(t, a)

	// A mistyped auth key fails without disconnecting the device.
	if err := a.d.Up(localapi.UpRequest{AuthKey: "tc-auth-wrong"}); err == nil {
		t.Fatal("bad auth key accepted")
	}
	if st := a.d.Status(); st.State != localapi.StateRunning {
		t.Fatalf("after a failed re-registration: state %s, want Running", st.State)
	}

	// Same server, new address: keep the registration, no auth key needed.
	moved := strings.Replace(url, "127.0.0.1", "localhost", 1)
	if err := a.d.Up(localapi.UpRequest{ControlURL: moved}); err != nil {
		t.Fatalf("up with moved URL: %v", err)
	}
	waitFor(t, "alpha running via new URL", running(a, 0))
	if st := a.d.Status(); st.ControlURL != moved || selfIP(t, a) != ip {
		t.Fatalf("after move: url=%s ip=%s (want %s, %s)", st.ControlURL, selfIP(t, a), moved, ip)
	}

	// A different server: fresh identity, so an auth key is required.
	_, other, _ := newControl(t)
	if err := a.d.Up(localapi.UpRequest{ControlURL: other}); err == nil {
		t.Fatal("switching to another server without an auth key should fail")
	}
}

func TestSuspendedAccount(t *testing.T) {
	cdb, url, _ := newControl(t)
	bob, _ := cdb.CreateUser(context.Background(), "bob")
	bobKey, _, _ := cdb.CreatePreAuthKey(context.Background(), db.CreatePreAuthKeyParams{UserID: bob.ID, Reusable: true, TTL: time.Hour})
	b, c := newTestNode(t, "beta"), newTestNode(t, "gamma")
	for _, n := range []struct {
		n    *testNode
		host string
	}{{b, "beta"}, {c, "gamma"}} {
		if err := n.n.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: bobKey, Hostname: n.host}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "bob's machines see each other", func() bool { return running(b, 1)() && running(c, 1)() })

	// Suspending bob cuts his machines off: each gets an empty map with a
	// notice explaining why.
	if err := cdb.SetUserStatus(context.Background(), "bob", db.StatusSuspended); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta cut off with a notice", func() bool {
		s := b.d.Status()
		return len(s.Peers) == 0 && strings.Contains(s.Notice, "suspended")
	})
	// A suspended account's machines can't (re)register either.
	if err := b.d.Up(localapi.UpRequest{AuthKey: bobKey}); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("re-register while suspended: %v", err)
	}

	// Reactivation restores everything without any action on the devices.
	if err := cdb.SetUserStatus(context.Background(), "bob", db.StatusActive); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both see each other again", func() bool {
		return running(b, 1)() && running(c, 1)() && b.d.Status().Notice == ""
	})
}

func TestTenantsIsolated(t *testing.T) {
	cdb, url, aliceKey := newControl(t)
	bob, _ := cdb.CreateUser(context.Background(), "bob")
	bobKey, _, _ := cdb.CreatePreAuthKey(context.Background(), db.CreatePreAuthKeyParams{UserID: bob.ID, TTL: time.Hour})
	// Both tenants name a machine "laptop".
	a, a2, b := newTestNode(t, "alice-laptop"), newTestNode(t, "alice-desk"), newTestNode(t, "bob-laptop")
	for _, n := range []struct {
		n    *testNode
		key  string
		host string
	}{{a, aliceKey, "laptop"}, {a2, aliceKey, "desk"}, {b, bobKey, "laptop"}} {
		if err := n.n.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: n.key, Hostname: n.host}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "alice's machines see each other", func() bool { return running(a, 1)() && running(a2, 1)() })
	waitFor(t, "bob running", func() bool { return b.d.Status().State == localapi.StateRunning })
	time.Sleep(300 * time.Millisecond) // let any (wrong) cross-tenant map updates arrive

	if ps := b.d.Status().Peers; len(ps) != 0 {
		t.Fatalf("bob sees %d peers from another tenant: %v", len(ps), ps[0].Name)
	}
	if st := a.d.Status(); st.Self.Name != "laptop.alice.e2e.internal" || st.Peers[0].Name != "desk.alice.e2e.internal" {
		t.Fatalf("alice names: %s, %s", st.Self.Name, st.Peers[0].Name)
	}
	if st := b.d.Status(); st.Self.Name != "laptop.bob.e2e.internal" {
		t.Fatalf("bob's laptop: %s", st.Self.Name)
	}

	// Names: alice's short name finds her own laptop; bob's machines don't exist for her.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ipA, ipB := selfIP(t, a), selfIP(t, b)
	got, err := resolver(a2).LookupNetIP(ctx, "ip4", "laptop.alice.e2e.internal")
	if err != nil || len(got) != 1 || got[0] != ipA {
		t.Fatalf("alice's laptop: %v %v", got, err)
	}
	var dnsErr *net.DNSError
	if _, err := resolver(a2).LookupNetIP(ctx, "ip4", "laptop.bob.e2e.internal"); !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("bob's laptop should not resolve for alice: %v", err)
	}
	if _, err := resolver(a2).LookupAddr(ctx, ipB.String()); err == nil {
		t.Fatal("reverse lookup of bob's address should fail for alice")
	}

	// Traffic: alice can't reach bob's address at all (no WireGuard peer).
	echo(t, b, ipB)
	dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dcancel()
	if c, err := a.tnet().DialContextTCPAddrPort(dctx, netip.AddrPortFrom(ipB, 7000)); err == nil {
		c.Close()
		t.Fatal("alice reached bob's machine")
	}
}

func TestSharingIsOneWay(t *testing.T) {
	cdb, url, aliceKey := newControl(t)
	bob, _ := cdb.CreateUser(context.Background(), "bob")
	bobKey, _, _ := cdb.CreatePreAuthKey(context.Background(), db.CreatePreAuthKeyParams{UserID: bob.ID, TTL: time.Hour})
	nas, laptop := newTestNode(t, "alice-nas"), newTestNode(t, "bob-laptop")
	if err := nas.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: aliceKey, Hostname: "nas"}); err != nil {
		t.Fatal(err)
	}
	if err := laptop.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: bobKey, Hostname: "laptop"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both running", func() bool { return running(nas, 0)() && running(laptop, 0)() })
	ipNas, ipLaptop := selfIP(t, nas), selfIP(t, laptop)
	echo(t, nas, ipNas)
	echo(t, laptop, ipLaptop)

	// Alice shares her nas with bob; it takes effect once bob accepts.
	nasID := nodeID(t, cdb, "nas", "alice")
	sh, err := cdb.ShareWith(context.Background(), nasID, "bob")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if len(laptop.d.Status().Peers) != 0 {
		t.Fatal("pending share already visible")
	}
	if err := cdb.AcceptShare(context.Background(), sh.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "share in both maps", func() bool { return running(nas, 1)() && running(laptop, 1)() })
	lp := laptop.d.Status().Peers[0]
	if lp.Name != "nas.alice.e2e.internal" || !lp.Shared || !lp.NoInitiate {
		t.Fatalf("bob's view of the nas: %+v", lp)
	}
	if np := nas.d.Status().Peers[0]; np.Name != "laptop.bob.e2e.internal" || !np.Shared || np.NoInitiate {
		t.Fatalf("nas's view of bob's laptop: %+v", np)
	}

	// Bob's laptop can use the nas...
	if got, err := ping(laptop, ipNas, "hello-nas"); err != nil || got != "pong:hello-nas" {
		t.Fatalf("bob → nas: %q %v", got, err)
	}
	// ...and resolve it by name.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if a, err := resolver(laptop).LookupNetIP(ctx, "ip4", "nas.alice.e2e.internal"); err != nil || len(a) != 1 || a[0] != ipNas {
		t.Fatalf("bob resolving the nas: %v %v", a, err)
	}
	// ...but the nas can't open connections to bob's laptop.
	dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dcancel()
	if c, err := nas.tnet().DialContextTCPAddrPort(dctx, netip.AddrPortFrom(ipLaptop, 7000)); err == nil {
		c.Close()
		t.Fatal("the shared nas opened a connection to bob's laptop")
	}
	if laptop.d.Status().FilterDropped == 0 {
		t.Fatal("bob's filter didn't count the refused connection")
	}
	// Bob can still talk to the nas afterwards (the filter state is per flow).
	if got, err := ping(laptop, ipNas, "again"); err != nil || got != "pong:again" {
		t.Fatalf("bob → nas after the refused attempt: %q %v", got, err)
	}

	// Revoking ends access at once.
	if err := cdb.DeleteShare(context.Background(), sh.ID, 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "share gone from both maps", func() bool { return running(nas, 0)() && running(laptop, 0)() })
	rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer rcancel()
	if c, err := laptop.tnet().DialContextTCPAddrPort(rctx, netip.AddrPortFrom(ipNas, 7000)); err == nil {
		c.Close()
		t.Fatal("bob reached the nas after the share was revoked")
	}
}

func nodeID(t *testing.T, cdb *db.DB, name, user string) int64 {
	t.Helper()
	nodes, _ := cdb.ListNodes(context.Background(), 0)
	for _, n := range nodes {
		if n.GivenName == name && n.UserName == user {
			return n.ID
		}
	}
	t.Fatalf("no node %s of %s", name, user)
	return 0
}
