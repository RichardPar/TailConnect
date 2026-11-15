package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
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

func newTestNodeEP(t *testing.T, name string, eps func(uint16) ([]netip.AddrPort, []netip.Prefix)) *testNode {
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
func newControl(t *testing.T, noSTUN ...bool) (*db.DB, string, string) {
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
	if st := a.d.Status(); st.Self.Name != "alpha.e2e.internal" || st.Peers[0].Name != "beta.e2e.internal" {
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
	// After logout, the control URL is remembered: an auth key alone rejoins.
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
