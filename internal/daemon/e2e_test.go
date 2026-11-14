package daemon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/netip"
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

func newTestNode(t *testing.T, name string) *testNode {
	t.Helper()
	n := &testNode{}
	d, err := New(Options{
		StateDir: filepath.Join(t.TempDir(), name),
		Logf:     func(f string, a ...any) { t.Logf("[%s] "+f, append([]any{name}, a...)...) },
		NewEngine: func(priv key.NodePrivate, addrs []netip.Prefix, port uint16) (*engine.Engine, error) {
			var ips []netip.Addr
			for _, p := range addrs {
				ips = append(ips, p.Addr())
			}
			tdev, tnet, err := netstack.CreateNetTUN(ips, nil, engine.DefaultMTU)
			if err != nil {
				return nil, err
			}
			e, err := engine.New(engine.Config{TUN: tdev, ListenPort: 0}, priv)
			if err != nil {
				return nil, err
			}
			n.mu.Lock()
			n.net = tnet
			n.mu.Unlock()
			return e, nil
		},
		// Both nodes share this host; reach each other over loopback.
		Endpoints: func(port uint16) ([]netip.AddrPort, []netip.Prefix) {
			return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)},
				[]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
		},
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

func ping(n *testNode, dst netip.Addr, msg string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

func TestEndToEndMesh(t *testing.T) {
	// Control server.
	cdb, err := db.Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := control.New(context.Background(), cdb, control.Config{BaseDomain: "e2e.internal", PollInterval: 50 * time.Millisecond},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(ctl.Handler())
	t.Cleanup(func() { ctl.Close(); ts.Close(); cdb.Close() })
	u, _ := cdb.CreateUser(context.Background(), "alice")
	authKey, _, _ := cdb.CreatePreAuthKey(context.Background(), db.CreatePreAuthKeyParams{UserID: u.ID, Reusable: true, TTL: time.Hour})

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
		t.Fatalf("alpha→beta: %q %v", got, err)
	}
	if got, err := ping(b, ipA, "hi-alpha"); err != nil || got != "pong:hi-alpha" {
		t.Fatalf("beta→alpha: %q %v", got, err)
	}
	st := a.d.Status()
	if !st.Peers[0].Active || st.Peers[0].TxBytes == 0 || st.Peers[0].RxBytes == 0 {
		t.Fatalf("peer stats not populated: %+v", st.Peers[0])
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
	d, err := New(Options{StateDir: dir, NewEngine: func(key.NodePrivate, []netip.Prefix, uint16) (*engine.Engine, error) {
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
