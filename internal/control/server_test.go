package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"tailconnect/internal/controlclient"
	"tailconnect/internal/db"
	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

type fixture struct {
	t   *testing.T
	db  *db.DB
	srv *Server
	ts  *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(context.Background(), d, Config{BaseDomain: "home.internal", PollInterval: 50 * time.Millisecond},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); ts.Close(); d.Close() })
	return &fixture{t: t, db: d, srv: s, ts: ts}
}

func (f *fixture) authKey(reusable bool) string {
	f.t.Helper()
	ctx := context.Background()
	u, err := f.db.GetUser(ctx, "alice")
	if err != nil {
		if u, err = f.db.CreateUser(ctx, "alice"); err != nil {
			f.t.Fatal(err)
		}
	}
	k, _, err := f.db.CreatePreAuthKey(ctx, db.CreatePreAuthKeyParams{UserID: u.ID, Reusable: reusable, TTL: time.Hour})
	if err != nil {
		f.t.Fatal(err)
	}
	return k
}

type node struct {
	mk    key.MachinePrivate
	nk    key.NodePublic
	disco key.DiscoPublic
	c     *controlclient.Client
}

func (f *fixture) newNode(serverKey key.MachinePublic) *node {
	f.t.Helper()
	n := &node{
		mk:    key.NewPrivate[key.MachineKind](),
		nk:    key.NewPrivate[key.NodeKind]().Public(),
		disco: key.NewPrivate[key.DiscoKind]().Public(),
	}
	if serverKey.IsZero() {
		serverKey = f.srv.MachinePublic()
	}
	c, err := controlclient.New(controlclient.Options{ServerURL: f.ts.URL, ServerKey: serverKey, MachineKey: n.mk})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(c.Close)
	n.c = c
	return n
}

func (n *node) register(host, authKey string) (protocol.RegisterResponse, error) {
	return n.c.Register(context.Background(), protocol.RegisterRequest{
		NodeKey: n.nk, DiscoKey: n.disco, AuthKey: authKey,
		Hostinfo: protocol.Hostinfo{Hostname: host, OS: "linux"},
	})
}

func code(err error) int {
	var he *controlclient.HTTPError
	if errors.As(err, &he) {
		return he.Code
	}
	return 0
}

func TestServerKeyStable(t *testing.T) {
	f := newFixture(t)
	k, err := controlclient.FetchServerKey(context.Background(), f.ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Equal(f.srv.MachinePublic()) {
		t.Fatal("fetched key mismatch")
	}
	s2, err := New(context.Background(), f.db, Config{BaseDomain: "x.internal"}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if !s2.MachinePublic().Equal(f.srv.MachinePublic()) {
		t.Fatal("machine key not persisted")
	}
}

func TestPlainEndpointsGone(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Post(f.ts.URL+"/machine/register", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("plaintext register reachable: %d", resp.StatusCode)
	}
	// Upgrade without a handshake is rejected.
	req, _ := http.NewRequest("POST", f.ts.URL+"/machine/noise", nil)
	req.Header.Set("Upgrade", "tailconnect-control-v1")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("upgrade without handshake: %d", resp.StatusCode)
	}
}

func TestWrongPinnedServerKey(t *testing.T) {
	f := newFixture(t)
	n := f.newNode(key.NewPrivate[key.MachineKind]().Public())
	_, err := n.register("x", f.authKey(false))
	if code(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong server key, got %v", err)
	}
}

func TestRegisterAndMap(t *testing.T) {
	f := newFixture(t)
	k := f.authKey(true)
	a, b := f.newNode(key.MachinePublic{}), f.newNode(key.MachinePublic{})

	if _, err := a.register("laptop", "tc-auth-wrong"); !controlclient.IsUnauthorized(err) {
		t.Fatalf("bad auth key: %v", err)
	}
	ra, err := a.register("laptop", k)
	if err != nil {
		t.Fatal(err)
	}
	if ra.Node.Name != "laptop.home.internal" || ra.Node.Addresses[0] != netip.MustParsePrefix("100.64.0.1/32") {
		t.Fatalf("unexpected node a: %+v", ra.Node)
	}
	// Re-registering the same node key needs no auth key.
	if _, err := a.register("laptop", ""); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if _, err := b.register("phone", k); err != nil {
		t.Fatal(err)
	}

	ep := netip.MustParseAddrPort("198.51.100.7:41641")
	m, err := a.c.Map(context.Background(), protocol.MapRequest{NodeKey: a.nk, DiscoKey: a.disco, Endpoints: []netip.AddrPort{ep}})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Self.NodeKey.Equal(a.nk) || len(m.Peers) != 1 || !m.Peers[0].NodeKey.Equal(b.nk) {
		t.Fatalf("unexpected map: %+v", m)
	}
	if !m.DNS.MagicDNS || m.DNS.Domain != "home.internal" {
		t.Fatalf("dns: %+v", m.DNS)
	}
	m, err = b.c.Map(context.Background(), protocol.MapRequest{NodeKey: b.nk, DiscoKey: b.disco})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Peers) != 1 || len(m.Peers[0].Endpoints) != 1 || m.Peers[0].Endpoints[0] != ep || !m.Peers[0].DiscoKey.Equal(a.disco) {
		t.Fatalf("b does not see a's status: %+v", m.Peers)
	}
}

func TestOtherMachinesNodeKeyRejected(t *testing.T) {
	f := newFixture(t)
	a, mallory := f.newNode(key.MachinePublic{}), f.newNode(key.MachinePublic{})
	if _, err := a.register("a", f.authKey(false)); err != nil {
		t.Fatal(err)
	}
	// mallory knows a's (public) node key from a netmap but not a's machine key.
	_, err := mallory.c.Map(context.Background(), protocol.MapRequest{NodeKey: a.nk})
	if code(err) != http.StatusForbidden {
		t.Fatalf("expected 403, got %v", err)
	}
	if err := mallory.c.Logout(context.Background(), a.nk); code(err) != http.StatusForbidden {
		t.Fatalf("expected 403 on logout, got %v", err)
	}
	if _, err := mallory.c.Map(context.Background(), protocol.MapRequest{NodeKey: mallory.nk}); !controlclient.IsUnauthorized(err) {
		t.Fatalf("unregistered node: %v", err)
	}
}

// streamer collects maps from a stream in the background.
type streamer struct {
	maps chan *protocol.MapResponse
	done chan error
}

func stream(t *testing.T, n *node) *streamer {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &streamer{maps: make(chan *protocol.MapResponse, 16), done: make(chan error, 1)}
	go func() {
		s.done <- n.c.StreamMap(ctx, protocol.MapRequest{NodeKey: n.nk, DiscoKey: n.disco}, func(m *protocol.MapResponse) error {
			s.maps <- m
			return nil
		})
	}()
	return s
}

func (s *streamer) next(t *testing.T, what string) *protocol.MapResponse {
	t.Helper()
	select {
	case m := <-s.maps:
		return m
	case err := <-s.done:
		t.Fatalf("%s: stream ended: %v", what, err)
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: timed out waiting for map", what)
	}
	return nil
}

func TestStreamUpdates(t *testing.T) {
	f := newFixture(t)
	k := f.authKey(true)
	a, b := f.newNode(key.MachinePublic{}), f.newNode(key.MachinePublic{})
	if _, err := a.register("a", k); err != nil {
		t.Fatal(err)
	}
	sa := stream(t, a)
	if m := sa.next(t, "initial"); len(m.Peers) != 0 {
		t.Fatalf("initial peers: %d", len(m.Peers))
	}
	waitOnline(t, f.srv, 1)

	// A new peer appears.
	rb, err := b.register("b", k)
	if err != nil {
		t.Fatal(err)
	}
	if m := sa.next(t, "peer joined"); len(m.Peers) != 1 || !m.Peers[0].NodeKey.Equal(b.nk) {
		t.Fatalf("after join: %+v", m.Peers)
	}

	// The peer reports an endpoint via a lite update.
	ep := netip.MustParseAddrPort("192.0.2.9:41641")
	if err := b.c.UpdateStatus(context.Background(), protocol.MapRequest{NodeKey: b.nk, DiscoKey: b.disco, Endpoints: []netip.AddrPort{ep}}); err != nil {
		t.Fatal(err)
	}
	if m := sa.next(t, "endpoint"); len(m.Peers) != 1 || len(m.Peers[0].Endpoints) != 1 || m.Peers[0].Endpoints[0] != ep {
		t.Fatalf("after endpoint update: %+v", m.Peers)
	}

	// An out-of-process change (admin CLI deleting the node) is noticed via the generation poll.
	if err := f.db.DeleteNode(context.Background(), int64(rb.Node.ID)); err != nil {
		t.Fatal(err)
	}
	if m := sa.next(t, "peer deleted"); len(m.Peers) != 0 {
		t.Fatalf("after delete: %+v", m.Peers)
	}

	// Logging out closes our own stream.
	if err := a.c.Logout(context.Background(), a.nk); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sa.done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream not closed after logout")
	}
}

func waitOnline(t *testing.T, s *Server, id int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !s.Online(id) {
		if time.Now().After(deadline) {
			t.Fatal("node never marked online")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestKeepAliveFiltered(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := New(context.Background(), d, Config{BaseDomain: "x.internal", KeepAlive: 20 * time.Millisecond}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); ts.Close(); d.Close() })
	f := &fixture{t: t, db: d, srv: s, ts: ts}
	a := f.newNode(key.MachinePublic{})
	if _, err := a.register("a", f.authKey(false)); err != nil {
		t.Fatal(err)
	}
	sa := stream(t, a)
	sa.next(t, "initial")
	time.Sleep(150 * time.Millisecond) // several keep-alives
	select {
	case m := <-sa.maps:
		b, _ := json.Marshal(m)
		t.Fatalf("keep-alive or duplicate map delivered: %s", b)
	default:
	}
	n, _ := d.GetNode(context.Background(), 1)
	if time.Since(n.LastSeen) > 2*time.Second {
		t.Fatal("keep-alives did not refresh last_seen")
	}
}
