package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

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
	t.Cleanup(func() { d.Close() })
	s, err := New(context.Background(), d, Config{BaseDomain: "home.internal"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &fixture{t: t, db: d, srv: s, ts: ts}
}

func (f *fixture) authKey(reusable bool) string {
	f.t.Helper()
	ctx := context.Background()
	u, err := f.db.GetUser(ctx, "alice")
	if err != nil {
		u, err = f.db.CreateUser(ctx, "alice")
		if err != nil {
			f.t.Fatal(err)
		}
	}
	k, _, err := f.db.CreatePreAuthKey(ctx, db.CreatePreAuthKeyParams{UserID: u.ID, Reusable: reusable, TTL: time.Hour})
	if err != nil {
		f.t.Fatal(err)
	}
	return k
}

func (f *fixture) post(path string, body, out any) int {
	f.t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(f.ts.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			f.t.Fatal(err)
		}
	}
	return resp.StatusCode
}

type client struct {
	machine key.MachinePublic
	node    key.NodePublic
	disco   key.DiscoPublic
}

func newClient() client {
	return client{
		machine: key.NewPrivate[key.MachineKind]().Public(),
		node:    key.NewPrivate[key.NodeKind]().Public(),
		disco:   key.NewPrivate[key.DiscoKind]().Public(),
	}
}

func (c client) register(host, authKey string) protocol.RegisterRequest {
	return protocol.RegisterRequest{
		Version: protocol.CurrentVersion, MachineKey: c.machine, NodeKey: c.node, DiscoKey: c.disco,
		AuthKey: authKey, Hostinfo: protocol.Hostinfo{Hostname: host, OS: "linux"},
	}
}

func TestServerKeyStable(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.ts.URL + "/key")
	if err != nil {
		t.Fatal(err)
	}
	var kr protocol.ServerKeyResponse
	json.NewDecoder(resp.Body).Decode(&kr)
	resp.Body.Close()
	if kr.MachineKey.IsZero() || !kr.MachineKey.Equal(f.srv.MachinePublic()) {
		t.Fatalf("bad server key %v", kr.MachineKey)
	}
	// A second server on the same DB must reuse the stored key.
	s2, err := New(context.Background(), f.db, Config{BaseDomain: "home.internal"}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !s2.MachinePublic().Equal(f.srv.MachinePublic()) {
		t.Fatal("machine key not persisted")
	}
}

func TestRegisterAndMap(t *testing.T) {
	f := newFixture(t)
	k := f.authKey(true)
	a, b := newClient(), newClient()

	if code := f.post("/machine/register", a.register("laptop", "tc-auth-wrong"), nil); code != http.StatusUnauthorized {
		t.Fatalf("bad auth key: status %d", code)
	}
	if code := f.post("/machine/register", protocol.RegisterRequest{AuthKey: k}, nil); code != http.StatusBadRequest {
		t.Fatalf("missing keys: status %d", code)
	}

	var ra, rb protocol.RegisterResponse
	if code := f.post("/machine/register", a.register("laptop", k), &ra); code != http.StatusOK {
		t.Fatalf("register a: %d", code)
	}
	if code := f.post("/machine/register", b.register("phone", k), &rb); code != http.StatusOK {
		t.Fatalf("register b: %d", code)
	}
	if ra.Node.Name != "laptop.home.internal" || ra.Node.Addresses[0] != netip.MustParsePrefix("100.64.0.1/32") {
		t.Fatalf("unexpected node a: %+v", ra.Node)
	}

	ep := netip.MustParseAddrPort("198.51.100.7:41641")
	var m protocol.MapResponse
	if code := f.post("/machine/map", protocol.MapRequest{NodeKey: a.node, DiscoKey: a.disco, Endpoints: []netip.AddrPort{ep}}, &m); code != http.StatusOK {
		t.Fatalf("map a: %d", code)
	}
	if !m.Self.NodeKey.Equal(a.node) || len(m.Peers) != 1 || !m.Peers[0].NodeKey.Equal(b.node) {
		t.Fatalf("unexpected map: %+v", m)
	}
	if !m.DNS.MagicDNS || m.DNS.Domain != "home.internal" || m.DNS.Resolver != protocol.MagicDNSAddr {
		t.Fatalf("unexpected dns config: %+v", m.DNS)
	}

	// b should now see a's reported endpoint.
	if code := f.post("/machine/map", protocol.MapRequest{NodeKey: b.node, DiscoKey: b.disco}, &m); code != http.StatusOK {
		t.Fatalf("map b: %d", code)
	}
	if len(m.Peers) != 1 || len(m.Peers[0].Endpoints) != 1 || m.Peers[0].Endpoints[0] != ep {
		t.Fatalf("b does not see a's endpoint: %+v", m.Peers)
	}
	if !m.Peers[0].DiscoKey.Equal(a.disco) {
		t.Fatal("peer disco key mismatch")
	}
}

func TestMapUnknownNode(t *testing.T) {
	f := newFixture(t)
	if code := f.post("/machine/map", protocol.MapRequest{NodeKey: newClient().node}, nil); code != http.StatusUnauthorized {
		t.Fatalf("status %d", code)
	}
}
