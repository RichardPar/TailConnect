package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/key"
	"tailconnect/internal/metrics"
	"tailconnect/internal/relay"
)

func TestRelayAPIToken(t *testing.T) {
	f := newFixture(t)
	secret, _, err := f.db.CreateRelayToken(context.Background(), "edge")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		auth string
		want int
	}{
		{"", http.StatusUnauthorized},
		{"Bearer tc-relay-wrong", http.StatusUnauthorized},
		{"Bearer " + secret, http.StatusOK},
	} {
		req, _ := http.NewRequest("POST", f.ts.URL+"/relay-api/v1/allowed", strings.NewReader(`{"Pairs":[]}`))
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%q: %d, want %d", c.auth, resp.StatusCode, c.want)
		}
	}
	if _, _, err := f.db.CreateRelayToken(context.Background(), "edge"); err == nil {
		t.Error("duplicate relay name accepted")
	}
}

// joinDirect registers a machine for account user, returning its key.
func (f *fixture) joinDirect(user, host string) (key.NodePrivate, int64) {
	f.t.Helper()
	ctx := context.Background()
	u, err := f.db.GetUser(ctx, user)
	if err != nil {
		if u, err = f.db.CreateUser(ctx, user); err != nil {
			f.t.Fatal(err)
		}
	}
	k, _, err := f.db.CreatePreAuthKey(ctx, db.CreatePreAuthKeyParams{UserID: u.ID, TTL: time.Hour})
	if err != nil {
		f.t.Fatal(err)
	}
	nk := key.NewPrivate[key.NodeKind]()
	res, err := f.db.RegisterNode(ctx, db.RegisterParams{
		MachineKey: key.NewPrivate[key.MachineKind]().Public().String(), NodeKey: nk.Public().String(),
		DiscoKey: key.NewPrivate[key.DiscoKind]().Public().String(), Hostname: host, AuthKey: k, Alloc: f.srv.ipam.Next,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return nk, res.Node.ID
}

type relayPkt struct {
	src  key.NodePublic
	data string
}

func relayClient(t *testing.T, url string, k key.NodePrivate) (*relay.Client, chan relayPkt) {
	t.Helper()
	ch := make(chan relayPkt, 16)
	c, err := relay.NewClient(relay.ClientOptions{URL: url, NodeKey: k, Recv: func(src key.NodePublic, b []byte) {
		ch <- relayPkt{src, string(b)}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, ch
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A standalone relay serves only the control server's machines, keeps
// accounts apart, and follows changes as they happen.
func TestStandaloneRelayAsksControl(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a1, _ := f.joinDirect("alice", "a1")
	a2, a2ID := f.joinDirect("alice", "a2")
	b1, _ := f.joinDirect("bob", "b1")
	f.srv.checkGeneration()

	secret, _, err := f.db.CreateRelayToken(ctx, "edge")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pol := relay.NewRemotePolicy(f.ts.URL, secret, log)
	if err := pol.Check(ctx); err != nil {
		t.Fatal(err)
	}
	go pol.Run(ctx)
	rs := relay.NewServer(key.NewPrivate[key.RelayKind](), pol.Authorize, log)
	rs.SetAllow(pol.Allow)
	rts := httptest.NewServer(rs)
	t.Cleanup(func() { rs.Close(); rts.Close() })
	url := rts.URL + "/relay"

	// Not a machine of this network: refused.
	stranger, _ := relayClient(t, url, key.NewPrivate[key.NodeKind]())
	eventually(t, "stranger refused", func() bool {
		e := stranger.LastError()
		return e != nil && strings.Contains(e.Error(), "not registered")
	})
	if stranger.Connected() {
		t.Fatal("unregistered machine connected")
	}

	ca1, _ := relayClient(t, url, a1)
	_, ch2 := relayClient(t, url, a2)
	_, chb := relayClient(t, url, b1)
	eventually(t, "clients connected", func() bool { n, _, _ := rs.Stats(); return n == 3 })

	// Same account: forwarded.
	ca1.Send(a2.Public(), []byte("hi a2"))
	select {
	case p := <-ch2:
		if p.data != "hi a2" {
			t.Fatalf("got %+v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("same-account packet not relayed")
	}
	// Another account: denied.
	ca1.Send(b1.Public(), []byte("hi bob"))
	eventually(t, "cross-account packet denied", func() bool { return rs.Denied() == 1 })
	select {
	case p := <-chb:
		t.Fatalf("bob got %+v", p)
	default:
	}

	// a2 is deleted while connected: the cached "allowed" must not outlive it.
	if err := f.db.DeleteNode(ctx, a2ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "deleted machine's traffic denied", func() bool {
		ca1.Send(a2.Public(), []byte("still there?"))
		return rs.Denied() >= 2
	})

	// The relay's metrics agree.
	reg := metrics.NewRegistry()
	rs.RegisterMetrics(reg)
	pol.RegisterMetrics(reg)
	// (Packets sent to a2 while its deletion was reaching the relay may have
	// been forwarded, so "forwarded" is at least the one before.)
	fwd, denied := metricValue(t, reg, `tc_relay_packets_total{result="forwarded"}`), metricValue(t, reg, `tc_relay_packets_total{result="denied"}`)
	clients, asked := metricValue(t, reg, `tc_relay_clients`), metricValue(t, reg, `tc_relay_control_requests_total{result="ok"}`)
	if fwd < 1 || denied < 2 || clients != 3 || asked < 3 {
		t.Errorf("relay metrics: forwarded %v, denied %v, clients %v, control requests %v", fwd, denied, clients, asked)
	}

	// Revoking the relay's token: new connections are refused.
	if err := f.db.DeleteRelayToken(ctx, "edge"); err != nil {
		t.Fatal(err)
	}
	late, _ := relayClient(t, url, a1)
	eventually(t, "connection refused after revocation", func() bool {
		e := late.LastError()
		return e != nil && strings.Contains(e.Error(), "control server unavailable")
	})
}
