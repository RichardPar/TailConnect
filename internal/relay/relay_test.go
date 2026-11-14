package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"tailconnect/internal/key"
)

type pkt struct {
	src  key.NodePublic
	data string
}

func newServer(t *testing.T, auth AuthorizeFunc) (*Server, string) {
	t.Helper()
	s := NewServer(key.NewPrivate[key.RelayKind](), auth, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(s)
	t.Cleanup(func() { s.Close(); ts.Close() })
	return s, ts.URL + "/relay"
}

func newClient(t *testing.T, url string, priv key.NodePrivate) (*Client, chan pkt) {
	t.Helper()
	ch := make(chan pkt, 16)
	c, err := NewClient(ClientOptions{URL: url, NodeKey: priv, Recv: func(src key.NodePublic, b []byte) {
		ch <- pkt{src, string(b)}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, ch
}

func waitConnected(t *testing.T, cs ...*Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for _, c := range cs {
		for !c.Connected() {
			if time.Now().After(deadline) {
				t.Fatalf("client never connected: %v", c.LastError())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func recv(t *testing.T, ch chan pkt) pkt {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for packet")
	}
	return pkt{}
}

func TestForwarding(t *testing.T) {
	s, url := newServer(t, nil)
	ka, kb := key.NewPrivate[key.NodeKind](), key.NewPrivate[key.NodeKind]()
	a, _ := newClient(t, url, ka)
	b, bch := newClient(t, url, kb)
	waitConnected(t, a, b)

	if err := a.Send(kb.Public(), []byte("hello b")); err != nil {
		t.Fatal(err)
	}
	if p := recv(t, bch); p.data != "hello b" || !p.src.Equal(ka.Public()) {
		t.Fatalf("got %+v", p)
	}
	// Large packet.
	big := make([]byte, 60000)
	for i := range big {
		big[i] = byte(i)
	}
	a.Send(kb.Public(), big)
	if p := recv(t, bch); p.data != string(big) {
		t.Fatal("large packet corrupted")
	}
	// Unknown destination is dropped, not an error to the sender.
	if err := a.Send(key.NewPrivate[key.NodeKind]().Public(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n, fwd, drop := s.Stats(); n != 2 || fwd != 2 || drop != 1 {
		t.Fatalf("stats: clients=%d forwarded=%d dropped=%d", n, fwd, drop)
	}
}

func TestAuthorization(t *testing.T) {
	allowed := key.NewPrivate[key.NodeKind]()
	_, url := newServer(t, func(_ context.Context, k key.NodePublic) error {
		if k.Equal(allowed.Public()) {
			return nil
		}
		return errors.New("unknown node")
	})
	ok, _ := newClient(t, url, allowed)
	bad, _ := newClient(t, url, key.NewPrivate[key.NodeKind]())
	waitConnected(t, ok)
	time.Sleep(200 * time.Millisecond)
	if bad.Connected() {
		t.Fatal("unauthorized client connected")
	}
	if err := bad.LastError(); err == nil {
		t.Fatal("expected an error for the unauthorized client")
	}
}

func TestDuplicateKeyNewestWins(t *testing.T) {
	_, url := newServer(t, nil)
	k, ks := key.NewPrivate[key.NodeKind](), key.NewPrivate[key.NodeKind]()
	sender, _ := newClient(t, url, ks)
	first, ch1 := newClient(t, url, k)
	waitConnected(t, sender, first)
	second, ch2 := newClient(t, url, k)
	waitConnected(t, second)
	time.Sleep(100 * time.Millisecond)
	sender.Send(k.Public(), []byte("to newest"))
	got := recv(t, ch2)
	if got.data != "to newest" {
		t.Fatalf("got %+v", got)
	}
	select {
	case p := <-ch1:
		t.Fatalf("old connection received %+v", p)
	default:
	}
}

func TestNotARelay(t *testing.T) {
	ts := httptest.NewServer(nil) // 404 for everything
	defer ts.Close()
	c, err := NewClient(ClientOptions{URL: ts.URL + "/relay", NodeKey: key.NewPrivate[key.NodeKind]()})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if c.Connected() || c.LastError() == nil {
		t.Fatal("expected connection failure")
	}
	c.Close()
	if err := c.Send(key.NewPrivate[key.NodeKind]().Public(), []byte("x")); err == nil {
		t.Fatal("send after close should fail")
	}
}

func TestQueuedWhileConnecting(t *testing.T) {
	_, url := newServer(t, nil)
	ka, kb := key.NewPrivate[key.NodeKind](), key.NewPrivate[key.NodeKind]()
	b, bch := newClient(t, url, kb)
	waitConnected(t, b)
	a, _ := newClient(t, url, ka)
	// Send immediately, before a's connection is established.
	if err := a.Send(kb.Public(), []byte("early")); err != nil {
		t.Fatal(err)
	}
	if p := recv(t, bch); p.data != "early" {
		t.Fatalf("got %+v", p)
	}
}
