package control

import (
	"context"
	"net/http"
	"testing"
	"time"

	"tailconnect/internal/iplimit"
	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

// A channel that never identifies a machine is closed; one that registers
// is kept.
func TestUnidentifiedConnectionClosed(t *testing.T) {
	f := newFixtureWith(t, func(c *Config) { c.IdentifyTimeout = 200 * time.Millisecond })
	stranger, member := f.newNode(key.MachinePublic{}), f.newNode(key.MachinePublic{})

	// The stranger opens a channel but its node key is unknown.
	_, err := stranger.c.Map(context.Background(), protocol.MapRequest{NodeKey: stranger.nk})
	if code(err) != http.StatusUnauthorized {
		t.Fatalf("unknown node's map: %v", err)
	}
	if _, err := member.register("laptop", f.authKey(false)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.stats.connRefused.unidentified.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("unidentified channel was not closed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if n := f.srv.stats.connRefused.unidentified.Load(); n != 1 {
		t.Fatalf("closed %d channels, want only the stranger's", n)
	}
	// The member's channel still works.
	if _, err := member.c.Map(context.Background(), protocol.MapRequest{NodeKey: member.nk}); err != nil {
		t.Fatalf("member after timeout: %v", err)
	}
}

func TestHandshakeRateLimit(t *testing.T) {
	f := newFixture(t)
	f.srv.handshakes = iplimit.NewRate(time.Hour, 2)
	for i := range 3 {
		n := f.newNode(key.MachinePublic{})
		_, err := n.c.Map(context.Background(), protocol.MapRequest{NodeKey: n.nk})
		want := http.StatusUnauthorized // handshake allowed, node unknown
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if code(err) != want {
			t.Fatalf("connection %d: %v, want %d", i, err, want)
		}
	}
}

func TestConnectionCap(t *testing.T) {
	f := newFixture(t)
	f.srv.connLimit = iplimit.NewCount(2, 100)
	var nodes []*node
	for i := range 3 {
		n := f.newNode(key.MachinePublic{})
		_, err := n.c.Map(context.Background(), protocol.MapRequest{NodeKey: n.nk})
		want := http.StatusUnauthorized
		if i == 2 {
			want = http.StatusServiceUnavailable
		}
		if code(err) != want {
			t.Fatalf("connection %d: %v, want %d", i, err, want)
		}
		nodes = append(nodes, n)
	}
	// Closing a channel frees its slot.
	nodes[0].c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := nodes[2].c.Map(context.Background(), protocol.MapRequest{NodeKey: nodes[2].nk})
		if code(err) == http.StatusUnauthorized {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot not freed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestFailedRegistrationLimit(t *testing.T) {
	f := newFixture(t)
	f.srv.regFails = iplimit.NewRate(time.Hour, 3)
	good := f.authKey(true)
	n := f.newNode(key.MachinePublic{})
	// A good key does not use up attempts.
	if _, err := n.register("ok", good); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		m := f.newNode(key.MachinePublic{})
		if _, err := m.register("guess", "tc-auth-wrong"); code(err) != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	m := f.newNode(key.MachinePublic{})
	if _, err := m.register("guess", good); code(err) != http.StatusTooManyRequests {
		t.Fatalf("after the limit: %v, want 429", err)
	}
	// A registered machine reconnecting is not affected.
	if _, err := n.c.Map(context.Background(), protocol.MapRequest{NodeKey: n.nk}); err != nil {
		t.Fatal(err)
	}
}
