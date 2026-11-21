package control

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestApprovalAndExpiryInMaps(t *testing.T) {
	bs := newBenchServer(t, 1, 3, false)
	ctx := context.Background()
	a, b := bs.ids[0], bs.ids[1]

	// An unapproved machine is cut off with a notice and hidden from peers.
	bs.db.SetMachineApproval(ctx, "tenant0", true)
	if _, err := bs.db.SQLForTest().ExecContext(ctx, `UPDATE nodes SET approved = 0 WHERE id = ?`, b); err != nil {
		t.Fatal(err)
	}
	m, _ := bs.srv.BuildMap(ctx, b)
	if len(m.Peers) != 0 || !strings.Contains(m.Notice, "waiting for approval") {
		t.Fatalf("unapproved machine's map: peers=%d notice=%q", len(m.Peers), m.Notice)
	}
	if ma, _ := bs.srv.BuildMap(ctx, a); len(ma.Peers) != 1 {
		t.Fatalf("peers still see the unapproved machine: %d peers", len(ma.Peers))
	}
	bs.db.ApproveNode(ctx, b)
	if m, _ := bs.srv.BuildMap(ctx, b); len(m.Peers) != 2 || m.Notice != "" {
		t.Fatalf("after approval: peers=%d notice=%q", len(m.Peers), m.Notice)
	}

	// A key expiring takes effect at that moment, without a database change.
	bs.db.SetNodeExpiry(ctx, b, time.Now().Add(1500*time.Millisecond))
	bs.srv.checkGeneration()
	if m, _ := bs.srv.BuildMap(ctx, b); m.Notice != "" {
		t.Fatalf("not expired yet: %q", m.Notice)
	}
	if !bs.srv.RelayAllowed(bs.keys[0], bs.keys[1]) {
		t.Fatal("relay refuses before expiry")
	}
	wake := bs.srv.bus.wait()
	time.Sleep(1600 * time.Millisecond)
	if !bs.srv.snapshotStale() {
		t.Fatal("snapshot should be stale after the expiry")
	}
	bs.srv.checkGeneration() // what the watcher does every tick
	select {
	case <-wake:
	default:
		t.Fatal("streams not woken when the key expired")
	}
	m, _ = bs.srv.BuildMap(ctx, b)
	if len(m.Peers) != 0 || !strings.Contains(m.Notice, "expired") {
		t.Fatalf("expired machine's map: peers=%d notice=%q", len(m.Peers), m.Notice)
	}
	if bs.srv.RelayAllowed(bs.keys[0], bs.keys[1]) {
		t.Fatal("relay still serves an expired machine")
	}
	// Never-expiring again.
	bs.db.SetNodeExpiry(ctx, b, time.Time{})
	if m, _ := bs.srv.BuildMap(ctx, b); m.Notice != "" {
		t.Fatalf("after removing expiry: %q", m.Notice)
	}
}

func TestEphemeralReaper(t *testing.T) {
	bs := newBenchServer(t, 1, 2, false)
	ctx := context.Background()
	db := bs.db.SQLForTest()
	old := time.Now().Add(-time.Hour).Unix()
	for _, id := range bs.ids {
		db.ExecContext(ctx, `UPDATE nodes SET ephemeral = 1, last_seen = ? WHERE id = ?`, old, id)
	}
	bs.srv.cfg.EphemeralTimeout = 30 * time.Minute
	// The first machine still has a map stream open: it stays.
	bs.srv.mu.Lock()
	bs.srv.online[bs.ids[0]] = 1
	bs.srv.mu.Unlock()
	bs.srv.reapEphemeral()
	nodes, _ := bs.db.ListNodes(ctx, 0)
	if len(nodes) != 1 || nodes[0].ID != bs.ids[0] {
		t.Fatalf("after reaping: %d nodes left (want only the online one)", len(nodes))
	}
}

// A map request (or /metrics) rebuilding the snapshot after a key expired,
// before the watcher's tick, must not hide the expiry from the watcher:
// streams are still woken and the relay stops serving the machine.
func TestExpirySeenAfterSomeoneElseRebuilt(t *testing.T) {
	bs := newBenchServer(t, 1, 2, false)
	ctx := context.Background()
	b := bs.ids[1]
	// Expiry is stored in whole seconds: aim at the start of a second.
	at := time.Now().Truncate(time.Second).Add(2 * time.Second)
	bs.db.SetNodeExpiry(ctx, b, at)
	bs.srv.checkGeneration()
	if !bs.srv.RelayAllowed(bs.keys[0], bs.keys[1]) {
		t.Fatal("relay refuses before expiry")
	}
	wake := bs.srv.bus.wait()
	time.Sleep(time.Until(at) + 100*time.Millisecond)
	bs.srv.BuildMap(ctx, bs.ids[0]) // rebuilds the snapshot first
	bs.srv.checkGeneration()
	select {
	case <-wake:
	default:
		t.Fatal("streams not woken: the expiry was missed")
	}
	if bs.srv.RelayAllowed(bs.keys[0], bs.keys[1]) {
		t.Fatal("relay still serves the expired machine")
	}
}
