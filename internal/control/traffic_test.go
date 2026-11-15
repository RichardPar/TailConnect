package control

import (
	"context"
	"testing"
	"time"

	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

func TestTrafficRates(t *testing.T) {
	var tt trafficTable
	p1, p2 := key.NewPrivate[key.NodeKind]().Public(), key.NewPrivate[key.NodeKind]().Public()
	t0 := time.Unix(1000, 0)
	if tt.get(1, t0) != nil {
		t.Fatal("traffic for a machine that never reported")
	}
	tt.report(1, []protocol.PeerTraffic{{NodeKey: p1, RxBytes: 1000, TxBytes: 500}}, t0)
	if m := tt.get(1, t0); m.RxRate != 0 || m.RxBytes != 1000 {
		t.Fatalf("first report: %+v", m)
	}
	// 30 s later: p1 moved 30 MB in, 3 MB out; p2 appeared.
	t1 := t0.Add(30 * time.Second)
	tt.report(1, []protocol.PeerTraffic{
		{NodeKey: p1, RxBytes: 1000 + 30e6, TxBytes: 500 + 3e6},
		{NodeKey: p2, RxBytes: 10, TxBytes: 10},
	}, t1)
	m := tt.get(1, t1)
	if m.RxRate != 1e6 || m.TxRate != 1e5 || m.RxBytes != 1010+30e6 || len(m.Peers) != 2 || m.Peers[0].NodeKey != p1 {
		t.Fatalf("rates: %+v", m)
	}
	// p1's counters went down (its session restarted): no rate, new totals.
	t2 := t1.Add(30 * time.Second)
	tt.report(1, []protocol.PeerTraffic{{NodeKey: p1, RxBytes: 100, TxBytes: 100}}, t2)
	if m := tt.get(1, t2); m.RxRate != 0 || m.RxBytes != 100 || len(m.Peers) != 1 {
		t.Fatalf("after reset: %+v", m)
	}
	// Busy, then silent (idle machines don't report): rates drop to zero.
	t3 := t2.Add(10 * time.Second)
	tt.report(1, []protocol.PeerTraffic{{NodeKey: p1, RxBytes: 100 + 1e6, TxBytes: 100}}, t3)
	if tt.get(1, t3).RxRate == 0 {
		t.Fatal("no rate while busy")
	}
	if m := tt.get(1, t3.Add(trafficIdle+time.Second)); m.RxRate != 0 || m.RxBytes != 100+1e6 {
		t.Fatalf("idle: %+v", m)
	}
}

// Machines report over the control channel; only for themselves.
func TestTrafficReport(t *testing.T) {
	f := newFixture(t)
	k := f.authKey(true)
	a, b := f.newNode(key.MachinePublic{}), f.newNode(key.MachinePublic{})
	ra, err := a.register("a", k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.register("b", k); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := a.c.ReportTraffic(ctx, protocol.TrafficRequest{NodeKey: a.nk, Peers: []protocol.PeerTraffic{{NodeKey: b.nk, RxBytes: 5, TxBytes: 7}}}); err != nil {
		t.Fatal(err)
	}
	m := f.srv.Traffic(int64(ra.Node.ID))
	if m == nil || len(m.Peers) != 1 || m.Peers[0].NodeKey != b.nk || m.TxBytes != 7 {
		t.Fatalf("traffic: %+v", m)
	}
	// b can't report on a's behalf.
	if err := b.c.ReportTraffic(ctx, protocol.TrafficRequest{NodeKey: a.nk}); code(err) != 403 {
		t.Fatalf("report for another machine: %v", err)
	}
}
