package control

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"testing"

	"tailconnect/internal/db"
	"tailconnect/internal/protocol"
)

// encOf encodes a map the way encodeMap does.
func encOf(t *testing.T, resp protocol.MapResponse, peers []protocol.Node) *mapEnc {
	t.Helper()
	resp.Peers = []protocol.Node{}
	head, _ := json.Marshal(resp)
	m := &mapEnc{head: head, at: bytes.Index(head, peersPlaceholder)}
	for _, p := range peers {
		b, _ := json.Marshal(p)
		m.ids, m.encs = append(m.ids, p.ID), append(m.encs, b)
	}
	return m
}

func decodeMap(t *testing.T, b []byte) *protocol.MapResponse {
	t.Helper()
	var m protocol.MapResponse
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return &m
}

// Applying each message to the client's last map gives exactly the full map,
// through random joins, changes, departures and self/DNS changes.
func TestDeltasReproduceFullMaps(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	resp := protocol.MapResponse{Self: protocol.Node{ID: 1, Name: "self"}, DNS: protocol.DNSConfig{Domain: "x.internal"}}
	peers := map[protocol.NodeID]protocol.Node{}
	var ds deltaState
	var client *protocol.MapResponse
	deltas, fulls := 0, 0
	for step := 0; step < 500; step++ {
		switch r := rng.IntN(10); {
		case r < 4: // join or change
			id := protocol.NodeID(2 + rng.IntN(30))
			peers[id] = protocol.Node{ID: id, Name: "n", HomeRelay: rng.IntN(3),
				Endpoints: []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(rng.IntN(4))}), 41641)}}
		case r < 7: // leave
			for id := range peers {
				delete(peers, id)
				break
			}
		case r < 8: // self changes: must be a full map
			resp.Self.HomeRelay = rng.IntN(3)
		}
		var list []protocol.Node
		for id := protocol.NodeID(0); id < 40; id++ {
			if p, ok := peers[id]; ok {
				list = append(list, p)
			}
		}
		m := encOf(t, resp, list)
		want := decodeMap(t, m.full())
		msg := ds.next(m)
		if msg == nil {
			if client == nil || !reflect.DeepEqual(client, want) {
				t.Fatalf("step %d: nothing sent, but the map changed", step)
			}
			continue
		}
		got := decodeMap(t, msg)
		if got.Delta {
			deltas++
			if client == nil {
				t.Fatal("delta first")
			}
			if len(msg) >= len(m.full()) && len(list) > 3 {
				t.Errorf("step %d: delta (%d bytes) not smaller than the full map (%d)", step, len(msg), len(m.full()))
			}
			got = protocol.ApplyDelta(client, got)
		} else {
			fulls++
		}
		if len(got.Peers) == 0 {
			got.Peers = []protocol.Node{} // an empty list decodes either way
		}
		if len(want.Peers) == 0 {
			want.Peers = []protocol.Node{}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("step %d: client map\n%+v\nwant\n%+v", step, got, want)
		}
		client = got
	}
	if deltas < 100 || fulls < 10 {
		t.Fatalf("deltas %d, full maps %d", deltas, fulls)
	}
}

// In a 200-machine account, one machine reporting a new endpoint costs each
// of the others a one-peer delta instead of a 199-peer map. (At 1,000
// machines: 343 KB → 0.4 KB.)
func TestDeltaSize(t *testing.T) {
	bs := newBenchServer(t, 1, 200, false)
	ctx := t.Context()
	var ds deltaState
	first, err := bs.srv.encodeMap(ctx, bs.ids[0])
	if err != nil {
		t.Fatal(err)
	}
	full := ds.next(first)
	n, err := bs.db.GetNode(ctx, bs.ids[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.db.UpdateNodeStatus(ctx, n.ID, db.NodeStatus{DiscoKey: n.DiscoKey,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:41641")}}); err != nil {
		t.Fatal(err)
	}
	m, err := bs.srv.encodeMap(ctx, bs.ids[0])
	if err != nil {
		t.Fatal(err)
	}
	delta := ds.next(m)
	d := decodeMap(t, delta)
	if !d.Delta || len(d.PeersChanged) != 1 || d.PeersChanged[0].ID != protocol.NodeID(n.ID) || len(d.PeersRemoved) != 0 {
		t.Fatalf("delta: %s", delta)
	}
	t.Logf("full map %d bytes, delta %d bytes (%.2f%%)", len(full), len(delta), 100*float64(len(delta))/float64(len(full)))
	if len(delta)*100 > len(full) {
		t.Fatalf("delta %d bytes is over 1%% of the full map (%d)", len(delta), len(full))
	}
}
