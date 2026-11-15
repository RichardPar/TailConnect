package control

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"tailconnect/internal/db"
)

// BuildMapJSON must produce exactly what encoding BuildMap's result would,
// for every kind of peer, or clients would see different maps.
func TestBuildMapJSONMatchesBuildMap(t *testing.T) {
	// 3 accounts of 3 machines; each account's first machine is shared with
	// the next account, so tenant0 and tenant2 also get a mutual-share pair
	// once tenant2's machine is shared back.
	bs := newBenchServer(t, 3, 3, true)
	ctx := context.Background()
	check := func(when string) {
		t.Helper()
		for _, id := range bs.ids {
			m, err := bs.srv.BuildMap(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := json.Marshal(m)
			got, err := bs.srv.BuildMapJSON(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s: node %d: BuildMapJSON differs from json.Marshal(BuildMap)\n got: %s\nwant: %s", when, id, got, want)
			}
		}
	}
	check("one-way shares")

	// Mutual share: tenant1's first machine (shared with tenant2) gets
	// tenant2's first machine shared back.
	back, err := bs.db.ShareWith(ctx, bs.ids[6], "tenant1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := bs.db.GetUser(ctx, "tenant1")
	bs.db.AcceptShare(ctx, back.ID, u.ID)
	check("mutual share")

	// A suspended account: its machines get the notice map, others drop them.
	bs.db.SetUserStatus(ctx, "tenant2", db.StatusSuspended)
	check("suspended account")

	// Peer counts sanity: tenant0's first machine sees its 2 siblings, the 3
	// machines of tenant1 (it's shared with tenant1), tenant2's shared
	// machine is gone (suspended).
	m, _ := bs.srv.BuildMap(ctx, bs.ids[0])
	if len(m.Peers) != 5 {
		t.Fatalf("tenant0/m0 peers: %d, want 5", len(m.Peers))
	}
}
