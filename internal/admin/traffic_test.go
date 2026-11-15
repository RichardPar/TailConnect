package admin

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/ipam"
	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

// The Machines API carries each machine's reported traffic, with peers named.
func TestTrafficInNodes(t *testing.T) {
	f := newFx(t)
	alice := f.account("alice", db.RoleTenant)
	ctx := context.Background()
	u, _ := f.db.GetUser(ctx, "alice")
	join := func(host string) (int64, key.NodePublic) {
		nk := key.NewPrivate[key.NodeKind]().Public()
		k, _, _ := f.db.CreatePreAuthKey(ctx, db.CreatePreAuthKeyParams{UserID: u.ID, TTL: time.Hour})
		res, err := f.db.RegisterNode(ctx, db.RegisterParams{MachineKey: "m-" + host, NodeKey: nk.String(), Hostname: host, AuthKey: k, Alloc: ipam.Default().Next})
		if err != nil {
			t.Fatal(err)
		}
		return res.Node.ID, nk
	}
	laptop, _ := join("laptop")
	_, nasKey := join("nas")
	f.srv.info.Traffic = func(id int64) *protocol.MachineTraffic {
		if id != laptop {
			return nil
		}
		return &protocol.MachineTraffic{Updated: time.Now(), RxBytes: 3e9, TxBytes: 1e8, RxRate: 2e6, TxRate: 5e4,
			Peers: []protocol.PeerTrafficStats{{NodeKey: nasKey, RxBytes: 3e9, TxBytes: 1e8, RxRate: 2e6, TxRate: 5e4}}}
	}

	code, _, body := f.do(alice, "GET", "/api/v1/nodes", nil, nil)
	if code != 200 {
		t.Fatalf("nodes: %d", code)
	}
	var nodes []apiNode
	if err := json.Unmarshal(body, &nodes); err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		switch n.Name {
		case "laptop":
			tr := n.Traffic
			if tr == nil || tr.RxRate != 2e6 || tr.Rx != 3e9 || len(tr.Peers) != 1 || tr.Peers[0].Name != "nas" || tr.Peers[0].FQDN != "nas.alice.home.internal" {
				t.Fatalf("laptop traffic: %+v", tr)
			}
		case "nas":
			if n.Traffic != nil {
				t.Fatalf("nas reported nothing, but has traffic %+v", n.Traffic)
			}
		}
	}
}
