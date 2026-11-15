package control

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"tailconnect/internal/acl"
	"tailconnect/internal/protocol"
)

func TestAccessRulesInMaps(t *testing.T) {
	bs := newBenchServer(t, 1, 3, false) // tenant0: m0, m1, m2
	ctx := context.Background()
	laptop, server, printer := bs.ids[0], bs.ids[1], bs.ids[2]
	bs.db.SetNodeTags(ctx, laptop, []string{"staff"})
	bs.db.SetNodeTags(ctx, server, []string{"web"})
	u, _ := bs.db.GetUser(ctx, "tenant0")
	peers := func(id int64) map[string]protocol.Node {
		m, err := bs.srv.BuildMap(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		// The fast encoding must match, whatever the rules.
		want, _ := json.Marshal(m)
		got, _ := bs.srv.BuildMapJSON(ctx, id)
		if !bytes.Equal(got, want) {
			t.Fatalf("node %d: BuildMapJSON differs\n got: %s\nwant: %s", id, got, want)
		}
		out := map[string]protocol.Node{}
		for _, p := range m.Peers {
			out[p.Name] = p
		}
		return out
	}

	// No rules: everyone sees everyone, unrestricted.
	if p := peers(server); len(p) != 2 || p["m0.tenant0.tc.internal"].NoInitiate {
		t.Fatalf("no rules: %+v", p)
	}

	// staff → web on tcp:443 and ping.
	bs.db.AddRule(ctx, u.ID, "tag:staff", "tag:web", "tcp:443,icmp")
	bs.srv.checkGeneration() // what the watcher does every second: refreshes the relay policy
	sp := peers(server)
	if len(sp) != 1 {
		t.Fatalf("server should only see the laptop now: %v", sp)
	}
	lap := sp["m0.tenant0.tc.internal"]
	if !lap.NoInitiate || acl.FormatPorts(acl.Access{Ranges: lap.Inbound}) != "tcp:443,icmp" {
		t.Fatalf("laptop as seen by the server: noInitiate=%v inbound=%v", lap.NoInitiate, lap.Inbound)
	}
	lp := peers(laptop)
	if srv := lp["m1.tenant0.tc.internal"]; len(lp) != 1 || !srv.NoInitiate || len(srv.Inbound) != 0 {
		t.Fatalf("server as seen by the laptop (may not initiate at all): %+v", lp)
	}
	if p := peers(printer); len(p) != 0 {
		t.Fatalf("printer has no rule: should see nobody, sees %v", p)
	}
	// The relay follows the rules.
	if !bs.srv.RelayAllowed(bs.keys[0], bs.keys[1]) || !bs.srv.RelayAllowed(bs.keys[1], bs.keys[0]) {
		t.Fatal("laptop ↔ server must be relayable (replies flow back)")
	}
	if bs.srv.RelayAllowed(bs.keys[0], bs.keys[2]) {
		t.Fatal("laptop ↔ printer relayed without a rule")
	}

	// A "*" rule restores everything.
	bs.db.AddRule(ctx, u.ID, "*", "*", "*")
	if p := peers(printer); len(p) != 2 || p["m0.tenant0.tc.internal"].NoInitiate {
		t.Fatalf("after * → *: %+v", p)
	}
}

// TestExitNodesInMaps: an exit node shows as one to its own account's
// machines that may send it anything, never to other accounts' machines
// through a share, and Self tells the exit node itself.
func TestExitNodesInMaps(t *testing.T) {
	bs := newBenchServer(t, 2, 2, true) // tenant0: m0 (shared with tenant1), m1; tenant1: m0 (shared with tenant0), m1
	ctx := context.Background()
	exit, lap, other := bs.ids[0], bs.ids[1], bs.ids[3]
	peer := func(id, of int64) (protocol.Node, protocol.Node) {
		t.Helper()
		m, err := bs.srv.BuildMap(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(m)
		if got, _ := bs.srv.BuildMapJSON(ctx, id); !bytes.Equal(got, want) {
			t.Fatalf("node %d: BuildMapJSON differs\n got: %s\nwant: %s", id, got, want)
		}
		for _, p := range m.Peers {
			if int64(p.ID) == of {
				return m.Self, p
			}
		}
		t.Fatalf("node %d doesn't see node %d", id, of)
		return protocol.Node{}, protocol.Node{}
	}
	if _, p := peer(lap, exit); p.ExitNode {
		t.Fatal("exit node role on by default")
	}
	if err := bs.db.SetNodeExitNode(ctx, exit, true); err != nil {
		t.Fatal(err)
	}
	if self, _ := peer(exit, lap); !self.ExitNode {
		t.Fatal("the exit node isn't told it is one")
	}
	if _, p := peer(lap, exit); !p.ExitNode {
		t.Fatal("its own account doesn't see the exit node")
	}
	if _, p := peer(other, exit); !p.Shared || p.ExitNode {
		t.Fatalf("another account sees a shared exit node as one: %+v", p)
	}

	// Rules that let the exit node open connections to the laptop but not
	// the other way: the laptop can't use it.
	u, _ := bs.db.GetUser(ctx, "tenant0")
	bs.db.SetNodeTags(ctx, exit, []string{"gw"})
	bs.db.SetNodeTags(ctx, lap, []string{"lap"})
	bs.db.AddRule(ctx, u.ID, "tag:gw", "tag:lap", "*")
	if _, p := peer(lap, exit); p.ExitNode {
		t.Fatal("exit node offered to a machine the rules don't let send to it")
	}
	bs.db.AddRule(ctx, u.ID, "tag:lap", "tag:gw", "*")
	if _, p := peer(lap, exit); !p.ExitNode {
		t.Fatal("exit node hidden although the rules allow everything")
	}
}
