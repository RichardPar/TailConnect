package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"tailconnect/internal/db"
	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

// snapshot is everything network maps are built from, read from the
// database once per generation and shared by every map built in it. Every
// change that affects a map bumps the generation (database triggers), so a
// snapshot for the current generation is exact. Without it, each map
// re-read and re-parsed every machine: with N machines in an account one
// change cost O(N²) work as all N maps were rebuilt.
type snapshot struct {
	gen    int64
	nodes  map[int64]*snapNode
	byUser map[int64][]int64 // machine IDs per account, sorted
	// Shares in effect: machines shared with each account, and the accounts
	// each machine is shared with.
	sharedIn map[int64][]int64
	sharedTo map[int64][]int64
	keys     map[key.NodePublic]int64 // node key → machine ID (active accounts only)
}

type snapNode struct {
	db    db.Node
	proto protocol.Node // LastSeen cleared: maps don't carry it

	// The node's JSON as a peer, encoded at most once per snapshot for each
	// way it can appear: own account, shared (no-initiate), shared (may
	// initiate). Encoding is most of the cost of a map, and a node appears
	// in many maps per generation.
	encOnce [3]sync.Once
	enc     [3][]byte
}

const (
	peerOwn = iota
	peerSharedNoInitiate
	peerSharedInitiate
)

func (n *snapNode) peerJSON(variant int) []byte {
	n.encOnce[variant].Do(func() {
		pn := n.proto
		pn.Shared = variant != peerOwn
		pn.NoInitiate = variant == peerSharedNoInitiate
		n.enc[variant], _ = json.Marshal(pn)
	})
	return n.enc[variant]
}

// currentSnapshot returns the snapshot for the database's current
// generation, building it if needed. Builds are serialised; concurrent map
// builds for the same generation share one.
func (s *Server) currentSnapshot(ctx context.Context) (*snapshot, error) {
	gen, err := s.db.Generation(ctx)
	if err != nil {
		return nil, err
	}
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if s.snap != nil && s.snap.gen == gen {
		return s.snap, nil
	}
	// Read the generation before the data: a change racing with the build
	// is in the snapshot or bumps the generation again, never lost.
	snap, err := s.buildSnapshot(ctx, gen)
	if err != nil {
		return nil, err
	}
	s.snap = snap
	return snap, nil
}

func (s *Server) buildSnapshot(ctx context.Context, gen int64) (*snapshot, error) {
	nodes, err := s.db.ListNodes(ctx, 0)
	if err != nil {
		return nil, err
	}
	shares, err := s.db.ListShares(ctx, db.ShareFilter{Accepted: true})
	if err != nil {
		return nil, err
	}
	snap := &snapshot{
		gen: gen, nodes: make(map[int64]*snapNode, len(nodes)), byUser: map[int64][]int64{},
		sharedIn: map[int64][]int64{}, sharedTo: map[int64][]int64{}, keys: make(map[key.NodePublic]int64, len(nodes)),
	}
	for _, n := range nodes {
		pn, err := s.toProtocol(n)
		if err != nil {
			return nil, err
		}
		pn.LastSeen = nil
		snap.nodes[n.ID] = &snapNode{db: n, proto: pn}
		snap.byUser[n.UserID] = append(snap.byUser[n.UserID], n.ID)
		if n.UserStatus == db.StatusActive {
			snap.keys[pn.NodeKey] = n.ID
		}
	}
	for _, ids := range snap.byUser {
		slices.Sort(ids)
	}
	for _, sh := range shares {
		if sh.InEffect() && snap.nodes[sh.NodeID] != nil {
			snap.sharedIn[sh.RecipientID] = append(snap.sharedIn[sh.RecipientID], sh.NodeID)
			snap.sharedTo[sh.NodeID] = append(snap.sharedTo[sh.NodeID], sh.RecipientID)
		}
	}
	return snap, nil
}

// mapPlan is a map before encoding: the response without peers, and the
// peers with the way each appears.
type mapPlan struct {
	resp  protocol.MapResponse
	peers []*snapNode
	how   []int // peerOwn, peerSharedNoInitiate or peerSharedInitiate
}

// planMap selects node id's peers. Tenants are isolated: a machine sees its
// own tenant's machines, plus, through shares in effect, machines shared
// with its tenant and (if it is itself shared) the recipient tenants'
// machines. Nothing else of another tenant.
//
// Sharing is one-way: peer P may open connections to this machine N only if
// they're in the same tenant or N is shared with P's tenant. Other peers are
// marked NoInitiate, and N's packet filter enforces it.
func (s *Server) planMap(ctx context.Context, id int64) (*mapPlan, error) {
	snap, err := s.currentSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	sn := snap.nodes[id]
	if sn == nil {
		return nil, fmt.Errorf("node %d: %w", id, db.ErrNotFound)
	}
	self := sn.db
	if self.UserStatus != db.StatusActive {
		// Keep the stream (so reactivation restores the map at once), but
		// cut the device off: no peers, relays or DNS.
		return &mapPlan{resp: protocol.MapResponse{
			Self:   sn.proto,
			Notice: "this machine's account is suspended or awaiting approval; ask the server's operator",
		}}, nil
	}

	sharedTo := map[int64]bool{} // accounts self is shared with
	for _, uid := range snap.sharedTo[id] {
		sharedTo[uid] = true
	}
	peerIDs := slices.Clone(snap.byUser[self.UserID])
	peerIDs = append(peerIDs, snap.sharedIn[self.UserID]...)
	for uid := range sharedTo {
		peerIDs = append(peerIDs, snap.byUser[uid]...)
	}
	slices.Sort(peerIDs)
	peerIDs = slices.Compact(peerIDs)

	plan := &mapPlan{
		resp: protocol.MapResponse{
			Self: sn.proto,
			DNS: protocol.DNSConfig{
				MagicDNS: !s.cfg.DisableMagicDNS,
				Domain:   s.cfg.BaseDomain,
				// The tenant domain first ("laptop" is our laptop), then the base
				// domain, so shared machines' short forms ("nas.acme") resolve.
				Search:      []string{s.tenantDomain(self.UserName), s.cfg.BaseDomain},
				Resolver:    protocol.MagicDNSAddr,
				Nameservers: s.cfg.Nameservers,
			},
			Relays: s.cfg.Relays,
		},
		peers: make([]*snapNode, 0, len(peerIDs)),
		how:   make([]int, 0, len(peerIDs)),
	}
	for _, pid := range peerIDs {
		p := snap.nodes[pid]
		if pid == id || p.db.UserStatus != db.StatusActive {
			continue // suspended accounts' machines drop out of everyone's map
		}
		how := peerOwn
		if p.db.UserID != self.UserID {
			how = peerSharedNoInitiate
			if sharedTo[p.db.UserID] {
				how = peerSharedInitiate
			}
		}
		plan.peers = append(plan.peers, p)
		plan.how = append(plan.how, how)
	}
	return plan, nil
}

// BuildMap computes the network map for node id (see planMap).
func (s *Server) BuildMap(ctx context.Context, id int64) (protocol.MapResponse, error) {
	plan, err := s.planMap(ctx, id)
	if err != nil {
		return protocol.MapResponse{}, err
	}
	resp := plan.resp
	resp.Peers = make([]protocol.Node, len(plan.peers))
	for i, p := range plan.peers {
		pn := p.proto // a copy: the flags are per map
		pn.Shared = plan.how[i] != peerOwn
		pn.NoInitiate = plan.how[i] == peerSharedNoInitiate
		resp.Peers[i] = pn
	}
	return resp, nil
}

// peersPlaceholder is what an empty peer list encodes to. It can't occur
// earlier in the output: inside JSON strings, quotes are escaped.
var peersPlaceholder = []byte(`"Peers":[]`)

// BuildMapJSON is json.Marshal(BuildMap(ctx, id)), assembled from peer
// encodings cached in the snapshot instead of encoding every peer again.
func (s *Server) BuildMapJSON(ctx context.Context, id int64) ([]byte, error) {
	plan, err := s.planMap(ctx, id)
	if err != nil {
		return nil, err
	}
	resp := plan.resp
	resp.Peers = []protocol.Node{}
	head, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	at := bytes.Index(head, peersPlaceholder)
	if at < 0 {
		return nil, fmt.Errorf("control: map encoding has no peer list")
	}
	size := len(head)
	encs := make([][]byte, len(plan.peers))
	for i, p := range plan.peers {
		encs[i] = p.peerJSON(plan.how[i])
		size += len(encs[i]) + 1
	}
	out := make([]byte, 0, size)
	out = append(out, head[:at]...)
	out = append(out, `"Peers":[`...)
	for i, e := range encs {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, e...)
	}
	out = append(out, ']')
	out = append(out, head[at+len(peersPlaceholder):]...)
	return out, nil
}
