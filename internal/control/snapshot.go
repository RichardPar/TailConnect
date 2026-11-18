package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"tailconnect/internal/acl"
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
	// sharePorts: what a recipient account's machines may open on a shared
	// machine, by (machine, account); absent = everything.
	sharePorts map[[2]int64][]protocol.PortRange
	keys       map[key.NodePublic]int64 // node key → machine ID (usable machines only)
	// Access rules per account (nil = no rules: everything allowed).
	policies map[int64]*acl.Policy
	// built is when the snapshot was made, and stale when it stops being
	// exact without a database change: the next key expiry (zero = never).
	built, stale time.Time
}

type snapNode struct {
	db    db.Node
	proto protocol.Node // LastSeen cleared: maps don't carry it

	acl acl.Machine

	// The node's JSON as a peer, encoded at most once per snapshot for each
	// way it appears (see peerView). Encoding is most of the cost of a map,
	// and a node appears in many maps per generation, in only a few ways.
	encMu sync.Mutex
	enc   map[string][]byte
}

// peerView is how a peer appears in one machine's map: whether it's
// another account's machine (shared), and what it may open there.
type peerView struct {
	shared     bool
	noInitiate bool
	inbound    []protocol.PortRange // with noInitiate: still allowed
	// noExit hides the peer's exit node role: this machine may not send it
	// everything (another account's machine, or access rules limit what
	// it may open there), so the exit node's packet filter would drop
	// internet traffic from it.
	noExit bool
}

func (v peerView) key() string {
	return fmt.Sprintf("%t/%t/%t/%s", v.shared, v.noInitiate, v.noExit, acl.FormatPorts(acl.Access{Ranges: v.inbound}))
}

func (v peerView) apply(pn *protocol.Node) {
	pn.Shared, pn.NoInitiate, pn.Inbound = v.shared, v.noInitiate, v.inbound
	if v.noExit {
		pn.ExitNode = false
	}
}

func (n *snapNode) peerJSON(v peerView) []byte {
	k := v.key()
	n.encMu.Lock()
	defer n.encMu.Unlock()
	if b, ok := n.enc[k]; ok {
		return b
	}
	pn := n.proto
	v.apply(&pn)
	b, _ := json.Marshal(pn)
	if n.enc == nil {
		n.enc = map[string][]byte{}
	}
	n.enc[k] = b
	return b
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
	if s.snap != nil && s.snap.gen == gen && (s.snap.stale.IsZero() || time.Now().Before(s.snap.stale)) {
		return s.snap, nil
	}
	// The generation and the data come from one read transaction, so the
	// snapshot is consistent and labelled with the generation it reflects.
	st, err := s.db.ReadState(ctx)
	if err != nil {
		return nil, err
	}
	snap, err := s.buildSnapshot(st)
	if err != nil {
		return nil, err
	}
	s.snap = snap
	return snap, nil
}

func (s *Server) buildSnapshot(st db.State) (*snapshot, error) {
	nodes, shares, rules := st.Nodes, st.Shares, st.Rules
	now := time.Now()
	snap := &snapshot{
		gen: st.Generation, built: now, nodes: make(map[int64]*snapNode, len(nodes)), byUser: map[int64][]int64{},
		sharedIn: map[int64][]int64{}, sharedTo: map[int64][]int64{}, keys: make(map[key.NodePublic]int64, len(nodes)),
		policies: map[int64]*acl.Policy{},
	}
	byAccount := map[int64][]acl.Rule{}
	for _, r := range rules {
		byAccount[r.UserID] = append(byAccount[r.UserID], acl.Rule{ID: r.ID, Src: r.Src, Dst: r.Dst, Ports: r.Ports})
	}
	for uid, rs := range byAccount {
		p, err := acl.Compile(rs)
		if err != nil {
			// Rules are validated when saved; if one is broken anyway,
			// fail closed for that account rather than open.
			s.log.Error("access rules don't compile; denying all traffic in the account", "user_id", uid, "err", err)
			p = acl.DenyAll()
		}
		snap.policies[uid] = p
	}
	for _, n := range nodes {
		pn, err := s.toProtocol(n)
		if err != nil {
			return nil, err
		}
		pn.LastSeen = nil
		snap.nodes[n.ID] = &snapNode{db: n, proto: pn, acl: acl.Machine{ID: n.ID, Name: n.GivenName, Tags: n.Tags}}
		snap.byUser[n.UserID] = append(snap.byUser[n.UserID], n.ID)
		if n.Usable(now) {
			snap.keys[pn.NodeKey] = n.ID
			if !n.ExpiresAt.IsZero() && (snap.stale.IsZero() || n.ExpiresAt.Before(snap.stale)) {
				snap.stale = n.ExpiresAt // a key expiring changes maps
			}
		}
	}
	for _, ids := range snap.byUser {
		slices.Sort(ids)
	}
	for _, sh := range shares {
		if sh.InEffect() && snap.nodes[sh.NodeID] != nil && snap.nodes[sh.NodeID].db.Usable(now) {
			snap.sharedIn[sh.RecipientID] = append(snap.sharedIn[sh.RecipientID], sh.NodeID)
			snap.sharedTo[sh.NodeID] = append(snap.sharedTo[sh.NodeID], sh.RecipientID)
			a, err := acl.ParsePorts(sh.Ports)
			if err != nil {
				// Validated when saved; if broken anyway, fail closed.
				s.log.Error("share ports don't parse; the recipient can't open connections", "share", sh.ID, "ports", sh.Ports, "err", err)
				a = acl.Access{}
			}
			if !a.All {
				if snap.sharePorts == nil {
					snap.sharePorts = map[[2]int64][]protocol.PortRange{}
				}
				snap.sharePorts[[2]int64{sh.NodeID, sh.RecipientID}] = a.Ranges
			}
		}
	}
	return snap, nil
}

// mapPlan is a map before encoding: the response without peers, and the
// peers with the way each appears.
type mapPlan struct {
	resp  protocol.MapResponse
	peers []*snapNode
	views []peerView
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
	if notice := cutOffNotice(self, snap.built); notice != "" {
		// Keep the stream (so approval, reactivation or re-authentication
		// restores the map at once), but cut the device off: no peers,
		// relays or DNS.
		return &mapPlan{resp: protocol.MapResponse{Self: sn.proto, Notice: notice}}, nil
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

	// Every domain a name in this map can end in: the base, plus accounts'
	// own domains (self's and its peers').
	domains := []string{s.cfg.BaseDomain}
	addDomain := func(n db.Node) {
		if n.UserDomain != "" && !slices.Contains(domains, n.UserDomain) {
			domains = append(domains, n.UserDomain)
		}
	}
	addDomain(self)
	plan := &mapPlan{
		resp: protocol.MapResponse{
			Self: sn.proto,
			DNS: protocol.DNSConfig{
				MagicDNS: !s.cfg.DisableMagicDNS,
				Domain:   s.cfg.BaseDomain,
				// The tenant domain first ("laptop" is our laptop), then the base
				// domain, so shared machines' short forms ("nas.acme") resolve.
				Search:      []string{s.tenantDomain(self.UserName, self.UserDomain), s.cfg.BaseDomain},
				Resolver:    protocol.MagicDNSAddr,
				Nameservers: s.cfg.Nameservers,
			},
			Relays: s.cfg.Relays,
		},
		peers: make([]*snapNode, 0, len(peerIDs)),
		views: make([]peerView, 0, len(peerIDs)),
	}
	for _, pid := range peerIDs {
		p := snap.nodes[pid]
		if pid == id || !p.db.Usable(snap.built) {
			continue // cut-off machines drop out of everyone's map
		}
		var view peerView
		if p.db.UserID != self.UserID {
			// Another account's machine, here through a share: it may open
			// connections only if self is shared with its account.
			view = peerView{shared: true, noInitiate: !sharedTo[p.db.UserID], noExit: true}
			if ports, limited := snap.sharePorts[[2]int64{id, p.db.UserID}]; limited && sharedTo[p.db.UserID] {
				// Shared with its account for some ports only.
				view.noInitiate, view.inbound = true, ports
			}
		} else if policy := snap.policies[self.UserID]; policy != nil {
			in, out := policy.Allowed(p.acl, sn.acl), policy.Allowed(sn.acl, p.acl)
			if in.None() && out.None() {
				continue // the rules don't let them talk at all: not peers
			}
			if !in.All {
				view = peerView{noInitiate: true, inbound: in.Ranges}
			}
			view.noExit = !out.All
		}
		plan.peers = append(plan.peers, p)
		plan.views = append(plan.views, view)
		addDomain(p.db)
	}
	slices.Sort(domains[1:])
	plan.resp.DNS.Domains = domains
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
		plan.views[i].apply(&pn)
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
	m, err := s.encodeMap(ctx, id)
	if err != nil {
		return nil, err
	}
	return m.full(), nil
}

// mapEnc is an encoded map in parts: the response with an empty peer list
// at head[at:], and each peer's encoding, ordered by ID.
type mapEnc struct {
	head []byte
	at   int
	ids  []protocol.NodeID
	encs [][]byte
}

func (s *Server) encodeMap(ctx context.Context, id int64) (*mapEnc, error) {
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
	m := &mapEnc{head: head, at: at, ids: make([]protocol.NodeID, len(plan.peers)), encs: make([][]byte, len(plan.peers))}
	for i, p := range plan.peers {
		m.ids[i] = p.proto.ID
		m.encs[i] = p.peerJSON(plan.views[i])
	}
	return m, nil
}

// full assembles the complete map.
func (m *mapEnc) full() []byte {
	size := len(m.head)
	for _, e := range m.encs {
		size += len(e) + 1
	}
	out := make([]byte, 0, size)
	out = append(out, m.head[:m.at]...)
	out = append(out, `"Peers":`...)
	out = appendList(out, m.encs)
	out = append(out, m.head[m.at+len(peersPlaceholder):]...)
	return out
}

func appendList(out []byte, encs [][]byte) []byte {
	out = append(out, '[')
	for i, e := range encs {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, e...)
	}
	return append(out, ']')
}

// deltaState is what a map stream last sent, to send only what changed
// (to clients of protocol.DeltaVersion or later).
type deltaState struct {
	head  []byte
	peers map[protocol.NodeID][]byte
}

// next returns the message that brings the client from the last map to m:
// the full map if anything but the peers changed (or nothing was sent yet),
// otherwise a delta, or nil if nothing changed.
func (d *deltaState) next(m *mapEnc) []byte {
	cur := make(map[protocol.NodeID][]byte, len(m.ids))
	for i, id := range m.ids {
		cur[id] = m.encs[i]
	}
	defer func() { d.head, d.peers = m.head, cur }()
	if d.peers == nil || !bytes.Equal(d.head, m.head) {
		return m.full()
	}
	var changed [][]byte
	for i, id := range m.ids {
		if old, ok := d.peers[id]; !ok || !bytes.Equal(old, m.encs[i]) {
			changed = append(changed, m.encs[i])
		}
	}
	var removed []protocol.NodeID
	for id := range d.peers {
		if _, ok := cur[id]; !ok {
			removed = append(removed, id)
		}
	}
	if len(changed) == 0 && len(removed) == 0 {
		return nil
	}
	slices.Sort(removed)
	out := []byte(`{"Delta":true`)
	if len(changed) > 0 {
		out = append(out, `,"PeersChanged":`...)
		out = appendList(out, changed)
	}
	if len(removed) > 0 {
		out = append(out, `,"PeersRemoved":[`...)
		for i, id := range removed {
			if i > 0 {
				out = append(out, ',')
			}
			out = strconv.AppendInt(out, int64(id), 10)
		}
		out = append(out, ']')
	}
	return append(out, '}')
}

// cutOffNotice explains why machine n is cut off from the network at time
// now, or is "" if it isn't.
func cutOffNotice(n db.Node, now time.Time) string {
	switch {
	case n.UserStatus != db.StatusActive:
		return "this machine's account is suspended or awaiting approval; ask the server's operator"
	case !n.Approved:
		return "this machine is waiting for approval by its account's owner or an operator (web portal: Machines)"
	case n.Expired(now):
		return "this machine's key has expired; re-authenticate with: sudo tc up --authkey KEY"
	}
	return ""
}

// snapshotStale reports whether the current snapshot has passed the moment
// it stops being exact (a key expired), so maps must be rebuilt.
func (s *Server) snapshotStale() bool {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	return s.snap != nil && !s.snap.stale.IsZero() && !time.Now().Before(s.snap.stale)
}
