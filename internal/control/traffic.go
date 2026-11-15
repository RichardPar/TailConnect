package control

import (
	"bytes"
	"net/http"
	"slices"
	"sync"
	"time"

	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

// Traffic between machines goes directly from one to the other (or through
// a relay), so only the machines know it. They report their WireGuard
// counters; the server keeps the latest per machine, in memory only, and
// derives rates from consecutive reports.

const (
	// trafficIdle: a machine whose counters don't change sends no reports,
	// so after this long without one its rates are shown as zero.
	trafficIdle = 90 * time.Second
	// trafficForget drops machines that stopped reporting (removed, offline).
	trafficForget   = time.Hour
	maxTrafficPeers = 10000
)

type trafficTable struct {
	mu        sync.Mutex
	nodes     map[int64]*nodeTraffic
	lastPurge time.Time
}

type nodeTraffic struct {
	updated time.Time
	peers   map[key.NodePublic]*peerTraffic
}

type peerTraffic struct {
	rx, tx         int64
	rxRate, txRate float64
}

// report records machine id's counters at time now.
func (t *trafficTable) report(id int64, peers []protocol.PeerTraffic, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nodes == nil {
		t.nodes = map[int64]*nodeTraffic{}
	}
	if now.Sub(t.lastPurge) > 10*time.Minute {
		for nid, n := range t.nodes {
			if now.Sub(n.updated) > trafficForget {
				delete(t.nodes, nid)
			}
		}
		t.lastPurge = now
	}
	prev := t.nodes[id]
	n := &nodeTraffic{updated: now, peers: make(map[key.NodePublic]*peerTraffic, len(peers))}
	for _, p := range peers {
		if p.RxBytes < 0 || p.TxBytes < 0 {
			continue
		}
		cur := &peerTraffic{rx: p.RxBytes, tx: p.TxBytes}
		if prev != nil {
			// Counters only grow; if they shrank, the peer's session (or the
			// machine's tunnel) restarted: no rate from this pair of reports.
			if old := prev.peers[p.NodeKey]; old != nil && p.RxBytes >= old.rx && p.TxBytes >= old.tx {
				if dt := now.Sub(prev.updated).Seconds(); dt > 0 {
					cur.rxRate = float64(p.RxBytes-old.rx) / dt
					cur.txRate = float64(p.TxBytes-old.tx) / dt
				}
			}
		}
		n.peers[p.NodeKey] = cur
	}
	t.nodes[id] = n
}

// get summarises machine id's traffic at time now (nil if it never reported).
func (t *trafficTable) get(id int64, now time.Time) *protocol.MachineTraffic {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.nodes[id]
	if n == nil {
		return nil
	}
	idle := now.Sub(n.updated) > trafficIdle
	out := &protocol.MachineTraffic{Updated: n.updated, Peers: make([]protocol.PeerTrafficStats, 0, len(n.peers))}
	for k, p := range n.peers {
		ps := protocol.PeerTrafficStats{NodeKey: k, RxBytes: p.rx, TxBytes: p.tx}
		if !idle {
			ps.RxRate, ps.TxRate = p.rxRate, p.txRate
		}
		out.RxBytes += ps.RxBytes
		out.TxBytes += ps.TxBytes
		out.RxRate += ps.RxRate
		out.TxRate += ps.TxRate
		out.Peers = append(out.Peers, ps)
	}
	slices.SortFunc(out.Peers, func(a, b protocol.PeerTrafficStats) int {
		ra, rb := a.RxRate+a.TxRate, b.RxRate+b.TxRate
		if ra != rb {
			if ra > rb {
				return -1
			}
			return 1
		}
		ta, tb := a.RxBytes+a.TxBytes, b.RxBytes+b.TxBytes
		switch {
		case ta > tb:
			return -1
		case ta < tb:
			return 1
		}
		ka, kb := a.NodeKey.Raw(), b.NodeKey.Raw()
		return bytes.Compare(ka[:], kb[:])
	})
	return out
}

// Traffic returns what machine id last reported about its traffic (nil if
// nothing). For the web portal.
func (s *Server) Traffic(id int64) *protocol.MachineTraffic {
	return s.traffic.get(id, time.Now())
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	var req protocol.TrafficRequest
	if !decode(w, r, &req) {
		return
	}
	self, ok := s.selfNode(w, r, req.NodeKey)
	if !ok {
		return
	}
	if len(req.Peers) > maxTrafficPeers {
		writeError(w, http.StatusBadRequest, "too many peers")
		return
	}
	s.traffic.report(self.ID, req.Peers, time.Now())
	w.WriteHeader(http.StatusNoContent)
}
