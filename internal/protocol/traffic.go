package protocol

import (
	"time"

	"tailconnect/internal/key"
)

// TrafficRequest is sent to POST /machine/traffic (inside the Noise
// channel): this machine's WireGuard byte counters for each peer, counted
// since its tunnel started. Clients send it periodically when the counters
// change; servers that don't know the call answer 404, and clients stop.
type TrafficRequest struct {
	NodeKey key.NodePublic
	Peers   []PeerTraffic
}

// PeerTraffic is the bytes exchanged with one peer.
type PeerTraffic struct {
	NodeKey key.NodePublic
	RxBytes int64 // received from the peer
	TxBytes int64 // sent to the peer
}

// MachineTraffic is what the control server knows about a machine's
// traffic, from its reports: totals since its tunnel started, and the
// current rates (bytes per second, averaged between the last two reports).
type MachineTraffic struct {
	Updated time.Time
	RxBytes int64
	TxBytes int64
	RxRate  float64
	TxRate  float64
	Peers   []PeerTrafficStats // busiest first
}

// PeerTrafficStats is one peer's share of a machine's traffic.
type PeerTrafficStats struct {
	NodeKey key.NodePublic
	RxBytes int64
	TxBytes int64
	RxRate  float64
	TxRate  float64
}
