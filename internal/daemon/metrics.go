package daemon

import (
	"tailconnect/internal/localapi"
	"tailconnect/internal/metrics"
)

// RegisterMetrics adds the client's metrics to r. They are read from the
// same status `tc status` shows, at each scrape.
func (d *Daemon) RegisterMetrics(r *metrics.Registry) {
	st := func() localapi.Status { return d.Status() }
	r.Collect("tc_state", "The client's state (1 for the current one).", "gauge", func(emit func([]string, float64)) {
		emit([]string{"state", st().State}, 1)
	})
	r.Collect("tc_peers", "Peers by path: direct, relay, or idle (no WireGuard session in the last 3 minutes).", "gauge",
		func(emit func([]string, float64)) {
			var direct, relayed, idle float64
			for _, p := range st().Peers {
				switch {
				case !p.Active:
					idle++
				case p.CurrentEndpoint.IsValid():
					direct++
				default:
					relayed++
				}
			}
			emit([]string{"path", "direct"}, direct)
			emit([]string{"path", "relay"}, relayed)
			emit([]string{"path", "idle"}, idle)
		})
	perPeer := func(name, help, typ string, val func(localapi.PeerStatus) (float64, bool)) {
		r.Collect(name, help, typ, func(emit func([]string, float64)) {
			for _, p := range st().Peers {
				if v, ok := val(p); ok {
					emit([]string{"peer", p.Name}, v)
				}
			}
		})
	}
	perPeer("tc_peer_received_bytes_total", "Bytes received from each peer through the tunnel.", "counter",
		func(p localapi.PeerStatus) (float64, bool) { return float64(p.RxBytes), true })
	perPeer("tc_peer_sent_bytes_total", "Bytes sent to each peer through the tunnel.", "counter",
		func(p localapi.PeerStatus) (float64, bool) { return float64(p.TxBytes), true })
	perPeer("tc_peer_latency_seconds", "Round trip to each peer on its direct path.", "gauge",
		func(p localapi.PeerStatus) (float64, bool) {
			return p.LatencyMS / 1000, p.CurrentEndpoint.IsValid() && p.LatencyMS > 0
		})
	r.GaugeFunc("tc_relay_connected", "Whether the connection to the home relay is up (1) or not (0).", func() float64 {
		if st().RelayConnected {
			return 1
		}
		return 0
	})
	r.CounterFunc("tc_filter_dropped_packets_total", "Packets refused because the sender may not open connections here (sharing, access rules).",
		func() float64 { return float64(st().FilterDropped) })
	r.Collect("tc_key_expiry_timestamp_seconds", "When this machine must re-authenticate (Unix time; absent if never).", "gauge",
		func(emit func([]string, float64)) {
			if s := st().Self; s != nil && s.KeyExpiry != nil {
				emit(nil, float64(s.KeyExpiry.Unix()))
			}
		})
}
