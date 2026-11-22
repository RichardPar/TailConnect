package relay

import "tailconnect/internal/metrics"

// RegisterMetrics adds the relay's metrics to r.
func (s *Server) RegisterMetrics(r *metrics.Registry) {
	r.GaugeFunc("tc_relay_clients", "Machines connected to this relay.", func() float64 {
		n, _, _ := s.Stats()
		return float64(n)
	})
	r.Collect("tc_relay_packets_total", "Packets the relay handled: forwarded, dropped (receiver not connected or too slow) or denied (the machines may not talk).", "counter",
		func(emit func([]string, float64)) {
			emit([]string{"result", "forwarded"}, float64(s.packetsForwarded.Load()))
			emit([]string{"result", "dropped"}, float64(s.packetsDropped.Load()))
			emit([]string{"result", "denied"}, float64(s.packetsDenied.Load()))
		})
	r.CounterFunc("tc_relay_connections_refused_total", "Connections refused by the per-address limits.", func() float64 {
		return float64(s.connsRefused.Load())
	})
	r.CounterFunc("tc_relay_bytes_forwarded_total", "Bytes of packets the relay forwarded.", func() float64 {
		return float64(s.bytesForwarded.Load())
	})
}

// RegisterMetrics adds the policy's metrics (a standalone relay's
// questions to the control server) to r.
func (p *RemotePolicy) RegisterMetrics(r *metrics.Registry) {
	r.Collect("tc_relay_control_requests_total", "Questions to the control server, by outcome.", "counter",
		func(emit func([]string, float64)) {
			emit([]string{"result", "ok"}, float64(p.requestsOK.Load()))
			emit([]string{"result", "error"}, float64(p.requestsFailed.Load()))
		})
	r.GaugeFunc("tc_relay_cached_pairs", "Pairs of machines whose answer is cached.", func() float64 {
		p.mu.RLock()
		defer p.mu.RUnlock()
		return float64(len(p.cache))
	})
}
