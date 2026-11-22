package control

import (
	"bytes"
	"context"
	"sync/atomic"
	"time"

	"tailconnect/internal/metrics"
)

type stats struct {
	registerOK, registerRefused atomic.Int64
	connRefused                 struct {
		rate, tooMany, unidentified atomic.Int64
	}
	mapFull, mapDelta           atomic.Int64 // messages on map streams
	mapFullBytes, mapDeltaBytes atomic.Int64
	statusLimited               atomic.Int64 // status updates skipped by the per-machine limit
}

var deltaPrefix = []byte(`{"Delta":true`)

func (st *stats) countMap(b []byte) {
	if bytes.HasPrefix(b, deltaPrefix) {
		st.mapDelta.Add(1)
		st.mapDeltaBytes.Add(int64(len(b)))
	} else {
		st.mapFull.Add(1)
		st.mapFullBytes.Add(int64(len(b)))
	}
}

// RegisterMetrics adds the control server's metrics to r.
func (s *Server) RegisterMetrics(r *metrics.Registry) {
	r.Collect("tc_control_machines", "Machines by state: online (map stream open), offline, or cut_off (unapproved, expired or suspended account).", "gauge",
		func(emit func([]string, float64)) {
			snap, err := s.currentSnapshot(s.ctx)
			if err != nil {
				return
			}
			s.mu.Lock()
			online := make(map[int64]bool, len(s.online))
			for id := range s.online {
				online[id] = true
			}
			s.mu.Unlock()
			var on, off, cut float64
			now := time.Now()
			for id, n := range snap.nodes {
				switch {
				case cutOffNotice(n.db, now) != "":
					cut++
				case online[id]:
					on++
				default:
					off++
				}
			}
			emit([]string{"state", "online"}, on)
			emit([]string{"state", "offline"}, off)
			emit([]string{"state", "cut_off"}, cut)
		})
	r.Collect("tc_control_accounts", "Accounts by status.", "gauge", func(emit func([]string, float64)) {
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()
		users, err := s.db.ListUsers(ctx)
		if err != nil {
			return
		}
		n := map[string]float64{"active": 0, "pending": 0, "suspended": 0}
		for _, u := range users {
			n[u.Status]++
		}
		for _, st := range []string{"active", "pending", "suspended"} {
			emit([]string{"status", st}, n[st])
		}
	})
	r.GaugeFunc("tc_control_map_streams", "Open map streams (connected machines).", func() float64 {
		s.mu.Lock()
		defer s.mu.Unlock()
		n := 0
		for _, c := range s.online {
			n += c
		}
		return float64(n)
	})
	r.Collect("tc_control_map_messages_total", "Network maps sent on streams: full maps, or deltas with only what changed.", "counter",
		func(emit func([]string, float64)) {
			emit([]string{"kind", "full"}, float64(s.stats.mapFull.Load()))
			emit([]string{"kind", "delta"}, float64(s.stats.mapDelta.Load()))
		})
	r.Collect("tc_control_map_bytes_total", "Bytes of network maps sent on streams.", "counter",
		func(emit func([]string, float64)) {
			emit([]string{"kind", "full"}, float64(s.stats.mapFullBytes.Load()))
			emit([]string{"kind", "delta"}, float64(s.stats.mapDeltaBytes.Load()))
		})
	r.Collect("tc_control_registrations_total", "Machine registrations (joins and re-authentications).", "counter",
		func(emit func([]string, float64)) {
			emit([]string{"result", "ok"}, float64(s.stats.registerOK.Load()))
			emit([]string{"result", "refused"}, float64(s.stats.registerRefused.Load()))
		})
	r.CounterFunc("tc_control_status_updates_limited_total", "Machines' status updates skipped because the machine sent too many.", func() float64 {
		return float64(s.stats.statusLimited.Load())
	})
	r.Collect("tc_control_connections_refused_total", "Control connections refused or closed by the abuse limits.", "counter",
		func(emit func([]string, float64)) {
			emit([]string{"reason", "rate"}, float64(s.stats.connRefused.rate.Load()))
			emit([]string{"reason", "too_many"}, float64(s.stats.connRefused.tooMany.Load()))
			emit([]string{"reason", "unidentified"}, float64(s.stats.connRefused.unidentified.Load()))
		})
}
