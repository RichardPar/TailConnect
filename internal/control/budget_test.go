package control

import (
	"context"
	"os"
	"testing"
	"time"
)

// Performance budgets: opt-in (TC_PERF_BUDGET=1, `make perf-budget`), since
// timings depend on the machine. Limits are ~10× what a 2021 laptop CPU
// measures, so they catch regressions in complexity (like the O(N²) map
// rebuilds these replaced), not noise.
func requireBudgets(t *testing.T) {
	if os.Getenv("TC_PERF_BUDGET") == "" {
		t.Skip("set TC_PERF_BUDGET=1 to check performance budgets")
	}
}

func TestPerfBudgetMaps(t *testing.T) {
	requireBudgets(t)
	bs := newBenchServer(t, 1, 1000, false)
	ctx := context.Background()

	// One map for a machine in a 1,000-machine account (measured ~0.3ms).
	r := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := bs.srv.BuildMapJSON(ctx, bs.ids[i%len(bs.ids)]); err != nil {
				b.Fatal(err)
			}
		}
	})
	if per := time.Duration(r.NsPerOp()); per > 5*time.Millisecond {
		t.Errorf("map for a 1,000-machine account: %v, budget 5ms", per)
	}

	// A whole update fanned out to all 1,000 machines (measured ~0.36s).
	start := time.Now()
	bs.srv.snapMu.Lock()
	bs.srv.snap = nil
	bs.srv.snapMu.Unlock()
	for _, id := range bs.ids {
		if _, err := bs.srv.BuildMapJSON(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("update fan-out to 1,000 machines: %v, budget 4s", d)
	}

	// Relay policy check, per relayed packet (measured ~165ns).
	r = testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bs.srv.RelayAllowed(bs.keys[i%1000], bs.keys[(i+1)%1000])
		}
	})
	if per := time.Duration(r.NsPerOp()); per > 2*time.Microsecond {
		t.Errorf("RelayAllowed: %v, budget 2µs", per)
	}
}
