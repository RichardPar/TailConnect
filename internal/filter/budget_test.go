package filter

import (
	"net/netip"
	"os"
	"testing"
	"time"
)

// See internal/control/budget_test.go.
func TestPerfBudgetFilter(t *testing.T) {
	if os.Getenv("TC_PERF_BUDGET") == "" {
		t.Skip("set TC_PERF_BUDGET=1 to check performance budgets")
	}
	w := Wrap(&nullTUN{})
	w.SetRestricted([]netip.Addr{shared, shrd6})
	pkt := fullSize(tcp(friend, me, 445, 50000, ack))
	buf := make([]byte, 16+len(pkt))
	copy(buf[16:], pkt)
	r := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			w.Write([][]byte{buf}, 16)
		}
	})
	// Every packet pays this once any share exists (measured ~58ns, 0 allocs).
	if per := time.Duration(r.NsPerOp()); per > time.Microsecond {
		t.Errorf("filter, unrestricted peer: %v per packet, budget 1µs", per)
	}
	if r.AllocsPerOp() > 1 {
		t.Errorf("filter, unrestricted peer: %d allocations per packet", r.AllocsPerOp())
	}
}
