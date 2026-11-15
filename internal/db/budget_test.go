package db

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// See internal/control/budget_test.go.
func TestPerfBudgetFleetJoin(t *testing.T) {
	if os.Getenv("TC_PERF_BUDGET") == "" {
		t.Skip("set TC_PERF_BUDGET=1 to check performance budgets")
	}
	d := open(t)
	u := mustUser(t, d, "fleet")
	k := mustKey(t, d, u.ID, true)
	// 1,000 machines with the same hostname. The per-candidate name probing
	// this replaced grew quadratically (about 11s here); now it's about 2s.
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if _, err := reg(d, fmt.Sprintf("m%d", i), fmt.Sprintf("n%d", i), "worker", k); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el > 6*time.Second {
		t.Errorf("1,000 same-named machines joining: %v, budget 6s", el)
	}
}
