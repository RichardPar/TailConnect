package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("tc_test_packets_total", "Packets seen.")
	c.Add(41)
	c.Inc()
	r.GaugeFunc("tc_test_ratio", "A ratio.", func() float64 { return 13.56 / 1000 })
	r.Collect("tc_test_peers", "Peers by path.", "gauge", func(emit func([]string, float64)) {
		emit([]string{"path", "direct"}, 3)
		emit([]string{"path", `odd "quoted"\name`, "region", "1"}, 1)
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	want := `# HELP tc_test_packets_total Packets seen.
# TYPE tc_test_packets_total counter
tc_test_packets_total 42
# HELP tc_test_peers Peers by path.
# TYPE tc_test_peers gauge
tc_test_peers{path="direct"} 3
tc_test_peers{path="odd \"quoted\"\\name",region="1"} 1
# HELP tc_test_ratio A ratio.
# TYPE tc_test_ratio gauge
tc_test_ratio 0.01356
`
	if got := rec.Body.String(); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate name accepted")
		}
	}()
	r.Counter("tc_test_packets_total", "again")
}
