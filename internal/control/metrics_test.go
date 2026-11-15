package control

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strconv"
	"testing"

	"tailconnect/internal/key"
	"tailconnect/internal/metrics"
	"tailconnect/internal/protocol"
)

func metricValue(t *testing.T, r *metrics.Registry, series string) float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(series) + ` (\S+)$`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no %s in\n%s", series, rec.Body.String())
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v
}

func TestControlMetrics(t *testing.T) {
	f := newFixture(t)
	r := metrics.NewRegistry()
	f.srv.RegisterMetrics(r)
	k := f.authKey(true)
	a, b := f.newNode(key.MachinePublic{}), f.newNode(key.MachinePublic{})
	if _, err := a.register("a", k); err != nil {
		t.Fatal(err)
	}
	if _, err := b.register("b", k); err != nil {
		t.Fatal(err)
	}
	if _, err := f.newNode(key.MachinePublic{}).register("c", "tc-auth-wrong"); err == nil {
		t.Fatal("bad key accepted")
	}
	sa := stream(t, a)
	sa.next(t, "first map")
	waitOnline(t, f.srv, 1)
	ep := netip.MustParseAddrPort("192.0.2.9:41641")
	if err := b.c.UpdateStatus(context.Background(), protocol.MapRequest{NodeKey: b.nk, DiscoKey: b.disco, Endpoints: []netip.AddrPort{ep}}); err != nil {
		t.Fatal(err)
	}
	sa.next(t, "endpoint change")

	for series, want := range map[string]float64{
		`tc_control_machines{state="online"}`:              1,
		`tc_control_machines{state="offline"}`:             1,
		`tc_control_machines{state="cut_off"}`:             0,
		`tc_control_accounts{status="active"}`:             1,
		`tc_control_map_streams`:                           1,
		`tc_control_registrations_total{result="ok"}`:      2,
		`tc_control_map_messages_total{kind="full"}`:       1,
		`tc_control_map_messages_total{kind="delta"}`:      1,
		`tc_control_registrations_total{result="refused"}`: 1,
	} {
		if got := metricValue(t, r, series); got != want {
			t.Errorf("%s = %v, want %v", series, got, want)
		}
	}
	if metricValue(t, r, `tc_control_map_bytes_total{kind="delta"}`) >= metricValue(t, r, `tc_control_map_bytes_total{kind="full"}`) {
		t.Error("the delta isn't smaller than the full map")
	}
}
