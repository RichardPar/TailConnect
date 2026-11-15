package daemon

import (
	"context"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"tailconnect/internal/localapi"
	"tailconnect/internal/metrics"
)

func scrape(t *testing.T, r *metrics.Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

// value returns the sample matching the series selector (name{labels}).
func value(t *testing.T, body, series string) float64 {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(series) + ` (\S+)$`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no %s in\n%s", series, body)
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v
}

func TestClientMetrics(t *testing.T) {
	_, url, authKey := newControl(t)
	a, b := newTestNode(t, "alpha"), newTestNode(t, "beta")
	for _, n := range []struct {
		n    *testNode
		host string
	}{{a, "alpha"}, {b, "beta"}} {
		if err := n.n.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: authKey, Hostname: n.host}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "both running", func() bool { return running(a, 1)() && running(b, 1)() })
	ipB := selfIP(t, b)
	echo(t, b, ipB)
	if got, err := ping(a, ipB, "metrics"); err != nil || got != "pong:metrics" {
		t.Fatalf("ping: %q %v", got, err)
	}

	r := metrics.NewRegistry()
	a.d.RegisterMetrics(r)
	waitFor(t, "a direct path in the metrics", func() bool {
		return strings.Contains(scrape(t, r), `tc_peers{path="direct"} 1`)
	})
	body := scrape(t, r)
	if value(t, body, `tc_state{state="Running"}`) != 1 || value(t, body, `tc_relay_connected`) != 1 {
		t.Fatalf("state or relay:\n%s", body)
	}
	peer := `{peer="beta.alice.e2e.internal"}`
	if value(t, body, "tc_peer_sent_bytes_total"+peer) <= 0 || value(t, body, "tc_peer_received_bytes_total"+peer) <= 0 {
		t.Fatalf("no traffic counted:\n%s", body)
	}
	if v := value(t, body, "tc_peer_latency_seconds"+peer); v <= 0 || v > 1 {
		t.Fatalf("latency %v", v)
	}
	if !strings.Contains(body, "tc_key_expiry_timestamp_seconds ") {
		t.Fatalf("key expiry missing (the server's default is 180 days):\n%s", body)
	}
}

// Machines report their traffic to the control server, per peer.
func TestTrafficReported(t *testing.T) {
	cdb, url, authKey, ctl := newControlServer(t, nil, false)
	a, b := newTestNode(t, "alpha"), newTestNode(t, "beta")
	for _, n := range []struct {
		n    *testNode
		host string
	}{{a, "alpha"}, {b, "beta"}} {
		if err := n.n.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: authKey, Hostname: n.host}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "both running", func() bool { return running(a, 1)() && running(b, 1)() })
	ipB := selfIP(t, b)
	echo(t, b, ipB)
	if got, err := ping(a, ipB, "traffic"); err != nil || got != "pong:traffic" {
		t.Fatalf("ping: %q %v", got, err)
	}
	nodes, _ := cdb.ListNodes(context.Background(), 0)
	ids := map[string]int64{}
	keys := map[string]string{}
	for _, n := range nodes {
		ids[n.GivenName], keys[n.GivenName] = n.ID, n.NodeKey
	}
	waitFor(t, "alpha's traffic with beta at the server", func() bool {
		m := ctl.Traffic(ids["alpha"])
		return m != nil && len(m.Peers) == 1 && m.Peers[0].NodeKey.String() == keys["beta"] && m.TxBytes > 0 && m.RxBytes > 0
	})
	waitFor(t, "beta's traffic with alpha", func() bool {
		m := ctl.Traffic(ids["beta"])
		return m != nil && len(m.Peers) == 1 && m.Peers[0].NodeKey.String() == keys["alpha"]
	})
}
