package daemon

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailconnect/internal/localapi"
	"tailconnect/internal/tlspin"
)

// Moving a registered device from HTTP to a self-signed HTTPS address:
// without the pin it fails with the fingerprint and stays connected; with
// it, it keeps its identity.
func TestMoveToSelfSigned(t *testing.T) {
	ss, err := tlspin.LoadOrCreate(t.TempDir(), []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cdb, plainURL, authKey, ctl := newControlServer(t, nil, false)
	a := newTestNode(t, "alpha")
	if err := a.d.Up(localapi.UpRequest{ControlURL: plainURL, AuthKey: authKey, Hostname: "alpha"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha running", running(a, 0))
	ip := selfIP(t, a)

	// The same control server, also over HTTPS.
	ts := httptest.NewUnstartedServer(ctl.Handler())
	ts.TLS = ss.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	_ = cdb

	err = a.d.Up(localapi.UpRequest{ControlURL: ts.URL})
	var ue *tlspin.UntrustedError
	if !errors.As(err, &ue) || ue.Fingerprint != ss.Fingerprint {
		t.Fatalf("unpinned move: %v", err)
	}
	if st := a.d.Status(); st.State != localapi.StateRunning || st.ControlURL != plainURL {
		t.Fatalf("a failed move must leave the device connected: %s %s", st.State, st.ControlURL)
	}
	if err := a.d.Up(localapi.UpRequest{ControlURL: ts.URL, TLSFingerprint: ss.Fingerprint}); err != nil {
		t.Fatalf("pinned move: %v", err)
	}
	waitFor(t, "alpha running over HTTPS", running(a, 0))
	if st := a.d.Status(); st.ControlURL != ts.URL || selfIP(t, a) != ip {
		t.Fatalf("after move: %s %s (want %s)", st.ControlURL, selfIP(t, a), ip)
	}
}

// A control server (and its embedded relay) with a self-signed certificate:
// refused until the client pins its fingerprint, then control and relay
// connections both work.
func TestSelfSignedControl(t *testing.T) {
	ss, err := tlspin.LoadOrCreate(t.TempDir(), []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, url, authKey, _ := newControlServerTLS(t, nil, true, ss.TLSConfig()) // no STUN: relay only
	a, b := newTestNodeEP(t, "alpha", deadEndpoints), newTestNodeEP(t, "beta", deadEndpoints)

	err = a.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: authKey, Hostname: "alpha"})
	var ue *tlspin.UntrustedError
	if !errors.As(err, &ue) || ue.Fingerprint != ss.Fingerprint || !strings.Contains(err.Error(), "--tls-fingerprint "+ss.Fingerprint) {
		t.Fatalf("unpinned up: %v", err)
	}
	if err := a.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: authKey, Hostname: "alpha", TLSFingerprint: "sha256:bogus"}); err == nil {
		t.Fatal("malformed fingerprint accepted")
	}
	for _, n := range []struct {
		n    *testNode
		host string
	}{{a, "alpha"}, {b, "beta"}} {
		if err := n.n.d.Up(localapi.UpRequest{ControlURL: url, AuthKey: authKey, Hostname: n.host, TLSFingerprint: ss.Fingerprint}); err != nil {
			t.Fatalf("up %s: %v", n.host, err)
		}
	}
	waitFor(t, "alpha running", running(a, 1))
	waitFor(t, "beta running", running(b, 1))
	ipA, ipB := selfIP(t, a), selfIP(t, b)
	echo(t, b, ipB)
	echo(t, a, ipA)
	if got, err := ping(a, ipB, "pinned-relay"); err != nil || got != "pong:pinned-relay" {
		t.Fatalf("alpha→beta via the self-signed relay: %q %v", got, err)
	}
	if p := a.d.Status().Peers[0]; p.Relay != 1 {
		t.Fatalf("expected the relay path: %+v", p)
	}
}
