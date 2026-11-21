package autotls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDuckDNSName(t *testing.T) {
	for in, want := range map[string]string{
		"tailconnect.duckdns.org":       "tailconnect",
		"TailConnect.DuckDNS.org.":      "tailconnect",
		"vpn.tailconnect.duckdns.org":   "tailconnect",
		"_acme-challenge.x.duckdns.org": "x",
	} {
		if got, err := DuckDNSName(in); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"duckdns.org", "example.com", "x.duckdns.org.evil.com"} {
		if _, err := DuckDNSName(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestDuckDNSUpdate(t *testing.T) {
	var last string
	answer := "OK"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r.URL.RawQuery
		w.Write([]byte(answer))
	}))
	defer ts.Close()
	d := &DuckDNS{Token: "tok-123", BaseURL: ts.URL}
	ctx := context.Background()
	if err := d.SetTXT(ctx, "tailconnect.duckdns.org", "abc_DEF-1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(last, "domains=tailconnect") || !strings.Contains(last, "token=tok-123") || !strings.Contains(last, "txt=abc_DEF-1") {
		t.Fatalf("set: %s", last)
	}
	if err := d.ClearTXT(ctx, "tailconnect.duckdns.org"); err != nil || !strings.Contains(last, "clear=true") {
		t.Fatalf("clear: %s %v", last, err)
	}
	answer = "KO"
	err := d.SetTXT(ctx, "tailconnect.duckdns.org", "v")
	if err == nil || strings.Contains(err.Error(), "tok-123") {
		t.Fatalf("KO: %v (must fail, without the token)", err)
	}
	// A transport error must not leak the token (it's in the URL).
	ts.Close()
	if err := d.SetTXT(ctx, "tailconnect.duckdns.org", "v"); err == nil || strings.Contains(err.Error(), "tok-123") {
		t.Fatalf("down: %v", err)
	}
}

// fakeCA signs certificates like an ACME CA would, for the issue hook.
type fakeCA struct {
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
	life  time.Duration
	now   func() time.Time
	calls atomic.Int32
	fail  atomic.Int32 // fail this many calls first
}

func newFakeCA(t *testing.T) *fakeCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour * 365), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &fakeCA{key: k, cert: c, life: 90 * 24 * time.Hour, now: time.Now}
}

func (ca *fakeCA) issue(_ context.Context, domains []string, key crypto.Signer) ([][]byte, error) {
	ca.calls.Add(1)
	if ca.fail.Load() > 0 {
		ca.fail.Add(-1)
		return nil, errors.New("CA unreachable")
	}
	now := ca.now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), DNSNames: domains, NotBefore: now, NotAfter: now.Add(ca.life),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, err
	}
	return [][]byte{der, ca.cert.Raw}, nil
}

func newTestDNS(t *testing.T, dir string, ca *fakeCA, staging bool) *Manager {
	t.Helper()
	cfg := Config{Domains: []string{"tailconnect.duckdns.org"}, CacheDir: dir, DNS: &DuckDNS{Token: "x"}, TLSListen: ":7740"}
	if staging {
		cfg.DirectoryURL = StagingURL
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.dns.issue = ca.issue
	m.dns.now = ca.now
	return m
}

func TestDNSManagerIssueServeAndCache(t *testing.T) {
	dir := t.TempDir()
	ca := newFakeCA(t)
	m := newTestDNS(t, dir, ca, false)

	// Any port works in DNS mode, and there's nothing to serve until issued.
	if _, err := m.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "tailconnect.duckdns.org"}); err == nil {
		t.Fatal("certificate served before it was issued")
	}
	if !m.dns.needsRenewal() {
		t.Fatal("no certificate: must want one")
	}
	if err := m.dns.obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Serve it over a real TLS handshake, trusted through the fake CA.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", m.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "tailconnect.duckdns.org", RootCAs: roots})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	c.Close()
	if m.dns.needsRenewal() {
		t.Fatal("fresh certificate wants renewal")
	}

	// A restart loads it from the cache instead of asking the CA again.
	m2 := newTestDNS(t, dir, ca, false)
	if m2.dns.cert == nil || m2.dns.needsRenewal() {
		t.Fatal("cached certificate not loaded")
	}
	// The test CA's cache is separate: a staging certificate is never
	// served by the real configuration, or the other way round.
	if m3 := newTestDNS(t, dir, ca, true); m3.dns.cert != nil {
		t.Fatal("staging configuration loaded the real CA's certificate")
	}

	// Renewal: in the last third of its life.
	base := time.Now()
	m2.dns.now = func() time.Time { return base.Add(61 * 24 * time.Hour) }
	if !m2.dns.needsRenewal() {
		t.Fatal("certificate with 29 of 90 days left must be renewed")
	}
	m2.dns.now = func() time.Time { return base.Add(50 * 24 * time.Hour) }
	if m2.dns.needsRenewal() {
		t.Fatal("certificate with 40 of 90 days left renewed too early")
	}
}

func TestDNSManagerRetries(t *testing.T) {
	old := dnsRetry
	dnsRetry = []time.Duration{10 * time.Millisecond}
	defer func() { dnsRetry = old }()
	ca := newFakeCA(t)
	ca.fail.Store(2)
	m := newTestDNS(t, t.TempDir(), ca, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for m.dns.needsRenewal() {
		if time.Now().After(deadline) {
			t.Fatalf("no certificate after %d attempts", ca.calls.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := ca.calls.Load(); n != 3 {
		t.Fatalf("attempts: %d, want 3 (two failures, then success)", n)
	}
}

func TestDNSModeConfig(t *testing.T) {
	if _, err := New(Config{Domains: []string{"x.duckdns.org"}, CacheDir: t.TempDir(), DNS: &DuckDNS{}, HTTPListen: ":80"}); err == nil {
		t.Fatal("DNS mode with an HTTP listener accepted")
	}
	if _, err := New(Config{Domains: []string{"*.x.duckdns.org"}, CacheDir: t.TempDir(), DNS: &DuckDNS{}}); err == nil {
		t.Fatal("wildcard accepted")
	}
	// Connection checks still insist on 443 or 80; DNS mode doesn't.
	if _, err := New(Config{Domains: []string{"x.duckdns.org"}, CacheDir: t.TempDir(), TLSListen: ":7740"}); err == nil {
		t.Fatal("port 7740 without DNS or HTTP accepted")
	}
	if _, err := New(Config{Domains: []string{"x.duckdns.org"}, CacheDir: t.TempDir(), TLSListen: ":7740", DNS: &DuckDNS{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := net.LookupHost("localhost"); err != nil {
		t.Skip("no resolver")
	}
}

func TestDuckDNSNameRejectsMalformed(t *testing.T) {
	for _, d := range []string{"foo..duckdns.org", ".duckdns.org", "a_b.duckdns.org", "duckdns.org", "x.example.org"} {
		if n, err := DuckDNSName(d); err == nil {
			t.Errorf("DuckDNSName(%q) = %q, want an error", d, n)
		}
	}
	if n, err := DuckDNSName("vpn.TailConnect.duckdns.org."); err != nil || n != "tailconnect" {
		t.Fatalf("got %q %v", n, err)
	}
}
