package tlspin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoadOrCreateKeepsKey(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	a, err := LoadOrCreate(dir, []string{"pi.local", "192.168.10.131"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Reissued || !strings.HasPrefix(a.Fingerprint, "sha256:") {
		t.Fatalf("first: %+v", a)
	}
	b, _ := LoadOrCreate(dir, []string{"192.168.10.131"}, now)
	if b.Reissued || b.Fingerprint != a.Fingerprint {
		t.Fatalf("a subset of names must reuse the certificate: %+v", b)
	}
	// A new address: new certificate, same key, same fingerprint.
	c, _ := LoadOrCreate(dir, []string{"pi.local", "10.0.0.5"}, now)
	if !c.Reissued || c.Fingerprint != a.Fingerprint {
		t.Fatalf("new name: reissued=%v fp %s vs %s", c.Reissued, c.Fingerprint, a.Fingerprint)
	}
	if err := c.Cert.Leaf.VerifyHostname("10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	// Near expiry: reissued.
	d, _ := LoadOrCreate(dir, []string{"pi.local"}, now.Add(certLife-renewBefore/2))
	if !d.Reissued || d.Fingerprint != a.Fingerprint {
		t.Fatalf("renewal: %+v", d)
	}
}

func TestParseFingerprint(t *testing.T) {
	s, _ := LoadOrCreate(t.TempDir(), []string{"x"}, time.Now())
	got, err := ParseFingerprint(" SHA256:" + strings.TrimPrefix(s.Fingerprint, "sha256:") + " ")
	if err != nil || got != s.Fingerprint {
		t.Fatalf("got %q %v", got, err)
	}
	for _, bad := range []string{"", "sha256:", "sha256:abc", "md5:" + strings.TrimPrefix(s.Fingerprint, "sha256:")} {
		if _, err := ParseFingerprint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPinnedClient(t *testing.T) {
	s, err := LoadOrCreate(t.TempDir(), []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	ts.TLS = s.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	get := func(cfg *tls.Config) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		resp, err := c.Get(ts.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}

	// Unpinned: refused, and Explain reports the fingerprint.
	err = get(nil)
	if err == nil {
		t.Fatal("self-signed accepted without a pin")
	}
	host := strings.TrimPrefix(ts.URL, "https://")
	var ue *UntrustedError
	if !errors.As(Explain(context.Background(), err, host, "127.0.0.1"), &ue) || ue.Fingerprint != s.Fingerprint {
		t.Fatalf("explain: %v", Explain(context.Background(), err, host, "127.0.0.1"))
	}
	// Pinned: accepted.
	if err := get(ClientConfig(s.Fingerprint)); err != nil {
		t.Fatal(err)
	}
	// Wrong pin: refused.
	other, _ := LoadOrCreate(t.TempDir(), []string{"x"}, time.Now())
	if err := get(ClientConfig(other.Fingerprint)); err == nil {
		t.Fatal("wrong pin accepted")
	}
	// Non-TLS errors pass through unchanged.
	plain := errors.New("boom")
	if Explain(context.Background(), plain, host, "") != plain {
		t.Fatal("unrelated error wrapped")
	}
	if _, err := net.ResolveTCPAddr("tcp", host); err != nil {
		t.Fatal(err)
	}
}

// A certificate that a trusted CA issued for another name must not pass
// when the client connects by IP address (TLS has no server name then):
// only the pinned key is accepted. By name, the usual check still works.
func TestPinByIPRejectsOtherTrustedCert(t *testing.T) {
	trusted, err := LoadOrCreate(t.TempDir(), []string{"unrelated.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(trusted.Cert.Leaf) // stands in for a public CA
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	ts.TLS = trusted.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	pinned, _ := LoadOrCreate(t.TempDir(), []string{"x"}, time.Now()) // the real server's key

	get := func(cfg *tls.Config) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		resp, err := c.Get(ts.URL) // https://127.0.0.1:port
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(clientConfig(pinned.Fingerprint, roots)); err == nil {
		t.Fatal("by IP: a trusted certificate for another name was accepted instead of the pinned key")
	}
	// By name, a trusted certificate for that name is still accepted.
	cfg := clientConfig(pinned.Fingerprint, roots)
	cfg.ServerName = "unrelated.example"
	if err := get(cfg); err != nil {
		t.Fatalf("by name: trusted certificate refused: %v", err)
	}
	cfg = clientConfig(pinned.Fingerprint, roots)
	cfg.ServerName = "other.example"
	if err := get(cfg); err == nil {
		t.Fatal("by name: trusted certificate for another name accepted")
	}
}
