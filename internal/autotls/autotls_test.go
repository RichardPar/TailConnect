package autotls

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseDomains(t *testing.T) {
	d, err := ParseDomains(" Ctl.Example.com., relay.example.com ")
	if err != nil || !slices.Equal(d, []string{"ctl.example.com", "relay.example.com"}) {
		t.Fatalf("%v %v", d, err)
	}
	for _, bad := range []string{"", "192.0.2.1", "localhost", "*.example.com", "ctl.example.com:443"} {
		if _, err := ParseDomains(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNewChecksReachability(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	base := Config{Domains: []string{"ctl.example.com"}, CacheDir: dir}
	c := base
	c.TLSListen = ":7740"
	if _, err := New(c); err == nil || !strings.Contains(err.Error(), "443") {
		t.Fatalf("HTTPS on :7740 without port 80: %v", err)
	}
	c.HTTPListen = ":80"
	if _, err := New(c); err != nil {
		t.Fatalf("with port 80 for challenges: %v", err)
	}
	c = base
	c.TLSListen = ":443"
	m, err := New(c)
	if err != nil {
		t.Fatalf("HTTPS on :443: %v", err)
	}
	cfg := m.TLSConfig()
	if !slices.Contains(cfg.NextProtos, "acme-tls/1") || !slices.Contains(cfg.NextProtos, "http/1.1") || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS config: protos %v, min %x", cfg.NextProtos, cfg.MinVersion)
	}
	// Other names never get a certificate.
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "evil.example.net"}); err == nil {
		t.Fatal("certificate requested for a name not in the list")
	}
	// Port 80 redirects to HTTPS.
	rec := httptest.NewRecorder()
	m.HTTPHandler().ServeHTTP(rec, httptest.NewRequest("GET", "http://ctl.example.com/x", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://ctl.example.com/x" {
		t.Fatalf("redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
