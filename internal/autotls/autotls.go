// Package autotls gets and renews HTTPS certificates from Let's Encrypt (or
// another ACME certificate authority) inside the process, so a server needs
// no reverse proxy or certbot: only a DNS name pointing at it, and port 443
// (or 80) reachable from the internet.
package autotls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// StagingURL is Let's Encrypt's test CA: certificates browsers don't
// trust, but generous rate limits, for trying a setup out.
const StagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

type Config struct {
	// Domains to get certificates for (required). Other names are refused.
	Domains []string
	// Email is given to the CA for expiry warnings (optional).
	Email string
	// CacheDir keeps the account key and certificates across restarts.
	CacheDir string
	// HTTPListen serves the CA's HTTP challenges (and redirects other
	// requests to HTTPS), e.g. ":80". Without it, the CA proves the domain
	// over TLS, which works only when the TLS listener is on port 443.
	HTTPListen string
	// TLSListen is the HTTPS listener's address, to check the setup.
	TLSListen string
	// DirectoryURL is the CA (default: Let's Encrypt).
	DirectoryURL string
}

// ParseDomains splits a comma-separated list into lowercase names.
func ParseDomains(s string) ([]string, error) {
	var out []string
	for _, d := range strings.Split(s, ",") {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		if net.ParseIP(d) != nil || !strings.Contains(d, ".") || strings.ContainsAny(d, "/:* ") {
			return nil, fmt.Errorf("%q is not a public DNS name (certificates are issued for names, not addresses)", d)
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, errors.New("no domain given")
	}
	return out, nil
}

// Manager issues certificates on demand and renews them before they expire.
type Manager struct {
	m *autocert.Manager
}

// New checks the configuration and prepares the certificate cache.
func New(c Config) (*Manager, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("autotls: no domains")
	}
	if c.HTTPListen == "" && listenPort(c.TLSListen) != "443" {
		return nil, fmt.Errorf("the certificate authority can't verify the domain: it connects to port 443 or 80, "+
			"but HTTPS listens on %q; listen on :443, or also serve port 80 for its checks", c.TLSListen)
	}
	if c.CacheDir == "" {
		return nil, errors.New("autotls: no cache directory")
	}
	if err := os.MkdirAll(c.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("certificate cache: %w", err)
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(c.CacheDir),
		HostPolicy: autocert.HostWhitelist(c.Domains...),
		Email:      c.Email,
	}
	if c.DirectoryURL != "" {
		m.Client = &acme.Client{DirectoryURL: c.DirectoryURL}
	}
	return &Manager{m: m}, nil
}

// TLSConfig is for the HTTPS listeners: it answers the CA's TLS challenges
// and serves the issued certificates.
func (m *Manager) TLSConfig() *tls.Config {
	cfg := m.m.TLSConfig()
	cfg.MinVersion = tls.VersionTLS12
	return cfg
}

// HTTPHandler serves the CA's HTTP challenges and redirects everything else
// to HTTPS (for Config.HTTPListen).
func (m *Manager) HTTPHandler() http.Handler { return m.m.HTTPHandler(nil) }

func listenPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}
