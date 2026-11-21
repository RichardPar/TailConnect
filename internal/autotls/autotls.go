// Package autotls gets and renews HTTPS certificates from Let's Encrypt (or
// another ACME certificate authority) inside the process, so a server needs
// no reverse proxy or certbot: only a DNS name pointing at it, and port 443
// (or 80) reachable from the internet.
package autotls

import (
	"context"
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
	// Email is the contact address for the CA account (optional).
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
	// DNS, if set, proves the domains with DNS TXT records (DNS-01)
	// instead of connections to this machine: no port needs to be
	// reachable from the internet, and HTTPListen is unused.
	DNS TXTSetter
	// Logf logs certificate events (DNS mode), slog style.
	Logf func(msg string, args ...any)
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
	m   *autocert.Manager // connection checks (TLS-ALPN-01, HTTP-01)
	dns *dnsManager       // DNS checks (DNS-01)
}

// New checks the configuration and prepares the certificate cache.
func New(c Config) (*Manager, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("autotls: no domains")
	}
	if c.CacheDir == "" {
		return nil, errors.New("autotls: no cache directory")
	}
	if err := os.MkdirAll(c.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("certificate cache: %w", err)
	}
	if c.DNS != nil {
		if c.HTTPListen != "" {
			return nil, errors.New("a DNS check needs no HTTP listener for the CA")
		}
		dm, err := newDNSManager(c)
		if err != nil {
			return nil, err
		}
		return &Manager{dns: dm}, nil
	}
	if c.HTTPListen == "" && listenPort(c.TLSListen) != "443" {
		return nil, fmt.Errorf("the certificate authority can't verify the domain: it connects to port 443 or 80, "+
			"but HTTPS listens on %q; listen on :443, also serve port 80 for its checks, or prove the domain through DNS", c.TLSListen)
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
	if m.dns != nil {
		return &tls.Config{GetCertificate: m.dns.getCertificate, MinVersion: tls.VersionTLS12}
	}
	cfg := m.m.TLSConfig()
	cfg.MinVersion = tls.VersionTLS12
	return cfg
}

// Start gets the first certificate and keeps renewing it in the
// background, until ctx ends (DNS checks). Connection checks need nothing:
// they happen on the first HTTPS connection.
func (m *Manager) Start(ctx context.Context) {
	if m.dns != nil {
		go m.dns.run(ctx)
	}
}

// HTTPHandler serves the CA's HTTP challenges and redirects everything else
// to HTTPS (for Config.HTTPListen). With DNS checks there are no HTTP
// challenges: it only redirects.
func (m *Manager) HTTPHandler() http.Handler {
	if m.m == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
		})
	}
	return m.m.HTTPHandler(nil)
}

func listenPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}
