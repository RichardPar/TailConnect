package autotls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// TXTSetter publishes the TXT record that proves control of a domain to the
// CA (the DNS-01 challenge), e.g. through a DNS provider's API.
type TXTSetter interface {
	SetTXT(ctx context.Context, domain, value string) error
	ClearTXT(ctx context.Context, domain string) error
}

// dnsManager gets and renews certificates by DNS-01: the CA looks up a TXT
// record instead of connecting to this machine, so no port needs to be
// reachable from the internet.
type dnsManager struct {
	cfg  Config
	logf func(msg string, args ...any)
	now  func() time.Time
	// issue gets a certificate chain for key (replaced in tests).
	issue func(ctx context.Context, domains []string, key crypto.Signer) ([][]byte, error)

	mu   sync.RWMutex
	cert *tls.Certificate
}

// Retry and renewal timing.
var (
	dnsCheckEvery = 12 * time.Hour
	dnsRetry      = []time.Duration{2 * time.Minute, 10 * time.Minute, time.Hour, 6 * time.Hour}
)

func newDNSManager(c Config) (*dnsManager, error) {
	for _, d := range c.Domains {
		if strings.HasPrefix(d, "*.") {
			return nil, fmt.Errorf("%q: wildcard names aren't supported", d)
		}
	}
	m := &dnsManager{cfg: c, logf: c.Logf, now: time.Now}
	if m.logf == nil {
		m.logf = func(string, ...any) {}
	}
	m.issue = m.acmeIssue
	if cert, err := m.loadCert(); err == nil {
		m.cert = cert
	}
	return m, nil
}

// run keeps the certificate valid until ctx ends.
func (m *dnsManager) run(ctx context.Context) {
	failures := 0
	for {
		wait := dnsCheckEvery
		if m.needsRenewal() {
			if err := m.obtain(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				wait = dnsRetry[min(failures, len(dnsRetry)-1)]
				failures++
				m.logf("certificate: DNS check failed; retrying", "domains", m.cfg.Domains, "in", wait, "err", err)
			} else {
				failures = 0
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// needsRenewal: no certificate, or one in the last third of its life.
func (m *dnsManager) needsRenewal() bool {
	m.mu.RLock()
	c := m.cert
	m.mu.RUnlock()
	if c == nil || c.Leaf == nil {
		return true
	}
	life := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore)
	return m.now().After(c.Leaf.NotAfter.Add(-life / 3))
}

func (m *dnsManager) obtain(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	m.logf("certificate: requesting one by DNS check", "domains", m.cfg.Domains)
	chain, err := m.issue(ctx, m.cfg.Domains, key)
	if err != nil {
		return err
	}
	cert, err := certFromChain(chain, key)
	if err != nil {
		return err
	}
	if err := m.saveCert(cert); err != nil {
		m.logf("certificate: can't store it; it will be requested again after a restart", "err", err)
	}
	m.mu.Lock()
	m.cert = cert
	m.mu.Unlock()
	m.logf("certificate obtained", "domains", m.cfg.Domains, "issuer", cert.Leaf.Issuer.CommonName, "expires", cert.Leaf.NotAfter.Format(time.DateOnly))
	return nil
}

func (m *dnsManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	c := m.cert
	m.mu.RUnlock()
	if c == nil {
		return nil, errors.New("autotls: no certificate yet (waiting for the DNS check)")
	}
	return c, nil
}

// acmeIssue runs the ACME order with DNS-01 challenges.
func (m *dnsManager) acmeIssue(ctx context.Context, domains []string, key crypto.Signer) ([][]byte, error) {
	acctKey, err := loadOrCreateKey(m.cachePath("account"))
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	dir := m.cfg.DirectoryURL
	if dir == "" {
		dir = acme.LetsEncryptURL
	}
	client := &acme.Client{Key: acctKey, DirectoryURL: dir, UserAgent: "tailconnect"}
	acct := &acme.Account{}
	if m.cfg.Email != "" {
		acct.Contact = []string{"mailto:" + m.cfg.Email}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register with the CA: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return nil, fmt.Errorf("order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := client.GetAuthorization(ctx, u)
		if err != nil {
			return nil, err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		if err := m.solve(ctx, client, z); err != nil {
			return nil, fmt.Errorf("%s: %w", z.Identifier.Value, err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("order: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: domains}, key)
	if err != nil {
		return nil, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	}
	return chain, nil
}

// solve answers one authorization's DNS-01 challenge: publish the TXT
// record, wait until the domain's name servers serve it, tell the CA.
func (m *dnsManager) solve(ctx context.Context, client *acme.Client, z *acme.Authorization) error {
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == "dns-01" {
			chal = c
		}
	}
	if chal == nil {
		return errors.New("the CA offered no DNS check (dns-01)")
	}
	value, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}
	domain := z.Identifier.Value
	if err := m.cfg.DNS.SetTXT(ctx, domain, value); err != nil {
		return fmt.Errorf("publish the TXT record: %w", err)
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := m.cfg.DNS.ClearTXT(cctx, domain); err != nil {
			m.logf("certificate: can't remove the TXT record", "domain", domain, "err", err)
		}
	}()
	if err := waitTXT(ctx, "_acme-challenge."+domain, value); err != nil {
		m.logf("certificate: TXT record not seen yet; asking the CA anyway", "domain", domain, "err", err)
	}
	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, z.URI); err != nil {
		return fmt.Errorf("the CA's DNS check failed: %w", err)
	}
	return nil
}

// waitTXT waits until fqdn's authoritative name servers serve value, so the
// CA (which asks them directly) sees it. Local resolvers would cache.
var waitTXT = func(ctx context.Context, fqdn, value string) error {
	servers := authoritativeNS(ctx, fqdn)
	if len(servers) == 0 {
		select { // can't check: give the provider a moment
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(30 * time.Second):
		}
		return errors.New("no name servers found to check with")
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		for _, ns := range servers {
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, net.JoinHostPort(ns, "53"))
			}}
			lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			txts, err := r.LookupTXT(lctx, fqdn)
			cancel()
			if err == nil && slices.Contains(txts, value) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s doesn't serve the new TXT record after 3 minutes", fqdn)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// authoritativeNS finds the name servers of the closest zone above fqdn.
func authoritativeNS(ctx context.Context, fqdn string) []string {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for i := 1; i < len(labels)-1; i++ {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		nss, err := net.DefaultResolver.LookupNS(lctx, strings.Join(labels[i:], "."))
		cancel()
		if err == nil && len(nss) > 0 {
			var out []string
			for _, ns := range nss {
				out = append(out, strings.TrimSuffix(ns.Host, "."))
			}
			return out
		}
	}
	return nil
}

// Cache: certificates and the account key, separately for each CA (so a
// test certificate is never served after switching to the real CA).

func (m *dnsManager) cachePath(what string) string {
	sum := sha256.Sum256([]byte(m.cfg.DirectoryURL))
	ca := "letsencrypt"
	if m.cfg.DirectoryURL != "" {
		ca = hex.EncodeToString(sum[:4])
		if m.cfg.DirectoryURL == StagingURL {
			ca = "staging"
		}
	}
	return filepath.Join(m.cfg.CacheDir, "dns01-"+ca+"-"+what+".pem")
}

func (m *dnsManager) certPath() string { return m.cachePath(m.cfg.Domains[0]) }

func (m *dnsManager) loadCert() (*tls.Certificate, error) {
	b, err := os.ReadFile(m.certPath())
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(b, b)
	if err != nil {
		return nil, err
	}
	for _, d := range m.cfg.Domains {
		if cert.Leaf.VerifyHostname(d) != nil {
			return nil, fmt.Errorf("stored certificate doesn't cover %s", d)
		}
	}
	return &cert, nil
}

func (m *dnsManager) saveCert(c *tls.Certificate) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for _, der := range c.Certificate {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return writeFileAtomic(m.certPath(), b, 0o600)
}

func certFromChain(chain [][]byte, key crypto.Signer) (*tls.Certificate, error) {
	if len(chain) == 0 {
		return nil, errors.New("the CA returned no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, err
	}
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("the CA's certificate is for another key")
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}

func loadOrCreateKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: not a PEM key", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s: not a signing key", path)
		}
		return s, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return k, writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
