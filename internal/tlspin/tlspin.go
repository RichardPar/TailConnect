// Package tlspin lets a server use a self-signed certificate, and clients
// trust it by pinning the fingerprint of its public key, as SSH does with
// host keys.
//
// A fingerprint is "sha256:" and the unpadded base64url SHA-256 of the
// certificate's SubjectPublicKeyInfo. It names the key, not the
// certificate, so the server can reissue its certificate (say, for a new
// address) without breaking clients that pinned it.
package tlspin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const prefix = "sha256:"

// Fingerprint returns the pin of a certificate's public key.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return prefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// ParseFingerprint normalises a fingerprint and checks its form. It accepts
// "SHA256:" in any case, as people copy it.
func ParseFingerprint(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		s = prefix + s[len(prefix):]
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if !strings.HasPrefix(s, prefix) || err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("%q is not a certificate fingerprint (want sha256:… as tc-control prints it)", s)
	}
	return s, nil
}

// ClientConfig returns a TLS client configuration that accepts the server
// if its certificate is valid as usual (a public CA, for its name), or if
// its key matches pin. With pin "", it returns nil: the default checks.
//
// The usual check needs the server's name. Connecting to an IP address
// gives none (TLS doesn't send IP addresses as the server name, so
// ConnectionState.ServerName is empty), and then only the pinned key is
// accepted: verifying the chain alone would accept any trusted certificate,
// for any name.
func ClientConfig(pin string) *tls.Config { return clientConfig(pin, nil) }

// clientConfig is ClientConfig with the trusted roots (nil = the system's).
func clientConfig(pin string, roots *x509.CertPool) *tls.Config {
	if pin == "" {
		return nil
	}
	return &tls.Config{
		// Verification happens in VerifyConnection, which still runs.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tls: server sent no certificate")
			}
			leaf := cs.PeerCertificates[0]
			if Fingerprint(leaf) == pin {
				return nil
			}
			if cs.ServerName == "" {
				return fmt.Errorf("server certificate %s doesn't match the pinned %s (connecting by IP address, only the pinned key is accepted)", Fingerprint(leaf), pin)
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: cs.ServerName, Intermediates: inter, Roots: roots}); err != nil {
				return fmt.Errorf("server certificate %s doesn't match the pinned %s, and isn't trusted: %w", Fingerprint(leaf), pin, err)
			}
			return nil
		},
	}
}

// UntrustedError is a TLS failure because the server's certificate isn't
// signed by a trusted authority (or is for another name), with the
// certificate's fingerprint, so the user can compare and pin it.
type UntrustedError struct {
	Fingerprint string
	Err         error
}

func (e *UntrustedError) Error() string {
	return fmt.Sprintf("the server's certificate isn't trusted (%v). If it's a self-signed certificate, check that its fingerprint, %s, "+
		"matches the one tc-control logs and the web portal shows, then pin it with --tls-fingerprint %s", e.Err, e.Fingerprint, e.Fingerprint)
}

func (e *UntrustedError) Unwrap() error { return e.Err }

// Explain turns err into an *UntrustedError if it's a certificate
// verification failure, by connecting to addr ("host:port") again without
// checks just to read the certificate. Other errors come back unchanged.
func Explain(ctx context.Context, err error, addr, serverName string) error {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var inv x509.CertificateInvalidError
	var tv *tls.CertificateVerificationError
	if err == nil || !(errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &inv) || errors.As(err, &tv)) {
		return err
	}
	fp, ferr := Probe(ctx, addr, serverName)
	if ferr != nil {
		return err
	}
	return &UntrustedError{Fingerprint: fp, Err: err}
}

// Probe connects to addr and returns the fingerprint of the certificate the
// server presents, without checking it.
func Probe(ctx context.Context, addr, serverName string) (string, error) {
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, ServerName: serverName}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no certificate")
	}
	return Fingerprint(certs[0]), nil
}

// Self-signed certificates.

const (
	keyFile  = "self-signed.key"
	certFile = "self-signed.crt"
	// certLife is long: browsers remember an exception per certificate,
	// and clients pin the key anyway.
	certLife = 10 * 365 * 24 * time.Hour
	// renewBefore reissues a certificate this close to expiring.
	renewBefore = 30 * 24 * time.Hour
)

// SelfSigned is a server's self-signed certificate.
type SelfSigned struct {
	Cert        tls.Certificate
	Fingerprint string
	Names       []string // DNS names and IP addresses it is valid for
	Reissued    bool     // a new certificate was written (new key, or new names)
}

// LoadOrCreate returns the self-signed certificate kept in dir, creating
// the key once and reissuing the certificate (with the same key, so the
// fingerprint stays) when it doesn't cover all of names or expires soon.
func LoadOrCreate(dir string, names []string, now time.Time) (*SelfSigned, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	names = normalizeNames(names)
	priv, err := loadOrCreateKey(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, certFile)
	der, reissue := loadCert(certPath, priv, names, now)
	if reissue {
		if der, err = issue(priv, names, now); err != nil {
			return nil, err
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := writeFile(certPath, pemBytes, 0o644); err != nil {
			return nil, err
		}
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &SelfSigned{
		Cert:        tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf},
		Fingerprint: Fingerprint(leaf),
		Names:       certNames(leaf),
		Reissued:    reissue,
	}, nil
}

// TLSConfig serves the certificate to every client.
func (s *SelfSigned) TLSConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.Cert}, MinVersion: tls.VersionTLS12}
}

// LocalNames are the names a server on this machine is likely reached by:
// its hostname (and hostname.local), localhost, ::1 and its IPv4 addresses.
// Other IPv6 addresses are left out: temporary ones change daily, and each
// new certificate makes browsers warn again (-tls-names adds them).
func LocalNames() []string {
	out := []string{"localhost", "::1"}
	if h, err := os.Hostname(); err == nil && h != "" {
		h = strings.ToLower(h)
		out = append(out, h)
		if !strings.Contains(h, ".") {
			out = append(out, h+".local")
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
				out = append(out, ipn.IP.String())
			}
		}
	}
	return out
}

func normalizeNames(names []string) []string {
	var out []string
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if ip := net.ParseIP(strings.Trim(n, "[]")); ip != nil {
			n = ip.String()
		}
		if n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

func certNames(c *x509.Certificate) []string {
	out := slices.Clone(c.DNSNames)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return normalizeNames(out)
}

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: not a PEM key", path)
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// loadCert returns the stored certificate, and whether it must be reissued.
func loadCert(path string, priv *ecdsa.PrivateKey, names []string, now time.Time) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, true
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, true
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || !priv.PublicKey.Equal(c.PublicKey) || now.Add(renewBefore).After(c.NotAfter) {
		return nil, true
	}
	have := certNames(c)
	for _, n := range names {
		if !slices.Contains(have, n) {
			return nil, true
		}
	}
	return blk.Bytes, false
}

func issue(priv *ecdsa.PrivateKey, names []string, now time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	cn := "TailConnect"
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"TailConnect self-signed"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certLife),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
