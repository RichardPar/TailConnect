// Package key defines the Curve25519 key types used by TailConnect.
//
// Every node has three key pairs, each with a distinct text prefix so they
// can never be confused with each other in configs, logs or the wire protocol:
//
//   - Machine key ("mkey:"): long-lived identity of the device, used to
//     authenticate the Noise control channel to tc-control.
//   - Node key ("nodekey:"): the WireGuard key. Rotatable.
//   - Disco key ("discokey:"): used to authenticate NAT-traversal discovery
//     messages between peers.
package key

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// Kind distinguishes key families at the type level and supplies their text prefixes.
type Kind interface {
	pubPrefix() string
	privPrefix() string
}

type (
	MachineKind struct{}
	NodeKind    struct{}
	DiscoKind   struct{}
	RelayKind   struct{}
)

func (MachineKind) pubPrefix() string  { return "mkey:" }
func (MachineKind) privPrefix() string { return "mprivkey:" }
func (NodeKind) pubPrefix() string     { return "nodekey:" }
func (NodeKind) privPrefix() string    { return "nodeprivkey:" }
func (DiscoKind) pubPrefix() string    { return "discokey:" }
func (DiscoKind) privPrefix() string   { return "discoprivkey:" }
func (RelayKind) pubPrefix() string    { return "relaykey:" }
func (RelayKind) privPrefix() string   { return "relayprivkey:" }

type (
	MachinePublic  = Public[MachineKind]
	MachinePrivate = Private[MachineKind]
	NodePublic     = Public[NodeKind]
	NodePrivate    = Private[NodeKind]
	DiscoPublic    = Public[DiscoKind]
	DiscoPrivate   = Private[DiscoKind]
	RelayPublic    = Public[RelayKind]
	RelayPrivate   = Private[RelayKind]
)

// Public is a Curve25519 public key of kind K. The zero value is "no key".
type Public[K Kind] struct{ k [32]byte }

// Private is a Curve25519 private key of kind K. The zero value is "no key".
type Private[K Kind] struct{ k [32]byte }

// NewPrivate generates a new random, clamped private key.
func NewPrivate[K Kind]() Private[K] {
	var p Private[K]
	if _, err := rand.Read(p.k[:]); err != nil {
		panic("key: crypto/rand failed: " + err.Error())
	}
	p.k[0] &= 248
	p.k[31] = (p.k[31] & 127) | 64
	return p
}

// PublicFromRaw wraps 32 raw bytes as a public key.
func PublicFromRaw[K Kind](raw [32]byte) Public[K] { return Public[K]{k: raw} }

// ParsePublic parses the text form ("nodekey:<hex>" etc.).
func ParsePublic[K Kind](s string) (Public[K], error) {
	var p Public[K]
	err := p.UnmarshalText([]byte(s))
	return p, err
}

// ParsePrivate parses the text form ("nodeprivkey:<hex>" etc.). Unlike
// UnmarshalText (where "" means "not set"), it refuses an empty or all-zero
// key: everyone can compute Diffie-Hellman with the zero key, so using one
// would let anybody pose as its owner.
func ParsePrivate[K Kind](s string) (Private[K], error) {
	var p Private[K]
	if err := p.UnmarshalText([]byte(strings.TrimSpace(s))); err != nil {
		return p, err
	}
	if p.IsZero() {
		return p, errors.New("key: empty or all-zero private key")
	}
	return p, nil
}

func (p Public[K]) IsZero() bool           { return p.k == [32]byte{} }
func (p Public[K]) Raw() [32]byte          { return p.k }
func (p Public[K]) Equal(o Public[K]) bool { return p.k == o.k }

func (p Public[K]) String() string {
	var k K
	return k.pubPrefix() + hex.EncodeToString(p.k[:])
}

// ShortString returns an abbreviated form for logs, e.g. "[nodekey:1a2b3c]".
func (p Public[K]) ShortString() string {
	var k K
	return "[" + k.pubPrefix() + hex.EncodeToString(p.k[:3]) + "]"
}

// MarshalText encodes the key with its prefix. The zero key encodes as "".
func (p Public[K]) MarshalText() ([]byte, error) {
	if p.IsZero() {
		return []byte{}, nil
	}
	return []byte(p.String()), nil
}

// UnmarshalText decodes a prefixed key. "" decodes to the zero key.
func (p *Public[K]) UnmarshalText(b []byte) error {
	var k K
	return decode(&p.k, string(b), k.pubPrefix())
}

func (p Private[K]) IsZero() bool  { return p.k == [32]byte{} }
func (p Private[K]) Raw() [32]byte { return p.k }

// Public derives the public half of the key pair.
func (p Private[K]) Public() Public[K] {
	if p.IsZero() {
		return Public[K]{}
	}
	out, err := curve25519.X25519(p.k[:], curve25519.Basepoint)
	if err != nil {
		panic("key: X25519 basepoint: " + err.Error())
	}
	var pub Public[K]
	copy(pub.k[:], out)
	return pub
}

// Equal compares in constant time.
func (p Private[K]) Equal(o Private[K]) bool {
	return subtle.ConstantTimeCompare(p.k[:], o.k[:]) == 1
}

// String deliberately redacts the key material so private keys don't leak into logs.
func (p Private[K]) String() string {
	var k K
	return k.privPrefix() + "<redacted>"
}

func (p Private[K]) MarshalText() ([]byte, error) {
	if p.IsZero() {
		return []byte{}, nil
	}
	var k K
	return []byte(k.privPrefix() + hex.EncodeToString(p.k[:])), nil
}

func (p *Private[K]) UnmarshalText(b []byte) error {
	var k K
	return decode(&p.k, string(b), k.privPrefix())
}

var errBadLength = errors.New("key: wrong length")

func decode(dst *[32]byte, s, prefix string) error {
	if s == "" {
		*dst = [32]byte{}
		return nil
	}
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return fmt.Errorf("key: missing %q prefix", prefix)
	}
	if hex.DecodedLen(len(rest)) != 32 {
		return errBadLength
	}
	var tmp [32]byte
	if _, err := hex.Decode(tmp[:], []byte(rest)); err != nil {
		return fmt.Errorf("key: %w", err)
	}
	*dst = tmp
	return nil
}
