// Package disco defines TailConnect's path-discovery messages, exchanged
// between peers over their WireGuard UDP sockets (and, for CallMeMaybe, via
// the relay) to find and verify direct paths through NATs.
//
// Wire format:
//
//	magic (6) | sender disco public key (32) | nonce (24) | box(type | version | body)
//
// The box is sealed with the sender's disco private key to the receiver's
// disco public key (NaCl box), so messages are authenticated and private.
// Disco keys are published in the network map.
//
// Messages:
//
//	Ping        txid (12) | sender node key (32)
//	Pong        txid (12) | the ping's source address as seen by the receiver (16 + 2)
//	CallMeMaybe the sender's endpoints, 18 bytes each; asks the receiver to
//	            ping them now, so both sides send at once and punch NAT holes
package disco

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/crypto/nacl/box"

	"tailconnect/internal/key"
)

// Magic starts every disco packet. It can't be confused with WireGuard
// (first byte 1–4 followed by three zero bytes) or STUN (first two bits 0,
// magic cookie at bytes 4–8).
const Magic = "TC\xf0\x9f\x92\xac" // "TC💬"

const (
	keyLen    = 32
	nonceLen  = 24
	headerLen = len(Magic) + keyLen + nonceLen
	version   = 0
	epLen     = 18
)

type MessageType byte

const (
	TypePing        MessageType = 1
	TypePong        MessageType = 2
	TypeCallMeMaybe MessageType = 3
)

type TxID [12]byte

func NewTxID() TxID {
	var t TxID
	if _, err := rand.Read(t[:]); err != nil {
		panic(err)
	}
	return t
}

type Message interface{ marshal() []byte }

type Ping struct {
	TxID    TxID
	NodeKey key.NodePublic
}

type Pong struct {
	TxID TxID
	Src  netip.AddrPort
}

type CallMeMaybe struct {
	Endpoints []netip.AddrPort
}

func putAddr(b []byte, ap netip.AddrPort) {
	a := ap.Addr().As16()
	copy(b[:16], a[:])
	binary.BigEndian.PutUint16(b[16:18], ap.Port())
}

func getAddr(b []byte) netip.AddrPort {
	var a [16]byte
	copy(a[:], b[:16])
	return netip.AddrPortFrom(netip.AddrFrom16(a).Unmap(), binary.BigEndian.Uint16(b[16:18]))
}

func (m *Ping) marshal() []byte {
	b := make([]byte, 2+12+keyLen)
	b[0], b[1] = byte(TypePing), version
	copy(b[2:14], m.TxID[:])
	k := m.NodeKey.Raw()
	copy(b[14:], k[:])
	return b
}

func (m *Pong) marshal() []byte {
	b := make([]byte, 2+12+epLen)
	b[0], b[1] = byte(TypePong), version
	copy(b[2:14], m.TxID[:])
	putAddr(b[14:], m.Src)
	return b
}

func (m *CallMeMaybe) marshal() []byte {
	b := make([]byte, 2+epLen*len(m.Endpoints))
	b[0], b[1] = byte(TypeCallMeMaybe), version
	for i, ep := range m.Endpoints {
		putAddr(b[2+i*epLen:], ep)
	}
	return b
}

// MaxEndpoints bounds CallMeMaybe so packets stay small.
const MaxEndpoints = 32

func parse(b []byte) (Message, error) {
	if len(b) < 2 {
		return nil, errShort
	}
	body := b[2:]
	switch MessageType(b[0]) {
	case TypePing:
		if len(body) < 12+keyLen {
			return nil, errShort
		}
		m := &Ping{}
		copy(m.TxID[:], body[:12])
		var k [32]byte
		copy(k[:], body[12:12+keyLen])
		m.NodeKey = key.PublicFromRaw[key.NodeKind](k)
		return m, nil
	case TypePong:
		if len(body) < 12+epLen {
			return nil, errShort
		}
		m := &Pong{}
		copy(m.TxID[:], body[:12])
		m.Src = getAddr(body[12:])
		return m, nil
	case TypeCallMeMaybe:
		m := &CallMeMaybe{}
		for i := 0; i+epLen <= len(body) && len(m.Endpoints) < MaxEndpoints; i += epLen {
			m.Endpoints = append(m.Endpoints, getAddr(body[i:]))
		}
		return m, nil
	default:
		return nil, errors.New("disco: unknown message type")
	}
}

var errShort = errors.New("disco: message too short")

// Looks reports whether b is (probably) a disco packet.
func Looks(b []byte) bool {
	return len(b) > headerLen && string(b[:len(Magic)]) == Magic
}

// Sender returns the sender's disco key without authenticating the packet.
func Sender(b []byte) (key.DiscoPublic, bool) {
	if !Looks(b) {
		return key.DiscoPublic{}, false
	}
	var k [32]byte
	copy(k[:], b[len(Magic):len(Magic)+keyLen])
	return key.PublicFromRaw[key.DiscoKind](k), true
}

// Seal encodes m from priv to the peer's disco key.
func Seal(priv key.DiscoPrivate, to key.DiscoPublic, m Message) []byte {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	pub, sk, pk := priv.Public().Raw(), priv.Raw(), to.Raw()
	out := make([]byte, 0, headerLen+box.Overhead+64)
	out = append(out, Magic...)
	out = append(out, pub[:]...)
	out = append(out, nonce[:]...)
	return box.Seal(out, m.marshal(), &nonce, &pk, &sk)
}

// Open authenticates and decodes a packet from the given sender.
func Open(priv key.DiscoPrivate, from key.DiscoPublic, b []byte) (Message, error) {
	if !Looks(b) {
		return nil, errors.New("disco: not a disco packet")
	}
	var nonce [24]byte
	copy(nonce[:], b[len(Magic)+keyLen:headerLen])
	sk, pk := priv.Raw(), from.Raw()
	plain, ok := box.Open(nil, b[headerLen:], &nonce, &pk, &sk)
	if !ok {
		return nil, errors.New("disco: authentication failed")
	}
	return parse(plain)
}
