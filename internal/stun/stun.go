// Package stun implements the small part of STUN (RFC 5389) TailConnect
// needs: Binding requests and responses carrying XOR-MAPPED-ADDRESS, so a
// node can learn the public address and port its UDP socket is mapped to.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

const (
	magicCookie     = 0x2112A442
	headerLen       = 20
	bindingRequest  = 0x0001
	bindingResponse = 0x0101

	attrMappedAddress    = 0x0001
	attrXorMappedAddress = 0x0020
	attrSoftware         = 0x8022
)

// TxID is a STUN transaction ID.
type TxID [12]byte

func NewTxID() TxID {
	var t TxID
	if _, err := rand.Read(t[:]); err != nil {
		panic(err)
	}
	return t
}

// Request returns a Binding request.
func Request(tx TxID) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], bindingRequest)
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	return b
}

func hasCookie(b []byte) bool {
	return len(b) >= headerLen && binary.BigEndian.Uint32(b[4:8]) == magicCookie && b[0]&0xc0 == 0
}

// IsRequest reports whether b looks like a STUN Binding request.
func IsRequest(b []byte) bool {
	return hasCookie(b) && binary.BigEndian.Uint16(b[0:2]) == bindingRequest
}

// IsResponse reports whether b looks like a STUN Binding success response.
func IsResponse(b []byte) bool {
	return hasCookie(b) && binary.BigEndian.Uint16(b[0:2]) == bindingResponse
}

// Response builds a Binding success response telling the client its address.
func Response(tx TxID, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	alen := 4
	family := byte(1)
	if ip.Is6() {
		alen, family = 16, 2
	}
	attrLen := 4 + alen
	b := make([]byte, headerLen+4+attrLen)
	binary.BigEndian.PutUint16(b[0:2], bindingResponse)
	binary.BigEndian.PutUint16(b[2:4], uint16(4+attrLen))
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	a := b[headerLen:]
	binary.BigEndian.PutUint16(a[0:2], attrXorMappedAddress)
	binary.BigEndian.PutUint16(a[2:4], uint16(attrLen))
	a[5] = family
	binary.BigEndian.PutUint16(a[6:8], addr.Port()^uint16(magicCookie>>16))
	xorKey := xorKey(tx)
	raw := ip.AsSlice()
	for i := range raw {
		a[8+i] = raw[i] ^ xorKey[i]
	}
	return b
}

func xorKey(tx TxID) [16]byte {
	var k [16]byte
	binary.BigEndian.PutUint32(k[0:4], magicCookie)
	copy(k[4:], tx[:])
	return k
}

var ErrMalformed = errors.New("stun: malformed message")

// ParseResponse extracts the transaction ID and mapped address from a
// Binding success response.
func ParseResponse(b []byte) (TxID, netip.AddrPort, error) {
	var tx TxID
	if !IsResponse(b) {
		return tx, netip.AddrPort{}, ErrMalformed
	}
	copy(tx[:], b[8:20])
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if headerLen+n > len(b) {
		return tx, netip.AddrPort{}, ErrMalformed
	}
	attrs := b[headerLen : headerLen+n]
	var fallback netip.AddrPort
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+l > len(attrs) {
			return tx, netip.AddrPort{}, ErrMalformed
		}
		v := attrs[4 : 4+l]
		switch typ {
		case attrXorMappedAddress:
			if ap, ok := parseAddr(v, true, tx); ok {
				return tx, ap, nil
			}
		case attrMappedAddress:
			if ap, ok := parseAddr(v, false, tx); ok {
				fallback = ap
			}
		}
		pad := (4 - l%4) % 4
		if 4+l+pad > len(attrs) {
			break
		}
		attrs = attrs[4+l+pad:]
	}
	if fallback.IsValid() {
		return tx, fallback, nil
	}
	return tx, netip.AddrPort{}, ErrMalformed
}

func parseAddr(v []byte, xor bool, tx TxID) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	var alen int
	switch v[1] {
	case 1:
		alen = 4
	case 2:
		alen = 16
	default:
		return netip.AddrPort{}, false
	}
	if len(v) < 4+alen {
		return netip.AddrPort{}, false
	}
	raw := make([]byte, alen)
	copy(raw, v[4:4+alen])
	if xor {
		port ^= uint16(magicCookie >> 16)
		k := xorKey(tx)
		for i := range raw {
			raw[i] ^= k[i]
		}
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, port), true
}

// Serve answers Binding requests on pc until it is closed.
func Serve(pc net.PacketConn) error {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !IsRequest(buf[:n]) {
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		var tx TxID
		copy(tx[:], buf[8:20])
		ap := ua.AddrPort()
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		pc.WriteTo(Response(tx, ap), from)
	}
}
