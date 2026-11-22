// Package relay implements TailConnect's packet relay: a server that
// forwards opaque (WireGuard-encrypted) packets between nodes addressed by
// node public key, for when they cannot reach each other directly.
//
// Transport: an HTTP Upgrade ("Upgrade: tailconnect-relay-v1") on GET /relay,
// over plain HTTP or TLS, then a stream of frames:
//
//	type (1 byte) | length (4 bytes, big endian) | payload
//
// Handshake:
//
//	server → client  ServerKey   magic "TCRELAY1" | server relay public key (32) | challenge (32)
//	client → server  ClientInfo  node public key (32) | nonce (24) | box(info JSON {Version, Challenge})
//	server → client  ServerInfo  JSON {Version}, or Error and close
//
// The ClientInfo box is sealed with the client's node private key to the
// server's public key, proving the client owns the node key it claims, so
// nobody can register someone else's key to intercept their packets.
//
// The challenge makes each proof good for one connection only: the client
// sends the ChallengeHeader on the upgrade request, gets a random challenge
// with the server key and must seal it in its ClientInfo, so a recorded
// ClientInfo can't be replayed. Clients from before the challenge (v0.17
// and older) don't send the header and are refused.
//
// After the handshake:
//
//	client → server  SendPacket  destination key (32) | packet
//	server → client  RecvPacket  source key (32) | packet
//	server → client  KeepAlive   (empty)
package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	UpgradeProtocol = "tailconnect-relay-v1"
	magic           = "TCRELAY1"
	version         = 1

	maxFrame     = 64 << 10
	keyLen       = 32
	nonceLen     = 24
	challengeLen = 32

	// ChallengeHeader on the upgrade request asks for a challenge.
	ChallengeHeader = "Tailconnect-Relay-Challenge"
)

type frameType byte

const (
	frameServerKey  frameType = 1
	frameClientInfo frameType = 2
	frameServerInfo frameType = 3
	frameSendPacket frameType = 4
	frameRecvPacket frameType = 5
	frameKeepAlive  frameType = 6
	frameError      frameType = 7
)

type clientInfo struct {
	Version   int
	Challenge []byte `json:",omitempty"` // the server's challenge, when it sent one
}

type serverInfo struct {
	Version int
}

func writeFrame(w io.Writer, t frameType, parts ...[]byte) error {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	if n > maxFrame {
		return errors.New("relay: frame too large")
	}
	buf := make([]byte, 5, 5+n)
	buf[0] = byte(t)
	binary.BigEndian.PutUint32(buf[1:], uint32(n))
	for _, p := range parts {
		buf = append(buf, p...)
	}
	_, err := w.Write(buf)
	return err
}

// readFrame reads one frame into buf (grown as needed) and returns its type and payload.
func readFrame(r io.Reader, buf []byte) (frameType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("relay: frame of %d bytes exceeds limit", n)
	}
	if cap(buf) < int(n) {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return frameType(hdr[0]), buf, nil
}
