// Package noise implements TailConnect's encrypted control channel: a Noise
// IK handshake (Curve25519, ChaChaPoly, BLAKE2s) followed by a framed,
// encrypted byte stream exposed as a net.Conn.
//
// IK means the client (initiator) must already know the server's static key,
// and the server learns and authenticates the client's static key, which is
// the client's machine key, from the first handshake message.
//
// Handshake transport (see internal/control and internal/controlclient):
//
//	client → server  POST /machine/noise  (HTTP/1.1, Upgrade: tailconnect-control-v1,
//	                                       X-TC-Handshake: base64(initiation))
//	server → client  101 Switching Protocols, then one frame holding the response
//	both             encrypted frames; HTTP/2 runs on top
//
// Frames are a 2-byte big-endian length followed by that many bytes.
package noise

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/flynn/noise"

	"tailconnect/internal/key"
)

const (
	// UpgradeProtocol is the HTTP Upgrade token for the control channel.
	UpgradeProtocol = "tailconnect-control-v1"
	// HandshakeHeader carries the base64 initiation message.
	HandshakeHeader = "X-TC-Handshake"

	prologue = "TailConnect control protocol v1"
	// version is sent as the initiation payload so the server can reject
	// clients speaking a protocol it doesn't understand.
	version byte = 1

	maxFrame     = 65535
	tagSize      = 16
	maxPlaintext = maxFrame - tagSize
)

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

func dhKey(priv key.MachinePrivate) noise.DHKey {
	r, p := priv.Raw(), priv.Public().Raw()
	return noise.DHKey{Private: r[:], Public: p[:]}
}

// ClientHandshake is an in-progress initiator handshake.
type ClientHandshake struct {
	hs     *noise.HandshakeState
	server key.MachinePublic
}

// Initiate starts a handshake from machine to server and returns the
// initiation message to send.
func Initiate(machine key.MachinePrivate, server key.MachinePublic) (*ClientHandshake, []byte, error) {
	sraw := server.Raw()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte(prologue),
		StaticKeypair: dhKey(machine),
		PeerStatic:    sraw[:],
	})
	if err != nil {
		return nil, nil, err
	}
	msg, _, _, err := hs.WriteMessage(nil, []byte{version})
	if err != nil {
		return nil, nil, err
	}
	return &ClientHandshake{hs: hs, server: server}, msg, nil
}

// Finish consumes the server's response (read from rw as a frame) and returns
// the encrypted connection. rw is used for all further I/O; c supplies
// addresses, deadlines and Close.
func (h *ClientHandshake) Finish(c net.Conn, rw io.ReadWriter) (*Conn, error) {
	resp, err := readFrame(rw, nil)
	if err != nil {
		return nil, fmt.Errorf("noise: read handshake response: %w", err)
	}
	payload, cs1, cs2, err := h.hs.ReadMessage(nil, resp)
	if err != nil {
		return nil, fmt.Errorf("noise: handshake failed (wrong server key?): %w", err)
	}
	if cs1 == nil || cs2 == nil {
		return nil, errors.New("noise: handshake incomplete")
	}
	if len(payload) != 1 || payload[0] != version {
		return nil, fmt.Errorf("noise: server speaks unsupported protocol version %v", payload)
	}
	return newConn(c, rw, cs1, cs2, h.server), nil
}

// Accept processes an initiation message on the server side. It returns the
// authenticated client machine key, the response message to send (as a
// frame, via WriteFrame) and a function that wraps the transport once the
// response has been sent.
func Accept(server key.MachinePrivate, initiation []byte) (key.MachinePublic, []byte, func(c net.Conn, rw io.ReadWriter) *Conn, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      []byte(prologue),
		StaticKeypair: dhKey(server),
	})
	if err != nil {
		return key.MachinePublic{}, nil, nil, err
	}
	payload, _, _, err := hs.ReadMessage(nil, initiation)
	if err != nil {
		return key.MachinePublic{}, nil, nil, fmt.Errorf("noise: bad initiation: %w", err)
	}
	if len(payload) != 1 || payload[0] != version {
		return key.MachinePublic{}, nil, nil, fmt.Errorf("noise: unsupported client protocol version %v", payload)
	}
	var peerRaw [32]byte
	copy(peerRaw[:], hs.PeerStatic())
	peer := key.PublicFromRaw[key.MachineKind](peerRaw)

	resp, cs1, cs2, err := hs.WriteMessage(nil, []byte{version})
	if err != nil {
		return key.MachinePublic{}, nil, nil, err
	}
	wrap := func(c net.Conn, rw io.ReadWriter) *Conn {
		// cs1 encrypts initiator→responder, cs2 responder→initiator.
		return newConn(c, rw, cs2, cs1, peer)
	}
	return peer, resp, wrap, nil
}

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, b []byte) error {
	if len(b) > maxFrame {
		return errors.New("noise: frame too large")
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf, nil
}

// Conn is an established encrypted channel.
type Conn struct {
	net.Conn // addresses, deadlines, Close
	rw       io.ReadWriter
	peer     key.MachinePublic

	rmu     sync.Mutex
	recv    *noise.CipherState
	rframe  []byte
	pending []byte // decrypted but not yet returned by Read

	wmu  sync.Mutex
	send *noise.CipherState
	wbuf []byte
}

func newConn(c net.Conn, rw io.ReadWriter, send, recv *noise.CipherState, peer key.MachinePublic) *Conn {
	return &Conn{Conn: c, rw: rw, send: send, recv: recv, peer: peer}
}

// Peer is the authenticated machine key of the other side.
func (c *Conn) Peer() key.MachinePublic { return c.peer }

func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		f, err := readFrame(c.rw, c.rframe)
		if err != nil {
			return 0, err
		}
		c.rframe = f
		pt, err := c.recv.Decrypt(c.pending[:0], nil, f)
		if err != nil {
			// A decryption failure means tampering or desync; the stream is unusable.
			c.Conn.Close()
			return 0, fmt.Errorf("noise: decrypt: %w", err)
		}
		c.pending = pt
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlaintext {
			chunk = chunk[:maxPlaintext]
		}
		if cap(c.wbuf) < 2+len(chunk)+tagSize {
			c.wbuf = make([]byte, 0, 2+maxFrame)
		}
		buf := c.wbuf[:2]
		buf, err := c.send.Encrypt(buf, nil, chunk)
		if err != nil {
			return written, err
		}
		binary.BigEndian.PutUint16(buf, uint16(len(buf)-2))
		if _, err := c.rw.Write(buf); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}
