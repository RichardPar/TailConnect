package noise

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"tailconnect/internal/key"
)

// handshake runs both sides over a net.Pipe and returns the two conns.
func handshake(t *testing.T, client key.MachinePrivate, serverPriv key.MachinePrivate, serverPub key.MachinePublic) (*Conn, *Conn, error) {
	t.Helper()
	cRaw, sRaw := net.Pipe()
	t.Cleanup(func() { cRaw.Close(); sRaw.Close() })

	ch, init, err := Initiate(client, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		c   *Conn
		err error
	}
	srvc := make(chan res, 1)
	go func() {
		_, resp, wrap, err := Accept(serverPriv, init)
		if err != nil {
			sRaw.Close()
			srvc <- res{nil, err}
			return
		}
		if err := WriteFrame(sRaw, resp); err != nil {
			srvc <- res{nil, err}
			return
		}
		srvc <- res{wrap(sRaw, sRaw), nil}
	}()
	cc, cerr := ch.Finish(cRaw, cRaw)
	sr := <-srvc
	if sr.err != nil {
		return nil, nil, sr.err
	}
	return cc, sr.c, cerr
}

func TestRoundTrip(t *testing.T) {
	client := key.NewPrivate[key.MachineKind]()
	server := key.NewPrivate[key.MachineKind]()
	cc, sc, err := handshake(t, client, server, server.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !sc.Peer().Equal(client.Public()) {
		t.Fatal("server did not learn the client machine key")
	}
	if !cc.Peer().Equal(server.Public()) {
		t.Fatal("client peer key mismatch")
	}

	// Larger than one frame, in both directions concurrently.
	big := make([]byte, 200_000)
	rand.Read(big)
	errc := make(chan error, 1)
	go func() {
		_, err := cc.Write(big)
		errc <- err
	}()
	got := make([]byte, len(big))
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("client→server data corrupted")
	}

	go func() { _, err := sc.Write([]byte("hello")); errc <- err }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(cc, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("server→client: %q %v", buf, err)
	}
	<-errc
}

func TestWrongServerKey(t *testing.T) {
	client := key.NewPrivate[key.MachineKind]()
	server := key.NewPrivate[key.MachineKind]()
	impostor := key.NewPrivate[key.MachineKind]()
	// Client expects `server` but talks to `impostor`: the impostor can't
	// decrypt the initiation, so the handshake must fail.
	if _, _, err := handshake(t, client, impostor, server.Public()); err == nil {
		t.Fatal("handshake with wrong server key succeeded")
	}
}

type tamper struct {
	io.ReadWriter
	flip bool
}

func (t *tamper) Write(p []byte) (int, error) {
	if t.flip && len(p) > 4 {
		q := append([]byte(nil), p...)
		q[len(q)-1] ^= 1
		return t.ReadWriter.Write(q)
	}
	return t.ReadWriter.Write(p)
}

func TestTamperDetected(t *testing.T) {
	client := key.NewPrivate[key.MachineKind]()
	server := key.NewPrivate[key.MachineKind]()
	cc, sc, err := handshake(t, client, server, server.Public())
	if err != nil {
		t.Fatal(err)
	}
	cc.rw = &tamper{ReadWriter: cc.rw, flip: true}
	go cc.Write([]byte("attack at dawn"))
	buf := make([]byte, 32)
	if _, err := sc.Read(buf); err == nil {
		t.Fatal("tampered frame was accepted")
	}
}
