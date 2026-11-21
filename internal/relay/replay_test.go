package relay

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"tailconnect/internal/key"
)

// rawHello does the relay handshake by hand, as priv, asking for a
// challenge or not. If replay is set it's sent as the ClientInfo payload
// instead of a fresh proof. It returns the payload sent and the server's
// answer.
func rawHello(t *testing.T, relayURL string, priv key.NodePrivate, askChallenge bool, replay []byte) ([]byte, frameType) {
	t.Helper()
	u, _ := url.Parse(relayURL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req, _ := http.NewRequest("GET", relayURL, nil)
	req.Header.Set("Upgrade", UpgradeProtocol)
	req.Header.Set("Connection", "Upgrade")
	if askChallenge {
		req.Header.Set(ChallengeHeader, "1")
	}
	req.Write(conn)
	br := bufio.NewReader(conn)
	if resp, err := http.ReadResponse(br, req); err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v", err)
	}
	ft, b, err := readFrame(br, nil)
	if err != nil || ft != frameServerKey {
		t.Fatalf("server key: %v %d", err, ft)
	}
	if got, want := len(b) > len(magic)+keyLen, askChallenge; got != want {
		t.Fatalf("challenge sent: %v, want %v", got, want)
	}
	payload := replay
	if payload == nil {
		var sp [32]byte
		copy(sp[:], b[len(magic):len(magic)+keyLen])
		info, _ := json.Marshal(clientInfo{Version: version, Challenge: b[len(magic)+keyLen:]})
		nonce, _ := generateNonce()
		raw := priv.Raw()
		pub := priv.Public().Raw()
		payload = append(append(pub[:], nonce[:]...), box.Seal(nil, info, &nonce, &sp, &raw)...)
	}
	writeFrame(conn, frameClientInfo, payload)
	ft, _, err = readFrame(br, nil)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	return payload, ft
}

func TestHelloReplayRefused(t *testing.T) {
	_, u := newServer(t, nil)
	victim := key.NewPrivate[key.NodeKind]()
	for _, challenge := range []bool{true, false} {
		recorded, ft := rawHello(t, u, victim, challenge, nil)
		if ft != frameServerInfo {
			t.Fatalf("challenge=%v: genuine hello refused (%d)", challenge, ft)
		}
		// An eavesdropper sends the same hello again, with or without
		// asking for a challenge: refused either way.
		for _, ask := range []bool{true, false} {
			if _, ft := rawHello(t, u, victim, ask, recorded); ft != frameError {
				t.Fatalf("hello recorded with challenge=%v replayed with challenge=%v: accepted", challenge, ask)
			}
		}
	}
}

// A relay that accepts the TCP connection but never answers the upgrade
// must not hang the client: Close returns promptly.
func TestStalledUpgradeDoesNotHangClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // accept, then say nothing
		}
	}()
	c, err := NewClient(ClientOptions{URL: "http://" + ln.Addr().String() + "/relay", NodeKey: key.NewPrivate[key.NodeKind]()})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // dialing, stuck in the upgrade
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung on a stalled upgrade")
	}
}
