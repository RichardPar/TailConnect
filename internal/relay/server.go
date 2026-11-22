package relay

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/nacl/box"

	"tailconnect/internal/iplimit"
	"tailconnect/internal/key"
)

// AuthorizeFunc decides whether a node (whose key ownership has already been
// proven) may use the relay. nil allows every node.
type AuthorizeFunc func(ctx context.Context, node key.NodePublic) error

// AllowFunc decides, per packet, whether src may send to dst through the
// relay (e.g. only machines of the same tenant). It must be fast.
type AllowFunc func(src, dst key.NodePublic) bool

type Server struct {
	priv      key.RelayPrivate
	authorize AuthorizeFunc
	allow     atomic.Pointer[AllowFunc]
	log       *slog.Logger
	keepAlive time.Duration

	mu      sync.Mutex
	clients map[key.NodePublic]*sclient
	closed  bool

	// Per-IP abuse limits (IPv4 address or IPv6 /64), as on the control
	// listener: anyone can connect and make the relay do a handshake.
	connLimit  *iplimit.Count // open connections
	handshakes *iplimit.Rate  // connection attempts

	packetsForwarded atomic.Int64
	packetsDropped   atomic.Int64
	packetsDenied    atomic.Int64 // refused by the AllowFunc
	connsRefused     atomic.Int64 // connections refused by the per-IP limits
	bytesForwarded   atomic.Int64
}

type sclient struct {
	key   key.NodePublic
	conn  net.Conn
	sendq chan []byte // encoded frames
	done  chan struct{}
	once  sync.Once
}

func (c *sclient) close() {
	c.once.Do(func() {
		close(c.done)
		c.conn.Close()
	})
}

// Per-IP limits. They are generous: machines behind one NAT share an
// address, and each holds one connection per relay it uses.
const (
	connsPerIP     = 64
	connsTotal     = 10000
	handshakeEvery = time.Second
	handshakeBurst = 30 // then one connection attempt a second
)

// KeepAlive is how often the relay sends idle clients a keep-alive frame,
// often enough to keep idle connections open through NATs and firewalls
// that drop them after a minute.
const KeepAlive = 25 * time.Second

func NewServer(priv key.RelayPrivate, authorize AuthorizeFunc, log *slog.Logger) *Server {
	return &Server{priv: priv, authorize: authorize, log: log, keepAlive: KeepAlive, clients: map[key.NodePublic]*sclient{},
		connLimit:  iplimit.NewCount(connsPerIP, connsTotal),
		handshakes: iplimit.NewRate(handshakeEvery, handshakeBurst),
	}
}

// SetAllow installs a per-packet policy (nil = forward between any clients).
func (s *Server) SetAllow(f AllowFunc) {
	if f == nil {
		s.allow.Store(nil)
		return
	}
	s.allow.Store(&f)
}

// PublicKey is the relay server's key, sent to clients in the handshake.
func (s *Server) PublicKey() key.RelayPublic { return s.priv.Public() }

// Stats returns counters for monitoring.
func (s *Server) Stats() (clients int, forwarded, dropped int64) {
	s.mu.Lock()
	clients = len(s.clients)
	s.mu.Unlock()
	return clients, s.packetsForwarded.Load(), s.packetsDropped.Load()
}

// Denied counts packets refused by the AllowFunc.
func (s *Server) Denied() int64 { return s.packetsDenied.Load() }

// Close disconnects all clients. (Hijacked connections are not tracked by
// http.Server.Shutdown.)
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	cs := s.clients
	s.clients = map[key.NodePublic]*sclient{}
	s.mu.Unlock()
	for _, c := range cs {
		c.close()
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), UpgradeProtocol) {
		http.Error(w, "TailConnect relay: expected Upgrade: "+UpgradeProtocol, http.StatusUpgradeRequired)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection cannot be upgraded", http.StatusInternalServerError)
		return
	}
	ip := iplimit.Client(r)
	if !s.handshakes.Allow(ip) {
		s.connsRefused.Add(1)
		http.Error(w, "too many connection attempts from this address; try again later", http.StatusTooManyRequests)
		return
	}
	if !s.connLimit.Acquire(ip) {
		s.connsRefused.Add(1)
		s.log.Info("relay: connection refused: too many open from this address", "remote", r.RemoteAddr)
		http.Error(w, "too many open connections from this address", http.StatusServiceUnavailable)
		return
	}
	defer s.connLimit.Release(ip) // serve below runs for the connection's life
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	// Until the handshake is done, everything (reads and writes) must
	// finish in time, so unauthenticated connections can't linger.
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + UpgradeProtocol + "\r\nConnection: Upgrade\r\n\r\n")
	if err := brw.Flush(); err != nil {
		conn.Close()
		return
	}
	if r.Header.Get(ChallengeHeader) != "1" {
		// A client from before challenges (v0.17 and older): its hello,
		// without one, could be a recording of an earlier connection.
		s.log.Info("relay: client without challenge support refused; it needs TailConnect v0.18 or later", "remote", conn.RemoteAddr())
		writeFrame(conn, frameError, []byte("this relay needs TailConnect v0.18 or later: upgrade this machine"))
		conn.Close()
		return
	}
	s.serve(r.Context(), conn, brw.Reader)
}

// handshakeTimeout bounds the upgrade and handshake.
const handshakeTimeout = 10 * time.Second

func (s *Server) serve(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	// Handshake.
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	pub := s.priv.Public().Raw()
	challenge := make([]byte, challengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return
	}
	if err := writeFrame(conn, frameServerKey, []byte(magic), pub[:], challenge); err != nil {
		return
	}
	t, b, err := readFrame(br, nil)
	if err != nil || t != frameClientInfo || len(b) < keyLen+nonceLen+box.Overhead {
		s.log.Debug("relay: bad client hello", "remote", remote, "err", err)
		return
	}
	var ck [32]byte
	copy(ck[:], b[:keyLen])
	var n24 [24]byte
	copy(n24[:], b[keyLen:keyLen+nonceLen])
	priv := s.priv.Raw()
	plain, ok := box.Open(nil, b[keyLen+nonceLen:], &n24, &ck, &priv)
	if !ok {
		s.log.Info("relay: client failed key proof", "remote", remote)
		writeFrame(conn, frameError, []byte("key proof failed"))
		return
	}
	var info clientInfo
	if err := json.Unmarshal(plain, &info); err != nil || info.Version != version {
		writeFrame(conn, frameError, []byte(fmt.Sprintf("unsupported version %d", info.Version)))
		return
	}
	// The hello must carry this connection's challenge: one recorded from
	// another connection carries that connection's.
	if !hmac.Equal(info.Challenge, challenge) {
		s.log.Info("relay: replayed or mismatched client hello refused", "remote", remote)
		writeFrame(conn, frameError, []byte("key proof failed"))
		return
	}
	nk := key.PublicFromRaw[key.NodeKind](ck)
	if s.authorize != nil {
		if err := s.authorize(ctx, nk); err != nil {
			s.log.Info("relay: client not authorized", "node", nk.ShortString(), "remote", remote, "err", err)
			writeFrame(conn, frameError, []byte("not authorized: "+err.Error()))
			return
		}
	}
	si, _ := json.Marshal(serverInfo{Version: version})
	if err := writeFrame(conn, frameServerInfo, si); err != nil {
		return
	}
	conn.SetDeadline(time.Time{}) // the writer sets its own write deadlines

	c := &sclient{key: nk, conn: conn, sendq: make(chan []byte, 256), done: make(chan struct{})}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if old := s.clients[nk]; old != nil {
		old.close() // newest connection for a key wins
	}
	s.clients[nk] = c
	s.mu.Unlock()
	s.log.Debug("relay: client connected", "node", nk.ShortString(), "remote", remote)
	defer func() {
		s.mu.Lock()
		if s.clients[nk] == c {
			delete(s.clients, nk)
		}
		s.mu.Unlock()
		c.close()
		s.log.Debug("relay: client disconnected", "node", nk.ShortString())
	}()

	go s.writer(c)

	var buf []byte
	for {
		t, b, err := readFrame(br, buf)
		if err != nil {
			return
		}
		buf = b[:0]
		if t != frameSendPacket || len(b) < keyLen {
			continue // ignore unknown frames for forward compatibility
		}
		var dk [32]byte
		copy(dk[:], b[:keyLen])
		s.forward(nk, key.PublicFromRaw[key.NodeKind](dk), b[keyLen:])
	}
}

func (s *Server) forward(srcKey, dst key.NodePublic, pkt []byte) {
	// Look up the destination first: the policy check may ask the control
	// server, which made packets to made-up keys a way to flood it.
	s.mu.Lock()
	dc := s.clients[dst]
	s.mu.Unlock()
	if dc == nil {
		s.packetsDropped.Add(1)
		return
	}
	if f := s.allow.Load(); f != nil && !(*f)(srcKey, dst) {
		s.packetsDenied.Add(1)
		return
	}
	src := srcKey.Raw()
	frame := make([]byte, 5+keyLen+len(pkt))
	frame[0] = byte(frameRecvPacket)
	putLen(frame[1:5], keyLen+len(pkt))
	copy(frame[5:], src[:])
	copy(frame[5+keyLen:], pkt)
	select {
	case dc.sendq <- frame:
		s.packetsForwarded.Add(1)
		s.bytesForwarded.Add(int64(len(pkt)))
	default:
		s.packetsDropped.Add(1) // receiver is slow; drop rather than block the sender
	}
}

func putLen(b []byte, n int) {
	b[0], b[1], b[2], b[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
}

func (s *Server) writer(c *sclient) {
	t := time.NewTicker(s.keepAlive)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case f := <-c.sendq:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.conn.Write(f); err != nil {
				c.close()
				return
			}
		case <-t.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := writeFrame(c.conn, frameKeepAlive); err != nil {
				c.close()
				return
			}
		}
	}
}

// GenerateNonce returns a random 24-byte nonce.
func generateNonce() ([24]byte, error) {
	var n [24]byte
	_, err := rand.Read(n[:])
	return n, err
}
