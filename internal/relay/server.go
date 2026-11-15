package relay

import (
	"bufio"
	"context"
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

	packetsForwarded atomic.Int64
	packetsDropped   atomic.Int64
	packetsDenied    atomic.Int64 // refused by the AllowFunc
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

func NewServer(priv key.RelayPrivate, authorize AuthorizeFunc, log *slog.Logger) *Server {
	return &Server{priv: priv, authorize: authorize, log: log, keepAlive: 60 * time.Second, clients: map[key.NodePublic]*sclient{}}
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
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + UpgradeProtocol + "\r\nConnection: Upgrade\r\n\r\n")
	if err := brw.Flush(); err != nil {
		conn.Close()
		return
	}
	s.serve(r.Context(), conn, brw.Reader)
}

func (s *Server) serve(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	// Handshake.
	pub := s.priv.Public().Raw()
	if err := writeFrame(conn, frameServerKey, []byte(magic), pub[:]); err != nil {
		return
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
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
	conn.SetReadDeadline(time.Time{})

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
	if f := s.allow.Load(); f != nil && !(*f)(srcKey, dst) {
		s.packetsDenied.Add(1)
		return
	}
	src := srcKey.Raw()
	s.mu.Lock()
	dc := s.clients[dst]
	s.mu.Unlock()
	if dc == nil {
		s.packetsDropped.Add(1)
		return
	}
	frame := make([]byte, 5+keyLen+len(pkt))
	frame[0] = byte(frameRecvPacket)
	putLen(frame[1:5], keyLen+len(pkt))
	copy(frame[5:], src[:])
	copy(frame[5+keyLen:], pkt)
	select {
	case dc.sendq <- frame:
		s.packetsForwarded.Add(1)
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
