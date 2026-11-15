// Package control implements tc-control's client-facing coordination API.
//
// In the clear it serves only GET /key (the server's public machine key),
// GET /healthz and POST /machine/noise. The latter upgrades the connection
// to a Noise IK channel (internal/noise) carrying HTTP/2, on which the real
// API lives:
//
//	POST /machine/register   join, or rotate the node key
//	POST /machine/map        report status; fetch or stream the network map
//	POST /machine/logout     remove this node
//
// Every request on the channel is authenticated by the client's machine key.
package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"tailconnect/internal/db"
	"tailconnect/internal/ipam"
	"tailconnect/internal/key"
	"tailconnect/internal/noise"
	"tailconnect/internal/protocol"
)

type Config struct {
	// BaseDomain is the MagicDNS suffix, e.g. "tc.internal".
	BaseDomain string
	Relays     protocol.RelayMap
	// DisableMagicDNS stops clients from configuring MagicDNS.
	DisableMagicDNS bool
	// Nameservers are upstream resolvers pushed to clients (optional). When
	// set, clients send all DNS queries through MagicDNS, which forwards
	// names outside BaseDomain to these.
	Nameservers []netip.Addr
	// KeepAlive is the interval between keep-alive messages on map streams
	// (default 30s). Each also refreshes the node's last-seen time.
	KeepAlive time.Duration
	// PollInterval is how often the database generation is checked for
	// changes made by other processes (default 1s).
	PollInterval time.Duration
}

type Server struct {
	db   *db.DB
	cfg  Config
	ipam *ipam.Allocator
	mkey key.MachinePrivate
	log  *slog.Logger
	bus  bus

	ctx    context.Context
	cancel context.CancelFunc

	genMu   sync.Mutex
	lastGen int64

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	online map[int64]int // node ID → number of open map streams
}

const settingMachineKey = "control.machine_key"

// New loads (or creates on first run) the server's machine key and returns a
// server. Call Close to stop background work and drop Noise connections.
func New(ctx context.Context, d *db.DB, cfg Config, log *slog.Logger) (*Server, error) {
	if err := ValidDomain(cfg.BaseDomain); err != nil {
		return nil, fmt.Errorf("control: BaseDomain: %w", err)
	}
	if cfg.KeepAlive <= 0 {
		cfg.KeepAlive = 30 * time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	fresh, _ := key.NewPrivate[key.MachineKind]().MarshalText()
	stored, err := d.SetSettingIfAbsent(ctx, settingMachineKey, string(fresh))
	if err != nil {
		return nil, fmt.Errorf("control: load machine key: %w", err)
	}
	mk, err := key.ParsePrivate[key.MachineKind](stored)
	if err != nil {
		return nil, fmt.Errorf("control: stored machine key: %w", err)
	}
	s := &Server{
		db: d, cfg: cfg, ipam: ipam.Default(), mkey: mk, log: log,
		conns: map[net.Conn]struct{}{}, online: map[int64]int{},
	}
	s.bus.init()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.lastGen, _ = d.Generation(ctx)
	go s.watchGeneration()
	return s, nil
}

// Close stops background work and closes all Noise connections. (Hijacked
// connections are not tracked by http.Server.Shutdown.)
func (s *Server) Close() {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		c.Close()
	}
}

// MachinePublic is the server's public machine key (clients pin it).
func (s *Server) MachinePublic() key.MachinePublic { return s.mkey.Public() }

// Online reports whether node id currently has an open map stream.
func (s *Server) Online(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.online[id] > 0
}

// Handler returns the client-facing HTTP handler (served in the clear or over TLS).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /key", s.handleKey)
	mux.HandleFunc("POST /machine/noise", s.handleUpgrade)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	return mux
}

// noiseHandler serves the API inside the Noise channel.
func (s *Server) noiseHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /machine/register", s.handleRegister)
	mux.HandleFunc("POST /machine/map", s.handleMap)
	mux.HandleFunc("POST /machine/logout", s.handleLogout)
	return mux
}

func (s *Server) handleKey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, protocol.ServerKeyResponse{Version: protocol.CurrentVersion, MachineKey: s.MachinePublic()})
}

// ---- Noise upgrade ----

type machineKeyCtx struct{}

func machineFrom(ctx context.Context) key.MachinePublic {
	mk, _ := ctx.Value(machineKeyCtx{}).(key.MachinePublic)
	return mk
}

func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), noise.UpgradeProtocol) {
		writeError(w, http.StatusBadRequest, "expected Upgrade: "+noise.UpgradeProtocol)
		return
	}
	init, err := base64.StdEncoding.DecodeString(r.Header.Get(noise.HandshakeHeader))
	if err != nil || len(init) == 0 {
		writeError(w, http.StatusBadRequest, "missing or malformed "+noise.HandshakeHeader)
		return
	}
	peer, resp, wrap, err := noise.Accept(s.mkey, init)
	if err != nil {
		// Typically the client has a stale pinned server key.
		s.log.Info("noise handshake rejected", "remote", r.RemoteAddr, "err", err)
		writeError(w, http.StatusUnauthorized, "noise handshake failed")
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "connection cannot be upgraded (HTTP/2 front end?)")
		return
	}
	raw, brw, err := hj.Hijack()
	if err != nil {
		s.log.Error("hijack failed", "err", err)
		return
	}
	_ = raw.SetDeadline(time.Time{})

	var hdr bytes.Buffer
	hdr.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	hdr.WriteString("Upgrade: " + noise.UpgradeProtocol + "\r\nConnection: Upgrade\r\n\r\n")
	if _, err := brw.Write(hdr.Bytes()); err != nil {
		raw.Close()
		return
	}
	if err := noise.WriteFrame(brw, resp); err != nil || brw.Flush() != nil {
		raw.Close()
		return
	}
	nc := wrap(raw, struct {
		io.Reader
		io.Writer
	}{brw.Reader, raw}) // reads may already be buffered in brw

	s.mu.Lock()
	s.conns[raw] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, raw)
		s.mu.Unlock()
		raw.Close()
	}()

	h2 := &http2.Server{ReadIdleTimeout: 60 * time.Second, PingTimeout: 15 * time.Second}
	h2.ServeConn(nc, &http2.ServeConnOpts{
		Context: context.WithValue(s.ctx, machineKeyCtx{}, peer),
		Handler: s.noiseHandler(),
	})
}

// ---- API handlers ----

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	mk := machineFrom(r.Context())
	var req protocol.RegisterRequest
	if !decode(w, r, &req) {
		return
	}
	if !req.MachineKey.IsZero() && !req.MachineKey.Equal(mk) {
		writeError(w, http.StatusForbidden, "MachineKey does not match the Noise channel")
		return
	}
	if req.NodeKey.IsZero() {
		writeError(w, http.StatusBadRequest, "NodeKey is required")
		return
	}
	hi, _ := json.Marshal(req.Hostinfo)
	res, err := s.db.RegisterNode(r.Context(), db.RegisterParams{
		MachineKey: mk.String(),
		NodeKey:    req.NodeKey.String(),
		DiscoKey:   textOrEmpty(req.DiscoKey),
		Hostname:   req.Hostinfo.Hostname,
		Hostinfo:   string(hi),
		AuthKey:    req.AuthKey,
		Alloc:      s.ipam.Next,
	})
	switch {
	case errors.Is(err, db.ErrInvalidAuthKey):
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	case errors.Is(err, db.ErrExists):
		writeError(w, http.StatusConflict, "node key already registered to another machine")
		return
	case errors.Is(err, ipam.ErrExhausted):
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	case err != nil:
		s.internalError(w, "register", err)
		return
	}
	s.checkGeneration()
	node, err := s.toProtocol(res.Node)
	if err != nil {
		s.internalError(w, "register", err)
		return
	}
	s.log.Info("node registered", "node", res.Node.GivenName, "id", res.Node.ID, "user", res.Node.UserName,
		"ip", res.Node.IPv4, "created", res.Created, "rotated", res.Rotated)
	writeJSON(w, http.StatusOK, protocol.RegisterResponse{Node: node})
}

// selfNode looks up the requesting node and checks it belongs to the
// authenticated machine. It writes the error response itself.
func (s *Server) selfNode(w http.ResponseWriter, r *http.Request, nk key.NodePublic) (db.Node, bool) {
	self, err := s.db.GetNodeByNodeKey(r.Context(), nk.String())
	if errors.Is(err, db.ErrNotFound) {
		// The client must (re-)register; e.g. the node was deleted by an admin.
		writeError(w, http.StatusUnauthorized, "node key not registered")
		return db.Node{}, false
	}
	if err != nil {
		s.internalError(w, "lookup node", err)
		return db.Node{}, false
	}
	if self.MachineKey != machineFrom(r.Context()).String() {
		writeError(w, http.StatusForbidden, "node key belongs to a different machine")
		return db.Node{}, false
	}
	return self, true
}

func (s *Server) handleMap(w http.ResponseWriter, r *http.Request) {
	var req protocol.MapRequest
	if !decode(w, r, &req) {
		return
	}
	self, ok := s.selfNode(w, r, req.NodeKey)
	if !ok {
		return
	}
	var hi string
	if req.Hostinfo != nil {
		b, _ := json.Marshal(req.Hostinfo)
		hi = string(b)
	}
	// Subscribe before writing so our own change is reflected in the first map.
	changed := s.bus.wait()
	if err := s.db.UpdateNodeStatus(r.Context(), self.ID, db.NodeStatus{
		DiscoKey: textOrEmpty(req.DiscoKey), Endpoints: req.Endpoints, HomeRelay: req.HomeRelay, Hostinfo: hi,
	}); err != nil {
		s.internalError(w, "map", err)
		return
	}
	s.checkGeneration() // wakes peers' streams only if something they see changed

	if req.OmitPeers && !req.Stream {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !req.Stream {
		resp, err := s.BuildMap(r.Context(), self.ID)
		if err != nil {
			s.internalError(w, "map", err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	s.streamMap(w, r, self, changed)
}

// streamMap writes newline-delimited MapResponses until the client goes away,
// the node is deleted, or the server shuts down.
func (s *Server) streamMap(w http.ResponseWriter, r *http.Request, self db.Node, changed <-chan struct{}) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ctx := r.Context()
	s.mu.Lock()
	s.online[self.ID]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.online[self.ID]--; s.online[self.ID] <= 0 {
			delete(s.online, self.ID)
		}
		s.mu.Unlock()
	}()
	log := s.log.With("node", self.GivenName, "id", self.ID)
	log.Info("map stream opened")
	defer log.Info("map stream closed")

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)

	var last []byte
	send := func() (alive bool) {
		resp, err := s.BuildMap(ctx, self.ID)
		if errors.Is(err, db.ErrNotFound) {
			log.Info("node removed; closing stream")
			return false
		}
		if err != nil {
			log.Error("build map", "err", err)
			return false
		}
		b, _ := json.Marshal(resp)
		if bytes.Equal(b, last) {
			return true
		}
		last = b
		if _, err := w.Write(append(b, '\n')); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !send() {
		return
	}
	keepAlive := time.NewTicker(s.cfg.KeepAlive)
	defer keepAlive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
			changed = s.bus.wait()
			// Debounce bursts (e.g. several nodes reporting at once).
			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
				return
			}
			if !send() {
				return
			}
		case <-keepAlive.C:
			if err := enc.Encode(protocol.MapResponse{KeepAlive: true}); err != nil {
				return
			}
			flusher.Flush()
			_ = s.db.TouchNode(ctx, self.ID)
		}
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req protocol.LogoutRequest
	if !decode(w, r, &req) {
		return
	}
	self, ok := s.selfNode(w, r, req.NodeKey)
	if !ok {
		return
	}
	if err := s.db.DeleteNode(r.Context(), self.ID); err != nil && !errors.Is(err, db.ErrNotFound) {
		s.internalError(w, "logout", err)
		return
	}
	s.checkGeneration()
	s.log.Info("node logged out", "node", self.GivenName, "id", self.ID)
	w.WriteHeader(http.StatusOK)
}

// BuildMap computes the network map for node id. Until ACLs land (milestone
// 8) every node can see every other node.
func (s *Server) BuildMap(ctx context.Context, id int64) (protocol.MapResponse, error) {
	nodes, err := s.db.ListNodes(ctx, 0)
	if err != nil {
		return protocol.MapResponse{}, err
	}
	resp := protocol.MapResponse{
		Peers: []protocol.Node{},
		DNS: protocol.DNSConfig{
			MagicDNS:    !s.cfg.DisableMagicDNS,
			Domain:      s.cfg.BaseDomain,
			Resolver:    protocol.MagicDNSAddr,
			Nameservers: s.cfg.Nameservers,
		},
		Relays: s.cfg.Relays,
	}
	found := false
	for _, n := range nodes {
		pn, err := s.toProtocol(n)
		if err != nil {
			return protocol.MapResponse{}, err
		}
		if n.ID == id {
			resp.Self, found = pn, true
		} else {
			// LastSeen changes on every keep-alive; leaving it out of peers
			// keeps maps stable so unchanged maps aren't re-sent.
			pn.LastSeen = nil
			resp.Peers = append(resp.Peers, pn)
		}
	}
	if !found {
		return protocol.MapResponse{}, fmt.Errorf("node %d: %w", id, db.ErrNotFound)
	}
	resp.Self.LastSeen = nil
	return resp, nil
}

func (s *Server) toProtocol(n db.Node) (protocol.Node, error) {
	nk, err := key.ParsePublic[key.NodeKind](n.NodeKey)
	if err != nil {
		return protocol.Node{}, fmt.Errorf("node %d: %w", n.ID, err)
	}
	dk, err := key.ParsePublic[key.DiscoKind](n.DiscoKey)
	if err != nil {
		return protocol.Node{}, fmt.Errorf("node %d: %w", n.ID, err)
	}
	var hi protocol.Hostinfo
	_ = json.Unmarshal([]byte(n.Hostinfo), &hi)
	out := protocol.Node{
		ID:        protocol.NodeID(n.ID),
		Name:      n.GivenName + "." + s.cfg.BaseDomain,
		User:      n.UserName,
		NodeKey:   nk,
		DiscoKey:  dk,
		Addresses: []netip.Prefix{netip.PrefixFrom(n.IPv4, 32), netip.PrefixFrom(n.IPv6, 128)},
		Endpoints: n.Endpoints,
		HomeRelay: n.HomeRelay,
		Hostinfo:  hi,
		Created:   n.CreatedAt,
	}
	if !n.LastSeen.IsZero() {
		t := n.LastSeen
		out.LastSeen = &t
	}
	if !n.ExpiresAt.IsZero() {
		t := n.ExpiresAt
		out.KeyExpiry = &t
	}
	return out, nil
}

// ---- change notification ----

// bus is a broadcast: wait returns a channel closed by the next notify.
type bus struct {
	mu sync.Mutex
	ch chan struct{}
}

func (b *bus) init() { b.ch = make(chan struct{}) }

func (b *bus) wait() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ch
}

func (b *bus) notify() {
	b.mu.Lock()
	defer b.mu.Unlock()
	close(b.ch)
	b.ch = make(chan struct{})
}

// checkGeneration wakes map streams if the database generation moved.
func (s *Server) checkGeneration() {
	g, err := s.db.Generation(s.ctx)
	if err != nil {
		if s.ctx.Err() == nil {
			s.log.Warn("read generation", "err", err)
		}
		return
	}
	s.genMu.Lock()
	changed := g != s.lastGen
	s.lastGen = g
	s.genMu.Unlock()
	if changed {
		s.bus.notify()
	}
}

// watchGeneration notices changes made outside this process (admin CLI) or
// by the admin web server, which share only the database.
func (s *Server) watchGeneration() {
	t := time.NewTicker(s.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.checkGeneration()
		}
	}
}

// ---- helpers ----

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return false
	}
	return true
}

func (s *Server) internalError(w http.ResponseWriter, op string, err error) {
	s.log.Error(op+" failed", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func textOrEmpty(k key.DiscoPublic) string {
	if k.IsZero() {
		return ""
	}
	return k.String()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, protocol.ErrorResponse{Error: msg})
}

// Timeouts for the client-facing listener. They apply only until a
// connection is upgraded to Noise.
const (
	ReadHeaderTimeout = 10 * time.Second
	IdleTimeout       = 120 * time.Second
)

// ValidDomain checks that d (lowercase, no trailing dot) can be a MagicDNS
// base domain: two or more labels of letters, digits and '-'.
func ValidDomain(d string) error {
	labels := strings.Split(d, ".")
	if d == "" || len(d) > 200 || len(labels) < 2 {
		return fmt.Errorf("%q: want a domain like tc.internal", d)
	}
	for _, l := range labels {
		if l == "" || db.SanitizeName(l) != l {
			return fmt.Errorf("%q: labels must be lowercase letters, digits and '-'", d)
		}
	}
	return nil
}
