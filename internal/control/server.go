// Package control implements tc-control's client-facing coordination API:
// server key discovery, node registration and the network map.
//
// Milestone 1 serves /machine/* as plain JSON over HTTP(S). These endpoints
// trust the keys in the request body, so the listener must not be exposed to
// untrusted networks until milestone 2 wraps them in a Noise IK channel
// authenticated by the machine key.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/ipam"
	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

type Config struct {
	// BaseDomain is the MagicDNS suffix, e.g. "home.tc".
	BaseDomain string
	Relays     protocol.RelayMap
	// Nameservers are upstream DNS servers pushed to clients (optional).
	Nameservers []netip.Addr
}

type Server struct {
	db     *db.DB
	cfg    Config
	ipam   *ipam.Allocator
	mkey   key.MachinePrivate
	log    *slog.Logger
	maxReq int64
}

const settingMachineKey = "control.machine_key"

// New loads (or creates on first run) the server's machine key and returns a server.
func New(ctx context.Context, d *db.DB, cfg Config, log *slog.Logger) (*Server, error) {
	if cfg.BaseDomain == "" {
		return nil, errors.New("control: BaseDomain is required")
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
	return &Server{db: d, cfg: cfg, ipam: ipam.Default(), mkey: mk, log: log, maxReq: 64 << 10}, nil
}

// MachinePublic is the server's public machine key (clients pin it).
func (s *Server) MachinePublic() key.MachinePublic { return s.mkey.Public() }

// Handler returns the client-facing HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /key", s.handleKey)
	mux.HandleFunc("POST /machine/register", s.handleRegister)
	mux.HandleFunc("POST /machine/map", s.handleMap)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	return mux
}

func (s *Server) handleKey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, protocol.ServerKeyResponse{Version: protocol.CurrentVersion, MachineKey: s.MachinePublic()})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.MachineKey.IsZero() || req.NodeKey.IsZero() {
		writeError(w, http.StatusBadRequest, "MachineKey and NodeKey are required")
		return
	}
	hi, _ := json.Marshal(req.Hostinfo)
	res, err := s.db.RegisterNode(r.Context(), db.RegisterParams{
		MachineKey: req.MachineKey.String(),
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
	node, err := s.toProtocol(res.Node)
	if err != nil {
		s.internalError(w, "register", err)
		return
	}
	s.log.Info("node registered", "node", res.Node.GivenName, "id", res.Node.ID, "user", res.Node.UserName,
		"ip", res.Node.IPv4, "created", res.Created, "rotated", res.Rotated)
	writeJSON(w, http.StatusOK, protocol.RegisterResponse{Node: node})
}

func (s *Server) handleMap(w http.ResponseWriter, r *http.Request) {
	var req protocol.MapRequest
	if !s.decode(w, r, &req) {
		return
	}
	self, err := s.db.GetNodeByNodeKey(r.Context(), req.NodeKey.String())
	if errors.Is(err, db.ErrNotFound) {
		// The client must (re-)register; e.g. the node was deleted by an admin.
		writeError(w, http.StatusUnauthorized, "node key not registered")
		return
	}
	if err != nil {
		s.internalError(w, "map", err)
		return
	}
	var hi string
	if req.Hostinfo != nil {
		b, _ := json.Marshal(req.Hostinfo)
		hi = string(b)
	}
	if err := s.db.UpdateNodeStatus(r.Context(), self.ID, textOrEmpty(req.DiscoKey), req.Endpoints, hi); err != nil {
		s.internalError(w, "map", err)
		return
	}
	resp, err := s.BuildMap(r.Context(), self.ID)
	if err != nil {
		s.internalError(w, "map", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
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
			MagicDNS:    true,
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
			resp.Peers = append(resp.Peers, pn)
		}
	}
	if !found {
		return protocol.MapResponse{}, fmt.Errorf("node %d: %w", id, db.ErrNotFound)
	}
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

func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.maxReq))
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

// Timeouts suitable for the client-facing listener. Map streaming (milestone 2)
// will need WriteTimeout lifted for that route.
const (
	ReadHeaderTimeout = 10 * time.Second
	IdleTimeout       = 120 * time.Second
)
