// Package admin is tc-control's administration web server: a JSON API under
// /api/v1 and an embedded single-page UI at /.
//
// Authentication uses an admin token (created with `tc-control admin-token`).
// Browsers exchange it for an HMAC-signed session cookie; scripts can send it
// as "Authorization: Bearer <token>". Mutating requests must be JSON, and
// cookies are SameSite=Strict, which together block cross-site request forgery.
package admin

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/protocol"
)

//go:embed ui
var uiFS embed.FS

// OnlineWindow is how recently a node must have contacted control to count
// as online. (Milestone 2's streaming map gives a precise signal.)
const OnlineWindow = 5 * time.Minute

type Info struct {
	MachineKey string
	BaseDomain string
	ControlURL string
	Version    string
}

type Server struct {
	db   *db.DB
	info Info
	log  *slog.Logger
	now  func() time.Time
}

func New(d *db.DB, info Info, log *slog.Logger) *Server {
	return &Server{db: d, info: info, log: log, now: time.Now}
}

func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/status", s.status)
	api.HandleFunc("GET /api/v1/users", s.listUsers)
	api.HandleFunc("POST /api/v1/users", s.createUser)
	api.HandleFunc("DELETE /api/v1/users/{name}", s.deleteUser)
	api.HandleFunc("GET /api/v1/keys", s.listKeys)
	api.HandleFunc("POST /api/v1/keys", s.createKey)
	api.HandleFunc("DELETE /api/v1/keys/{id}", s.revokeKey)
	api.HandleFunc("GET /api/v1/nodes", s.listNodes)
	api.HandleFunc("DELETE /api/v1/nodes/{id}", s.deleteNode)
	api.HandleFunc("POST /api/v1/nodes/{id}/rename", s.renameNode)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.Handle("/api/v1/", s.requireAuth(api))
	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("/", http.FileServerFS(sub))
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// checkMutation enforces JSON bodies and same-origin for state-changing requests.
func checkMutation(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return nil
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		// HTML forms can POST cross-site but only with form/text content types.
		// (DELETE can't be sent by a form, and cross-origin fetch needs a preflight.)
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			return errors.New("Content-Type must be application/json")
		}
	}
	if o := r.Header.Get("Origin"); o != "" {
		if o != "http://"+r.Host && o != "https://"+r.Host {
			return errors.New("cross-origin request rejected")
		}
	}
	return nil
}

func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st, err := s.loadAuth(r.Context())
		if err != nil {
			s.internal(w, "auth", err)
			return
		}
		ok := false
		if tok, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found {
			ok = st.checkToken(tok)
		} else if c, err := r.Cookie(sessionCookie); err == nil {
			ok = st.checkSession(c.Value, s.now())
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		if err := checkMutation(r); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := checkMutation(r); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	var req struct{ Token string }
	if !decode(w, r, &req) {
		return
	}
	st, err := s.loadAuth(r.Context())
	if err != nil {
		s.internal(w, "login", err)
		return
	}
	if st.tokenHash == "" {
		writeError(w, http.StatusUnauthorized, "no admin token configured; run `tc-control admin-token` on the server")
		return
	}
	if !st.checkToken(strings.TrimSpace(req.Token)) {
		s.log.Warn("admin login failed", "remote", r.RemoteAddr)
		time.Sleep(500 * time.Millisecond) // blunt online guessing
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	val, exp := st.newSession(s.now())
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: val, Path: "/", Expires: exp,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	s.log.Info("admin login", "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- API types ---

type apiUser struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Nodes   int       `json:"nodes"`
}

type apiKey struct {
	ID        int64     `json:"id"`
	Prefix    string    `json:"prefix"`
	User      string    `json:"user"`
	Reusable  bool      `json:"reusable"`
	Ephemeral bool      `json:"ephemeral"`
	Uses      int       `json:"uses"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	Revoked   bool      `json:"revoked"`
	Usable    bool      `json:"usable"`
}

type apiNode struct {
	ID        int64            `json:"id"`
	Name      string           `json:"name"`
	FQDN      string           `json:"fqdn"`
	User      string           `json:"user"`
	Hostname  string           `json:"hostname"`
	OS        string           `json:"os"`
	IPv4      netip.Addr       `json:"ipv4"`
	IPv6      netip.Addr       `json:"ipv6"`
	Endpoints []netip.AddrPort `json:"endpoints"`
	NodeKey   string           `json:"nodeKey"`
	Ephemeral bool             `json:"ephemeral"`
	Created   time.Time        `json:"created"`
	LastSeen  *time.Time       `json:"lastSeen,omitempty"`
	Online    bool             `json:"online"`
}

func (s *Server) toAPINode(n db.Node) apiNode {
	var hi protocol.Hostinfo
	_ = json.Unmarshal([]byte(n.Hostinfo), &hi)
	out := apiNode{
		ID: n.ID, Name: n.GivenName, FQDN: n.GivenName + "." + s.info.BaseDomain, User: n.UserName,
		Hostname: n.Hostname, OS: hi.OS, IPv4: n.IPv4, IPv6: n.IPv6, Endpoints: n.Endpoints,
		NodeKey: n.NodeKey, Ephemeral: n.Ephemeral, Created: n.CreatedAt,
	}
	if out.Endpoints == nil {
		out.Endpoints = []netip.AddrPort{}
	}
	if !n.LastSeen.IsZero() {
		t := n.LastSeen
		out.LastSeen = &t
		out.Online = s.now().Sub(t) < OnlineWindow
	}
	return out
}

// --- handlers ---

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.db.ListNodes(r.Context(), 0)
	if err != nil {
		s.internal(w, "status", err)
		return
	}
	users, err := s.db.ListUsers(r.Context())
	if err != nil {
		s.internal(w, "status", err)
		return
	}
	online := 0
	for _, n := range nodes {
		if s.toAPINode(n).Online {
			online++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"machineKey": s.info.MachineKey, "baseDomain": s.info.BaseDomain, "controlURL": s.info.ControlURL,
		"version": s.info.Version, "users": len(users), "nodes": len(nodes), "online": online,
	})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListUsers(r.Context())
	if err != nil {
		s.internal(w, "list users", err)
		return
	}
	nodes, err := s.db.ListNodes(r.Context(), 0)
	if err != nil {
		s.internal(w, "list users", err)
		return
	}
	count := map[int64]int{}
	for _, n := range nodes {
		count[n.UserID]++
	}
	out := make([]apiUser, 0, len(users))
	for _, u := range users {
		out = append(out, apiUser{Name: u.Name, Created: u.CreatedAt, Nodes: count[u.ID]})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	u, err := s.db.CreateUser(r.Context(), strings.TrimSpace(req.Name))
	if s.dbError(w, "create user", err) {
		return
	}
	s.log.Info("admin: user created", "user", u.Name)
	writeJSON(w, http.StatusCreated, apiUser{Name: u.Name, Created: u.CreatedAt})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if s.dbError(w, "delete user", s.db.DeleteUser(r.Context(), name)) {
		return
	}
	s.log.Info("admin: user deleted", "user", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.db.ListPreAuthKeys(r.Context(), 0)
	if err != nil {
		s.internal(w, "list keys", err)
		return
	}
	now := s.now()
	out := make([]apiKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, toAPIKey(k, now))
	}
	writeJSON(w, http.StatusOK, out)
}

func toAPIKey(k db.PreAuthKey, now time.Time) apiKey {
	return apiKey{
		ID: k.ID, Prefix: k.Prefix, User: k.UserName, Reusable: k.Reusable, Ephemeral: k.Ephemeral,
		Uses: k.Uses, Created: k.CreatedAt, Expires: k.ExpiresAt, Revoked: k.Revoked, Usable: k.Usable(now),
	}
}

// MaxKeyTTL caps auth-key lifetime from the web UI.
const MaxKeyTTL = 90 * 24 * time.Hour

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User      string `json:"user"`
		Reusable  bool   `json:"reusable"`
		Ephemeral bool   `json:"ephemeral"`
		TTL       string `json:"ttl"` // Go duration, e.g. "24h"
	}
	if !decode(w, r, &req) {
		return
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl <= 0 || ttl > MaxKeyTTL {
		writeError(w, http.StatusBadRequest, "ttl must be a duration between 1s and 2160h (90 days)")
		return
	}
	u, err := s.db.GetUser(r.Context(), req.User)
	if s.dbError(w, "create key", err) {
		return
	}
	secret, k, err := s.db.CreatePreAuthKey(r.Context(), db.CreatePreAuthKeyParams{
		UserID: u.ID, Reusable: req.Reusable, Ephemeral: req.Ephemeral, TTL: ttl,
	})
	if s.dbError(w, "create key", err) {
		return
	}
	s.log.Info("admin: auth key created", "id", k.ID, "user", u.Name, "reusable", k.Reusable)
	writeJSON(w, http.StatusCreated, map[string]any{"key": secret, "info": toAPIKey(k, s.now())})
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || s.dbError(w, "revoke key", s.db.RevokePreAuthKey(r.Context(), id)) {
		return
	}
	s.log.Info("admin: auth key revoked", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.db.ListNodes(r.Context(), 0)
	if err != nil {
		s.internal(w, "list nodes", err)
		return
	}
	out := make([]apiNode, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, s.toAPINode(n))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || s.dbError(w, "delete node", s.db.DeleteNode(r.Context(), id)) {
		return
	}
	s.log.Info("admin: node deleted", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) renameNode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	if s.dbError(w, "rename node", s.db.RenameNode(r.Context(), id, strings.TrimSpace(req.Name))) {
		return
	}
	n, err := s.db.GetNode(r.Context(), id)
	if s.dbError(w, "rename node", err) {
		return
	}
	s.log.Info("admin: node renamed", "id", id, "name", n.GivenName)
	writeJSON(w, http.StatusOK, s.toAPINode(n))
}

// --- helpers ---

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return 0, false
	}
	return id, true
}

// dbError writes an appropriate response for err and reports whether it did.
func (s *Server) dbError(w http.ResponseWriter, op string, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, db.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, db.ErrExists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, db.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, context.Canceled):
		writeError(w, http.StatusRequestTimeout, "request cancelled")
	default:
		s.internal(w, op, err)
	}
	return true
}

func (s *Server) internal(w http.ResponseWriter, op string, err error) {
	s.log.Error("admin: "+op+" failed", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad request body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
