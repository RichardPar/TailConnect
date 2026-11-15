// Package admin is tc-control's web portal: a JSON API under /api/v1 and an
// embedded single-page UI at /.
//
// People sign in with an account (name and password). Tenants see and manage
// only their own machines and auth keys; operators manage the whole server:
// accounts, approvals and invites. The admin token (`tc-control admin-token`)
// is the operator's break-glass credential, and the API token for scripts
// ("Authorization: Bearer <token>").
//
// Browsers get an HMAC-signed session cookie. Mutating requests must be JSON,
// and cookies are SameSite=Strict, which together block cross-site request
// forgery.
package admin

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/password"
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
	Signup     string        // sign-up mode (SignupOff, ...); "" = off
	KeyExpiry  time.Duration // default key lifetime for machines (0 = never)
}

type Server struct {
	db   *db.DB
	info Info
	log  *slog.Logger
	now  func() time.Time

	hashSem   chan struct{} // bounds concurrent password hashing
	authLimit *limiter      // sign-in and sign-up attempts per client IP
}

func New(d *db.DB, info Info, log *slog.Logger) *Server {
	return &Server{
		db: d, info: info, log: log, now: time.Now,
		hashSem:   make(chan struct{}, 4),
		authLimit: newLimiter(6*time.Second, 10), // 10 at once, then one every 6s
	}
}

func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	// Any signed-in account; tenants see only their own data.
	api.HandleFunc("GET /api/v1/status", s.status)
	api.HandleFunc("GET /api/v1/me", s.me)
	api.HandleFunc("POST /api/v1/me/password", s.changeOwnPassword)
	api.HandleFunc("GET /api/v1/keys", s.listKeys)
	api.HandleFunc("POST /api/v1/keys", s.createKey)
	api.HandleFunc("DELETE /api/v1/keys/{id}", s.revokeKey)
	api.HandleFunc("GET /api/v1/nodes", s.listNodes)
	api.HandleFunc("DELETE /api/v1/nodes/{id}", s.deleteNode)
	api.HandleFunc("POST /api/v1/nodes/{id}/rename", s.renameNode)
	api.HandleFunc("POST /api/v1/nodes/{id}/approve", s.approveNode)
	api.HandleFunc("POST /api/v1/nodes/{id}/expiry", s.setNodeExpiry)
	api.HandleFunc("POST /api/v1/nodes/{id}/tags", s.setNodeTags)
	api.HandleFunc("GET /api/v1/rules", s.listRules)
	api.HandleFunc("POST /api/v1/rules", s.addRule)
	api.HandleFunc("DELETE /api/v1/rules/{id}", s.deleteRule)
	api.HandleFunc("GET /api/v1/me/settings", s.getSettings)
	api.HandleFunc("POST /api/v1/me/settings", s.setSettings)
	api.HandleFunc("POST /api/v1/nodes/{id}/shares", s.shareNode)
	api.HandleFunc("POST /api/v1/nodes/{id}/share-links", s.createShareLink)
	api.HandleFunc("GET /api/v1/shares", s.listShares)
	api.HandleFunc("POST /api/v1/shares/{id}/accept", s.acceptShare)
	api.HandleFunc("POST /api/v1/shares/redeem", s.redeemShareLink)
	api.HandleFunc("DELETE /api/v1/shares/{id}", s.deleteShare)
	// Operators only.
	op := func(pattern string, h http.HandlerFunc) { api.Handle(pattern, operatorOnly(h)) }
	op("GET /api/v1/users", s.listUsers)
	op("POST /api/v1/users", s.createUser)
	op("DELETE /api/v1/users/{name}", s.deleteUser)
	op("POST /api/v1/users/{name}/status", s.setStatus)
	op("POST /api/v1/users/{name}/role", s.setRole)
	op("POST /api/v1/users/{name}/password", s.setUserPassword)
	op("GET /api/v1/invites", s.listInvites)
	op("POST /api/v1/invites", s.createInvite)
	op("DELETE /api/v1/invites/{id}", s.revokeInvite)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/config", s.config)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("POST /api/signup", s.signup)
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
		var p principal
		ok := false
		if tok, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found {
			ok = st.checkToken(tok)
		} else if c, err := r.Cookie(sessionCookie); err == nil {
			if subject, valid := st.checkSession(c.Value, s.now()); valid {
				p, ok = s.resolve(r.Context(), subject)
			}
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		if err := checkMutation(r); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func operatorOnly(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !principalFrom(r.Context()).operator() {
			writeError(w, http.StatusForbidden, "operators only")
			return
		}
		h(w, r)
	})
}

// --- API types ---

type apiUser struct {
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Role        string    `json:"role"`
	HasPassword bool      `json:"hasPassword"`
	Created     time.Time `json:"created"`
	Nodes       int       `json:"nodes"`
}

func toAPIUser(u db.User, nodes int) apiUser {
	return apiUser{Name: u.Name, Status: u.Status, Role: u.Role, HasPassword: u.HasPassword(), Created: u.CreatedAt, Nodes: nodes}
}

type apiKey struct {
	ID          int64     `json:"id"`
	Prefix      string    `json:"prefix"`
	User        string    `json:"user"`
	Reusable    bool      `json:"reusable"`
	Ephemeral   bool      `json:"ephemeral"`
	Preapproved bool      `json:"preapproved"`
	Uses        int       `json:"uses"`
	Created     time.Time `json:"created"`
	Expires     time.Time `json:"expires"`
	Revoked     bool      `json:"revoked"`
	Usable      bool      `json:"usable"`
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
	Approved  bool             `json:"approved"`
	Tags      []string         `json:"tags"`
	KeyExpiry *time.Time       `json:"keyExpiry,omitempty"` // absent = never expires
	Expired   bool             `json:"expired"`
	Created   time.Time        `json:"created"`
	LastSeen  *time.Time       `json:"lastSeen,omitempty"`
	Online    bool             `json:"online"`
}

func (s *Server) toAPINode(n db.Node) apiNode {
	var hi protocol.Hostinfo
	_ = json.Unmarshal([]byte(n.Hostinfo), &hi)
	out := apiNode{
		ID: n.ID, Name: n.GivenName, FQDN: n.GivenName + "." + db.TenantLabel(n.UserName) + "." + s.info.BaseDomain, User: n.UserName,
		Hostname: n.Hostname, OS: hi.OS, IPv4: n.IPv4, IPv6: n.IPv6, Endpoints: n.Endpoints,
		NodeKey: n.NodeKey, Ephemeral: n.Ephemeral, Approved: n.Approved, Tags: n.Tags, Expired: n.Expired(s.now()), Created: n.CreatedAt,
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	if !n.ExpiresAt.IsZero() {
		t := n.ExpiresAt
		out.KeyExpiry = &t
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
	p := principalFrom(r.Context())
	nodes, err := s.db.ListNodes(r.Context(), p.scope())
	if err != nil {
		s.internal(w, "status", err)
		return
	}
	online, pendingMachines := 0, 0
	for _, n := range nodes {
		if s.toAPINode(n).Online {
			online++
		}
		if !n.Approved {
			pendingMachines++
		}
	}
	out := map[string]any{
		"machineKey": s.info.MachineKey, "baseDomain": s.info.BaseDomain, "controlURL": s.info.ControlURL,
		"version": s.info.Version, "nodes": len(nodes), "online": online, "signup": s.info.Signup,
		"pendingMachines": pendingMachines,
	}
	if p.user != nil {
		incoming, err := s.db.ListShares(r.Context(), db.ShareFilter{RecipientID: p.user.ID})
		if err != nil {
			s.internal(w, "status", err)
			return
		}
		pendingShares := 0
		for _, sh := range incoming {
			if sh.Status == db.SharePending {
				pendingShares++
			}
		}
		out["pendingShares"] = pendingShares
	}
	if p.operator() {
		users, err := s.db.ListUsers(r.Context())
		if err != nil {
			s.internal(w, "status", err)
			return
		}
		pending := 0
		for _, u := range users {
			if u.Status == db.StatusPending {
				pending++
			}
		}
		out["users"], out["pending"] = len(users), pending
	}
	writeJSON(w, http.StatusOK, out)
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
		out = append(out, toAPIUser(u, count[u.ID]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"` // optional: without one, the account can't sign in to the portal
		Role     string `json:"role"`     // default tenant
	}
	if !decode(w, r, &req) {
		return
	}
	acct := db.NewAccount{Name: strings.TrimSpace(req.Name), Role: req.Role}
	if req.Password != "" {
		var err error
		s.hashing(func() { acct.PasswordHash, err = password.Hash(req.Password) })
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	u, err := s.db.CreateAccount(r.Context(), acct)
	if s.dbError(w, "create user", err) {
		return
	}
	s.log.Info("admin: user created", "user", u.Name)
	writeJSON(w, http.StatusCreated, toAPIUser(u, 0))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := s.targetUser(w, r, true)
	if !ok {
		return
	}
	name := u.Name
	if s.dbError(w, "delete user", s.db.DeleteUser(r.Context(), name)) {
		return
	}
	s.log.Info("admin: user deleted", "user", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.db.ListPreAuthKeys(r.Context(), principalFrom(r.Context()).scope())
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
		ID: k.ID, Prefix: k.Prefix, User: k.UserName, Reusable: k.Reusable, Ephemeral: k.Ephemeral, Preapproved: k.Preapproved,
		Uses: k.Uses, Created: k.CreatedAt, Expires: k.ExpiresAt, Revoked: k.Revoked, Usable: k.Usable(now),
	}
}

// MaxKeyTTL caps auth-key lifetime from the web UI.
const MaxKeyTTL = 90 * 24 * time.Hour

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User        string `json:"user"`
		Reusable    bool   `json:"reusable"`
		Ephemeral   bool   `json:"ephemeral"`
		Preapproved bool   `json:"preapproved"`
		TTL         string `json:"ttl"` // Go duration, e.g. "24h"
	}
	if !decode(w, r, &req) {
		return
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl <= 0 || ttl > MaxKeyTTL {
		writeError(w, http.StatusBadRequest, "ttl must be a duration between 1s and 2160h (90 days)")
		return
	}
	// Tenants create keys for themselves; operators for anyone (default: themselves).
	p := principalFrom(r.Context())
	if req.User == "" && p.user != nil {
		req.User = p.user.Name
	}
	if !p.operator() && req.User != p.user.Name {
		writeError(w, http.StatusForbidden, "you can only create keys for your own account")
		return
	}
	u, err := s.db.GetUser(r.Context(), req.User)
	if s.dbError(w, "create key", err) {
		return
	}
	if !u.Active() {
		writeError(w, http.StatusBadRequest, "account "+u.Name+" is not active (pending approval or suspended)")
		return
	}
	secret, k, err := s.db.CreatePreAuthKey(r.Context(), db.CreatePreAuthKeyParams{
		UserID: u.ID, Reusable: req.Reusable, Ephemeral: req.Ephemeral, Preapproved: req.Preapproved, TTL: ttl,
	})
	if s.dbError(w, "create key", err) {
		return
	}
	s.log.Info("admin: auth key created", "id", k.ID, "user", u.Name, "reusable", k.Reusable)
	writeJSON(w, http.StatusCreated, map[string]any{"key": secret, "info": toAPIKey(k, s.now())})
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || s.dbError(w, "revoke key", s.db.RevokeUserPreAuthKey(r.Context(), id, principalFrom(r.Context()).scope())) {
		return
	}
	s.log.Info("admin: auth key revoked", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.db.ListNodes(r.Context(), principalFrom(r.Context()).scope())
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

// ownNode loads node {id}, which must be visible to the principal. Another
// tenant's node is reported as not found.
func (s *Server) ownNode(w http.ResponseWriter, r *http.Request) (db.Node, bool) {
	id, ok := pathID(w, r)
	if !ok {
		return db.Node{}, false
	}
	n, err := s.db.GetNode(r.Context(), id)
	if err == nil {
		if sc := principalFrom(r.Context()).scope(); sc != 0 && n.UserID != sc {
			err = fmt.Errorf("node %d: %w", id, db.ErrNotFound)
		}
	}
	if s.dbError(w, "node", err) {
		return db.Node{}, false
	}
	return n, true
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	n, ok := s.ownNode(w, r)
	id := n.ID
	if !ok || s.dbError(w, "delete node", s.db.DeleteNode(r.Context(), id)) {
		return
	}
	s.log.Info("admin: node deleted", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) renameNode(w http.ResponseWriter, r *http.Request) {
	n0, ok := s.ownNode(w, r)
	if !ok {
		return
	}
	id := n0.ID
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

func (s *Server) approveNode(w http.ResponseWriter, r *http.Request) {
	n, ok := s.ownNode(w, r)
	if !ok || s.dbError(w, "approve node", s.db.ApproveNode(r.Context(), n.ID)) {
		return
	}
	s.log.Info("machine approved", "node", n.GivenName, "user", n.UserName, "by", principalFrom(r.Context()).name())
	s.writeNode(w, r, n.ID)
}

// setNodeExpiry sets a machine's key to never expire, or back to the
// server's default lifetime from now.
func (s *Server) setNodeExpiry(w http.ResponseWriter, r *http.Request) {
	n, ok := s.ownNode(w, r)
	if !ok {
		return
	}
	var req struct{ Expiry string }
	if !decode(w, r, &req) {
		return
	}
	var at time.Time
	switch req.Expiry {
	case "never":
	case "default":
		if s.info.KeyExpiry > 0 {
			at = s.now().Add(s.info.KeyExpiry)
		}
	default:
		writeError(w, http.StatusBadRequest, `expiry must be "never" or "default"`)
		return
	}
	if s.dbError(w, "set expiry", s.db.SetNodeExpiry(r.Context(), n.ID, at)) {
		return
	}
	s.log.Info("machine key expiry set", "node", n.GivenName, "user", n.UserName, "expiry", req.Expiry, "by", principalFrom(r.Context()).name())
	s.writeNode(w, r, n.ID)
}

func (s *Server) writeNode(w http.ResponseWriter, r *http.Request, id int64) {
	n, err := s.db.GetNode(r.Context(), id)
	if s.dbError(w, "node", err) {
		return
	}
	writeJSON(w, http.StatusOK, s.toAPINode(n))
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.user == nil {
		writeError(w, http.StatusBadRequest, "signed in with the admin token: no account settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requireMachineApproval": p.user.RequireMachineApproval})
}

func (s *Server) setSettings(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.user == nil {
		writeError(w, http.StatusBadRequest, "signed in with the admin token: no account settings")
		return
	}
	var req struct{ RequireMachineApproval bool }
	if !decode(w, r, &req) {
		return
	}
	if s.dbError(w, "settings", s.db.SetMachineApproval(r.Context(), p.user.Name, req.RequireMachineApproval)) {
		return
	}
	s.log.Info("account settings", "login", p.user.Name, "require_machine_approval", req.RequireMachineApproval)
	writeJSON(w, http.StatusOK, map[string]any{"requireMachineApproval": req.RequireMachineApproval})
}
