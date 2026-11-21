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
	"tailconnect/internal/iplimit"
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
	// TenantDomainSuffixes are the suffixes accounts may choose their own
	// MagicDNS domain under (e.g. "internal" allows "acme.internal").
	// Empty: only operators can set account domains.
	TenantDomainSuffixes []string
	ControlURL           string
	// TLSFingerprint is the pin of the server's self-signed certificate
	// ("" when it has none): shown for clients to check and pin.
	TLSFingerprint string
	Version        string
	Signup         string        // sign-up mode (SignupOff, ...); "" = off
	KeyExpiry      time.Duration // default key lifetime for machines (0 = never)
	// Traffic returns what machine id reported about its traffic (nil if
	// nothing), from the control server. nil: no traffic in the portal.
	Traffic func(id int64) *protocol.MachineTraffic
	// Hosts are the names the portal answers to, besides IP addresses
	// (always allowed). Requests for other names are refused.
	Hosts []string
}

type Server struct {
	db   *db.DB
	info Info
	log  *slog.Logger
	now  func() time.Time

	hashSem   chan struct{}   // bounds concurrent password hashing
	hosts     map[string]bool // allowed Host names (normalized)
	authLimit *iplimit.Rate   // password attempts and sign-ups per client (IPv4 address or IPv6 /64)
	// acctLimit is wrong passwords per account, from anywhere, so guessing
	// from many addresses gets no further. It counts only failures, so it
	// never blocks a sign-in with the right password before it runs out.
	acctLimit *iplimit.Rate
}

func New(d *db.DB, info Info, log *slog.Logger) *Server {
	s := &Server{
		db: d, info: info, log: log, now: time.Now,
		hashSem:   make(chan struct{}, 4),
		hosts:     map[string]bool{"localhost": true},
		authLimit: iplimit.NewRate(6*time.Second, 10), // 10 at once, then one every 6s
		acctLimit: iplimit.NewRate(time.Minute, 20),   // 20 wrong, then one a minute
	}
	for _, h := range info.Hosts {
		if h = normalHost(strings.TrimSpace(h)); h != "" {
			s.hosts[h] = true
		}
	}
	return s
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
	api.HandleFunc("POST /api/v1/nodes/{id}/aliases", s.setNodeAliases)
	api.HandleFunc("POST /api/v1/nodes/{id}/exit-node", s.setNodeExitNode)
	api.HandleFunc("GET /api/v1/rules", s.listRules)
	api.HandleFunc("POST /api/v1/rules", s.addRule)
	api.HandleFunc("DELETE /api/v1/rules/{id}", s.deleteRule)
	api.HandleFunc("GET /api/v1/me/settings", s.getSettings)
	api.HandleFunc("POST /api/v1/me/settings", s.setSettings)
	api.HandleFunc("POST /api/v1/nodes/{id}/shares", s.shareNode)
	api.HandleFunc("POST /api/v1/nodes/{id}/share-links", s.createShareLink)
	api.HandleFunc("GET /api/v1/shares", s.listShares)
	api.HandleFunc("POST /api/v1/shares/{id}/accept", s.acceptShare)
	api.HandleFunc("POST /api/v1/shares/{id}/ports", s.setSharePorts)
	api.HandleFunc("POST /api/v1/shares/redeem", s.redeemShareLink)
	api.HandleFunc("DELETE /api/v1/shares/{id}", s.deleteShare)
	// Operators only.
	op := func(pattern string, h http.HandlerFunc) { api.Handle(pattern, operatorOnly(h)) }
	op("GET /api/v1/users", s.listUsers)
	op("POST /api/v1/users", s.createUser)
	op("DELETE /api/v1/users/{name}", s.deleteUser)
	op("POST /api/v1/users/{name}/status", s.setStatus)
	op("POST /api/v1/users/{name}/role", s.setRole)
	op("POST /api/v1/users/{name}/dns-domain", s.setUserDNSDomain)
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
	return securityHeaders(s.checkHost(mux))
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		if r.TLS != nil {
			// No includeSubDomains: other names under the domain aren't ours.
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
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
	DNSDomain   string    `json:"dnsDomain"` // the account's machines are <machine>.<DNSDomain>
	Custom      bool      `json:"customDomain"`
	Created     time.Time `json:"created"`
	Nodes       int       `json:"nodes"`
}

func (s *Server) toAPIUser(u db.User, nodes int) apiUser {
	return apiUser{Name: u.Name, Status: u.Status, Role: u.Role, HasPassword: u.HasPassword(),
		DNSDomain: db.TenantDomain(u.Name, u.DNSDomain, s.info.BaseDomain), Custom: u.DNSDomain != "",
		Created: u.CreatedAt, Nodes: nodes}
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
	Aliases   []string         `json:"aliases"`    // labels, e.g. "nas"
	AliasFQDN []string         `json:"aliasFqdns"` // the same, fully qualified
	ExitNode  bool             `json:"exitNode"`
	KeyExpiry *time.Time       `json:"keyExpiry,omitempty"` // absent = never expires
	Expired   bool             `json:"expired"`
	Created   time.Time        `json:"created"`
	LastSeen  *time.Time       `json:"lastSeen,omitempty"`
	Online    bool             `json:"online"`
	Traffic   *apiTraffic      `json:"traffic,omitempty"`
}

// apiTraffic is a machine's traffic as it reported it: totals since its
// tunnel started, current rates in bytes per second, and per peer.
type apiTraffic struct {
	Updated time.Time        `json:"updated"`
	Rx      int64            `json:"rx"`
	Tx      int64            `json:"tx"`
	RxRate  float64          `json:"rxRate"`
	TxRate  float64          `json:"txRate"`
	Peers   []apiPeerTraffic `json:"peers"`
}

type apiPeerTraffic struct {
	Name   string  `json:"name"`
	FQDN   string  `json:"fqdn"`
	Rx     int64   `json:"rx"`
	Tx     int64   `json:"tx"`
	RxRate float64 `json:"rxRate"`
	TxRate float64 `json:"txRate"`
}

// traffic converts what the control server knows about machine id for the
// API, naming peers from byKey (node key → node).
func (s *Server) traffic(id int64, byKey map[string]db.Node) *apiTraffic {
	if s.info.Traffic == nil {
		return nil
	}
	mt := s.info.Traffic(id)
	if mt == nil {
		return nil
	}
	out := &apiTraffic{Updated: mt.Updated, Rx: mt.RxBytes, Tx: mt.TxBytes, RxRate: mt.RxRate, TxRate: mt.TxRate,
		Peers: make([]apiPeerTraffic, 0, len(mt.Peers))}
	for _, p := range mt.Peers {
		ap := apiPeerTraffic{Rx: p.RxBytes, Tx: p.TxBytes, RxRate: p.RxRate, TxRate: p.TxRate}
		if n, ok := byKey[p.NodeKey.String()]; ok {
			ap.Name, ap.FQDN = n.GivenName, s.fqdn(n)
		} else {
			ap.Name = "another machine" // removed, or not this account's to name
		}
		out.Peers = append(out.Peers, ap)
	}
	return out
}

func (s *Server) fqdn(n db.Node) string {
	return n.GivenName + "." + db.TenantDomain(n.UserName, n.UserDomain, s.info.BaseDomain)
}

func (s *Server) toAPINode(n db.Node) apiNode {
	var hi protocol.Hostinfo
	_ = json.Unmarshal([]byte(n.Hostinfo), &hi)
	out := apiNode{
		ID: n.ID, Name: n.GivenName, FQDN: s.fqdn(n), User: n.UserName,
		Hostname: n.Hostname, OS: hi.OS, IPv4: n.IPv4, IPv6: n.IPv6, Endpoints: n.Endpoints,
		NodeKey: n.NodeKey, Ephemeral: n.Ephemeral, Approved: n.Approved, Tags: n.Tags, ExitNode: n.ExitNode, Expired: n.Expired(s.now()), Created: n.CreatedAt,
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	out.Aliases, out.AliasFQDN = []string{}, []string{}
	dom := db.TenantDomain(n.UserName, n.UserDomain, s.info.BaseDomain)
	for _, a := range n.Aliases {
		out.Aliases = append(out.Aliases, a)
		out.AliasFQDN = append(out.AliasFQDN, a+"."+dom)
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
		"machineKey": s.info.MachineKey, "baseDomain": s.info.BaseDomain, "controlURL": s.info.ControlURL, "tlsFingerprint": s.info.TLSFingerprint,
		"version": s.info.Version, "nodes": len(nodes), "online": online, "signup": s.info.Signup,
		"pendingMachines": pendingMachines, "keyExpiryDays": int(s.info.KeyExpiry / (24 * time.Hour)),
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
		out = append(out, s.toAPIUser(u, count[u.ID]))
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
	writeJSON(w, http.StatusCreated, s.toAPIUser(u, 0))
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
	resp := map[string]any{"key": secret, "info": toAPIKey(k, s.now()), "joinURL": JoinURL(s.info.ControlURL, secret, s.info.TLSFingerprint)}
	if svg, err := qrSVG(JoinURL(s.info.ControlURL, secret, s.info.TLSFingerprint)); err == nil {
		resp["qrSvg"] = svg
	}
	writeJSON(w, http.StatusCreated, resp)
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
	// Peers in traffic reports are named from the machines the account is
	// connected with: its own, machines shared with it, and the machines
	// of accounts it shares with (all in its machines' maps anyway). A
	// machine reports traffic per node key, so naming from every machine
	// would tell a former share partner what a key is called now.
	var byKey map[string]db.Node
	if s.info.Traffic != nil {
		all, err := s.db.ListNodes(r.Context(), 0)
		if err != nil {
			s.internal(w, "list nodes", err)
			return
		}
		visible := func(db.Node) bool { return true } // operators see everything
		if sc := principalFrom(r.Context()).scope(); sc != 0 {
			shares, err := s.db.ListShares(r.Context(), db.ShareFilter{OwnerID: sc, RecipientID: sc})
			if err != nil {
				s.internal(w, "list shares", err)
				return
			}
			nodesIn, accountsOut := map[int64]bool{}, map[int64]bool{}
			for _, sh := range shares {
				if !sh.InEffect() {
					continue
				}
				if sh.RecipientID == sc {
					nodesIn[sh.NodeID] = true
				} else {
					accountsOut[sh.RecipientID] = true
				}
			}
			visible = func(n db.Node) bool { return n.UserID == sc || nodesIn[n.ID] || accountsOut[n.UserID] }
		}
		byKey = make(map[string]db.Node, len(all))
		for _, n := range all {
			if visible(n) {
				byKey[n.NodeKey] = n
			}
		}
	}
	out := make([]apiNode, 0, len(nodes))
	for _, n := range nodes {
		an := s.toAPINode(n)
		an.Traffic = s.traffic(n.ID, byKey)
		out = append(out, an)
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

// setNodeExpiry sets when a machine's key expires: never, the server's
// default lifetime from now, a number of months from now, or a date (see
// NodeExpiry).
func (s *Server) setNodeExpiry(w http.ResponseWriter, r *http.Request) {
	n, ok := s.ownNode(w, r)
	if !ok {
		return
	}
	var req struct{ Expiry string }
	if !decode(w, r, &req) {
		return
	}
	at, err := NodeExpiry(req.Expiry, s.now(), s.info.KeyExpiry, time.Local)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.dbError(w, "set expiry", s.db.SetNodeExpiry(r.Context(), n.ID, at)) {
		return
	}
	s.log.Info("machine key expiry set", "node", n.GivenName, "user", n.UserName, "expiry", req.Expiry, "by", principalFrom(r.Context()).name())
	s.writeNode(w, r, n.ID)
}

// setNodeExitNode lets a machine carry its account's internet traffic, or
// stops it. Only Linux clients can forward traffic, so only they can be
// made exit nodes (turning it off always works).
func (s *Server) setNodeExitNode(w http.ResponseWriter, r *http.Request) {
	n, ok := s.ownNode(w, r)
	if !ok {
		return
	}
	var req struct{ Enabled bool }
	if !decode(w, r, &req) {
		return
	}
	if req.Enabled {
		if err := db.CanBeExitNode(n); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if s.dbError(w, "set exit node", s.db.SetNodeExitNode(r.Context(), n.ID, req.Enabled)) {
		return
	}
	s.log.Info("machine exit node", "node", n.GivenName, "user", n.UserName, "enabled", req.Enabled, "by", principalFrom(r.Context()).name())
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
	writeJSON(w, http.StatusOK, s.settingsJSON(*p.user))
}

func (s *Server) settingsJSON(u db.User) map[string]any {
	suffixes := s.info.TenantDomainSuffixes
	if u.Operator() {
		suffixes = nil // any domain
	}
	return map[string]any{
		"requireMachineApproval": u.RequireMachineApproval,
		"dnsDomain":              db.TenantDomain(u.Name, u.DNSDomain, s.info.BaseDomain),
		"customDomain":           u.DNSDomain,
		"defaultDomain":          db.TenantDomain(u.Name, "", s.info.BaseDomain),
		"domainSuffixes":         suffixes,
		"canSetDomain":           u.Operator() || len(s.info.TenantDomainSuffixes) > 0,
	}
}

// checkTenantDomain enforces the allowed suffixes on a domain an account
// chooses for itself, so a tenant can't make clients it shares machines
// with send real internet names (say, bank.com) to MagicDNS.
func (s *Server) checkTenantDomain(domain string) error {
	if domain == "" {
		return nil
	}
	if len(s.info.TenantDomainSuffixes) == 0 {
		return fmt.Errorf("%w: only an operator can set an account's domain on this server", db.ErrInvalid)
	}
	for _, suf := range s.info.TenantDomainSuffixes {
		if strings.HasSuffix(domain, "."+suf) {
			return nil
		}
	}
	return fmt.Errorf("%w: the domain must end in .%s", db.ErrInvalid, strings.Join(s.info.TenantDomainSuffixes, " or ."))
}

func (s *Server) setSettings(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.user == nil {
		writeError(w, http.StatusBadRequest, "signed in with the admin token: no account settings")
		return
	}
	// Fields left out are unchanged. DNSDomain "" restores the default.
	var req struct {
		RequireMachineApproval *bool
		DNSDomain              *string
	}
	if !decode(w, r, &req) {
		return
	}
	if req.DNSDomain != nil {
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(*req.DNSDomain)), ".")
		if d == db.TenantDomain(p.user.Name, "", s.info.BaseDomain) {
			d = "" // the default, typed out
		}
		if !p.user.Operator() && s.dbError(w, "settings", s.checkTenantDomain(d)) {
			return
		}
		if s.dbError(w, "settings", s.db.SetUserDNSDomain(r.Context(), p.user.Name, d, s.info.BaseDomain)) {
			return
		}
		s.log.Info("account settings", "login", p.user.Name, "dns_domain", d)
	}
	if req.RequireMachineApproval != nil {
		if s.dbError(w, "settings", s.db.SetMachineApproval(r.Context(), p.user.Name, *req.RequireMachineApproval)) {
			return
		}
		s.log.Info("account settings", "login", p.user.Name, "require_machine_approval", *req.RequireMachineApproval)
	}
	u, err := s.db.GetUser(r.Context(), p.user.Name)
	if s.dbError(w, "settings", err) {
		return
	}
	writeJSON(w, http.StatusOK, s.settingsJSON(u))
}
