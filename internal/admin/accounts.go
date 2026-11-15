package admin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/iplimit"
	"tailconnect/internal/password"
)

// Sign-up modes (tc-control serve -signup).
const (
	SignupOff      = "off"      // only the operator creates accounts
	SignupApproval = "approval" // anyone may sign up; the operator approves
	SignupInvite   = "invite"   // sign-up needs an operator-issued invite code
	SignupOpen     = "open"     // anyone may sign up and use it straight away
)

// ValidSignupMode reports whether m is a sign-up mode.
func ValidSignupMode(m string) bool {
	switch m {
	case SignupOff, SignupApproval, SignupInvite, SignupOpen:
		return true
	}
	return false
}

// MaxInviteTTL caps invite lifetime from the web UI.
const MaxInviteTTL = 30 * 24 * time.Hour

// hashPassword runs password hashing (about 19 MiB and tens of ms each)
// with bounded concurrency, so a burst of sign-ins can't exhaust memory.
func (s *Server) hashing(f func()) {
	s.hashSem <- struct{}{}
	defer func() { <-s.hashSem }()
	f()
}

const tooMany = "too many attempts; wait a minute and try again"

// config is public: the sign-in page uses it to decide what to offer.
func (s *Server) config(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"signup": s.info.Signup, "version": s.info.Version})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := checkMutation(r); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	var req struct {
		Token    string
		Login    string
		Password string
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authLimit.Allow(iplimit.Client(r)) {
		writeError(w, http.StatusTooManyRequests, tooMany)
		return
	}
	st, err := s.loadAuth(r.Context())
	if err != nil {
		s.internal(w, "login", err)
		return
	}

	if req.Token != "" {
		if st.tokenHash == "" {
			writeError(w, http.StatusUnauthorized, "no admin token configured; run `tc-control admin-token` on the server")
			return
		}
		if !st.checkToken(strings.TrimSpace(req.Token)) {
			s.log.Warn("admin login failed", "method", "token", "remote", r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		s.setSession(w, r, st, tokenSubject())
		s.log.Info("admin login", "method", "token", "remote", r.RemoteAddr)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	name := strings.ToLower(strings.TrimSpace(req.Login))
	if s.acctLimit.Blocked(name) {
		s.log.Warn("login refused: too many wrong passwords for this account", "login", name, "remote", r.RemoteAddr)
		writeError(w, http.StatusTooManyRequests, tooMany)
		return
	}
	u, err := s.db.GetUser(r.Context(), name)
	ok := false
	switch {
	case errors.Is(err, db.ErrNotFound) || (err == nil && !u.HasPassword()):
		s.hashing(func() { password.VerifyDummy(req.Password) }) // same timing as a wrong password
	case err != nil:
		s.internal(w, "login", err)
		return
	default:
		s.hashing(func() { ok = password.Verify(req.Password, u.PasswordHash) })
	}
	if !ok {
		s.acctLimit.Allow(name) // count the failure
		s.log.Warn("login failed", "login", name, "remote", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "wrong name or password")
		return
	}
	switch u.Status {
	case db.StatusPending:
		writeError(w, http.StatusForbidden, "your account is waiting for the operator's approval")
		return
	case db.StatusSuspended:
		writeError(w, http.StatusForbidden, "this account is suspended")
		return
	}
	s.setSession(w, r, st, userSubject(u))
	s.log.Info("login", "login", u.Name, "role", u.Role, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	if err := checkMutation(r); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.info.Signup == SignupOff || s.info.Signup == "" {
		writeError(w, http.StatusForbidden, "sign-up is disabled on this server; ask the operator for an account")
		return
	}
	var req struct {
		Login    string
		Password string
		Invite   string
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authLimit.Allow(iplimit.Client(r)) {
		writeError(w, http.StatusTooManyRequests, tooMany)
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Login))
	if !db.ValidUserName(name) {
		writeError(w, http.StatusBadRequest, "choose a name of 1-32 lowercase letters, digits or '-' (it becomes part of your machines' names)")
		return
	}
	if err := password.Check(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	invite := strings.TrimSpace(req.Invite)
	if s.info.Signup == SignupInvite && invite == "" {
		writeError(w, http.StatusBadRequest, "an invite code is required to sign up on this server")
		return
	}
	// A valid invite skips approval in every mode.
	status := db.StatusActive
	if s.info.Signup == SignupApproval && invite == "" {
		status = db.StatusPending
	}
	var hash string
	var herr error
	s.hashing(func() { hash, herr = password.Hash(req.Password) })
	if herr != nil {
		s.internal(w, "signup", herr)
		return
	}
	u, err := s.db.CreateAccount(r.Context(), db.NewAccount{Name: name, PasswordHash: hash, Status: status, Invite: invite})
	switch {
	case errors.Is(err, db.ErrExists):
		writeError(w, http.StatusConflict, "that name is taken")
		return
	case errors.Is(err, db.ErrInvalidInvite):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case s.dbError(w, "signup", err):
		return
	}
	s.log.Info("signup", "login", u.Name, "status", u.Status, "invite", invite != "", "remote", r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]any{"login": u.Name, "status": u.Status})
}

// ---- the signed-in account ----

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	out := map[string]any{"login": p.name(), "operator": p.operator(), "token": p.user == nil}
	if p.user != nil {
		out["role"], out["status"] = p.user.Role, p.user.Status
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.user == nil {
		writeError(w, http.StatusBadRequest, "signed in with the admin token: there is no account password to change")
		return
	}
	var req struct {
		Current string
		New     string
	}
	if !decode(w, r, &req) {
		return
	}
	if err := password.Check(req.New); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Checking the current password is a password guess like signing in,
	// so it has the same limits (a stolen session mustn't guess faster).
	if !s.authLimit.Allow(iplimit.Client(r)) || s.acctLimit.Blocked(p.user.Name) {
		writeError(w, http.StatusTooManyRequests, tooMany)
		return
	}
	ok := false
	s.hashing(func() { ok = password.Verify(req.Current, p.user.PasswordHash) })
	if !ok {
		s.acctLimit.Allow(p.user.Name) // count the failure
		s.log.Warn("password change: wrong current password", "login", p.user.Name, "remote", r.RemoteAddr)
		writeError(w, http.StatusForbidden, "current password is wrong")
		return
	}
	var hash string
	var err error
	s.hashing(func() { hash, err = password.Hash(req.New) })
	if err != nil {
		s.internal(w, "change password", err)
		return
	}
	if s.dbError(w, "change password", s.db.SetPassword(r.Context(), p.user.Name, hash)) {
		return
	}
	// The epoch changed, which ended every session including this one:
	// issue a fresh cookie so the user stays signed in here.
	u, err := s.db.GetUser(r.Context(), p.user.Name)
	st, err2 := s.loadAuth(r.Context())
	if err == nil && err2 == nil {
		s.setSession(w, r, st, userSubject(u))
	}
	s.log.Info("password changed", "login", p.user.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- operator: accounts ----

// targetUser loads the {name} account for an operator action, refusing
// actions on the operator's own account that could lock them out.
func (s *Server) targetUser(w http.ResponseWriter, r *http.Request, protectSelf bool) (db.User, bool) {
	name := r.PathValue("name")
	if p := principalFrom(r.Context()); protectSelf && p.user != nil && p.user.Name == name {
		writeError(w, http.StatusBadRequest, "you can't do that to your own account")
		return db.User{}, false
	}
	u, err := s.db.GetUser(r.Context(), name)
	if s.dbError(w, "user", err) {
		return db.User{}, false
	}
	return u, true
}

func (s *Server) setStatus(w http.ResponseWriter, r *http.Request) {
	u, ok := s.targetUser(w, r, true)
	if !ok {
		return
	}
	var req struct{ Status string }
	if !decode(w, r, &req) {
		return
	}
	if req.Status != db.StatusActive && req.Status != db.StatusSuspended {
		writeError(w, http.StatusBadRequest, `status must be "active" or "suspended"`)
		return
	}
	if s.dbError(w, "set status", s.db.SetUserStatus(r.Context(), u.Name, req.Status)) {
		return
	}
	s.log.Info("admin: account status", "login", u.Name, "from", u.Status, "to", req.Status, "by", principalFrom(r.Context()).name())
	s.writeUser(w, r, u.Name)
}

func (s *Server) setRole(w http.ResponseWriter, r *http.Request) {
	u, ok := s.targetUser(w, r, true)
	if !ok {
		return
	}
	var req struct{ Role string }
	if !decode(w, r, &req) {
		return
	}
	if s.dbError(w, "set role", s.db.SetUserRole(r.Context(), u.Name, req.Role)) {
		return
	}
	s.log.Info("admin: account role", "login", u.Name, "role", req.Role, "by", principalFrom(r.Context()).name())
	s.writeUser(w, r, u.Name)
}

// setUserDNSDomain sets an account's MagicDNS domain (operators only, so
// the tenant suffix restriction doesn't apply). Domain "" restores the default.
func (s *Server) setUserDNSDomain(w http.ResponseWriter, r *http.Request) {
	u, ok := s.targetUser(w, r, false)
	if !ok {
		return
	}
	var req struct{ Domain string }
	if !decode(w, r, &req) {
		return
	}
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Domain)), ".")
	if d == db.TenantDomain(u.Name, "", s.info.BaseDomain) {
		d = ""
	}
	if s.dbError(w, "set dns domain", s.db.SetUserDNSDomain(r.Context(), u.Name, d, s.info.BaseDomain)) {
		return
	}
	s.log.Info("admin: account dns domain", "login", u.Name, "dns_domain", d, "by", principalFrom(r.Context()).name())
	s.writeUser(w, r, u.Name)
}

func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.targetUser(w, r, false)
	if !ok {
		return
	}
	var req struct{ Password string }
	if !decode(w, r, &req) {
		return
	}
	var hash string
	var err error
	s.hashing(func() { hash, err = password.Hash(req.Password) })
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.dbError(w, "set password", s.db.SetPassword(r.Context(), u.Name, hash)) {
		return
	}
	s.log.Info("admin: password set", "login", u.Name, "by", principalFrom(r.Context()).name())
	s.writeUser(w, r, u.Name)
}

func (s *Server) writeUser(w http.ResponseWriter, r *http.Request, name string) {
	u, err := s.db.GetUser(r.Context(), name)
	if s.dbError(w, "user", err) {
		return
	}
	writeJSON(w, http.StatusOK, s.toAPIUser(u, 0))
}

// ---- operator: invites ----

type apiInvite struct {
	ID      int64      `json:"id"`
	Prefix  string     `json:"prefix"`
	Created time.Time  `json:"created"`
	Expires time.Time  `json:"expires"`
	UsedBy  string     `json:"usedBy,omitempty"`
	UsedAt  *time.Time `json:"usedAt,omitempty"`
	Revoked bool       `json:"revoked"`
	Usable  bool       `json:"usable"`
}

func toAPIInvite(i db.Invite, now time.Time) apiInvite {
	out := apiInvite{ID: i.ID, Prefix: i.Prefix, Created: i.CreatedAt, Expires: i.ExpiresAt, UsedBy: i.UsedBy, Revoked: i.Revoked, Usable: i.Usable(now)}
	if !i.UsedAt.IsZero() {
		t := i.UsedAt
		out.UsedAt = &t
	}
	return out
}

func (s *Server) listInvites(w http.ResponseWriter, r *http.Request) {
	list, err := s.db.ListInvites(r.Context())
	if err != nil {
		s.internal(w, "list invites", err)
		return
	}
	now := s.now()
	out := make([]apiInvite, 0, len(list))
	for _, i := range list {
		out = append(out, toAPIInvite(i, now))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	var req struct{ TTL string }
	if !decode(w, r, &req) {
		return
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl <= 0 || ttl > MaxInviteTTL {
		writeError(w, http.StatusBadRequest, "ttl must be a duration between 1s and 720h (30 days)")
		return
	}
	code, inv, err := s.db.CreateInvite(r.Context(), ttl)
	if s.dbError(w, "create invite", err) {
		return
	}
	s.log.Info("admin: invite created", "id", inv.ID, "by", principalFrom(r.Context()).name())
	writeJSON(w, http.StatusCreated, map[string]any{"code": code, "info": toAPIInvite(inv, s.now())})
}

func (s *Server) revokeInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || s.dbError(w, "revoke invite", s.db.RevokeInvite(r.Context(), id)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
