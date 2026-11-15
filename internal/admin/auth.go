package admin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tailconnect/internal/db"
)

// TokenPrefix starts every admin token.
const TokenPrefix = "tc-admin-"

const (
	settingTokenHash     = "admin.token_hash"
	settingSessionSecret = "admin.session_secret"
	sessionCookie        = "tc_admin"
	sessionTTL           = 12 * time.Hour
)

// ResetToken generates a new admin token, stores its hash (replacing any
// previous token and invalidating token sessions) and returns the token.
// The admin token is the operator's break-glass credential and API token.
func ResetToken(ctx context.Context, d *db.DB) (string, error) {
	tok := TokenPrefix + randHex(24)
	if err := d.SetSetting(ctx, settingTokenHash, hashToken(tok)); err != nil {
		return "", err
	}
	return tok, nil
}

// HasToken reports whether an admin token has been configured.
func HasToken(ctx context.Context, d *db.DB) (bool, error) {
	_, err := d.GetSetting(ctx, settingTokenHash)
	if errors.Is(err, db.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("admin: crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// principal is who a request acts as: the admin token (user == nil), or an
// account. Operators see and manage everything; tenants only their own.
type principal struct {
	user *db.User
}

func (p principal) operator() bool { return p.user == nil || p.user.Operator() }

// scope is the user ID whose data the principal may see (0 = everyone).
func (p principal) scope() int64 {
	if p.operator() {
		return 0
	}
	return p.user.ID
}

func (p principal) name() string {
	if p.user == nil {
		return "admin-token"
	}
	return p.user.Name
}

type ctxKey struct{}

func principalFrom(ctx context.Context) principal {
	p, _ := ctx.Value(ctxKey{}).(principal)
	return p
}

// authState is loaded per request so changes made via the CLI (token reset,
// suspension, password change) take effect immediately.
type authState struct {
	tokenHash string // "" = no token configured
	secret    []byte
}

func (s *Server) loadAuth(ctx context.Context) (authState, error) {
	var st authState
	th, err := s.db.GetSetting(ctx, settingTokenHash)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return st, err
	}
	st.tokenHash = th
	sec, err := s.db.SetSettingIfAbsent(ctx, settingSessionSecret, randHex(32))
	if err != nil {
		return st, err
	}
	st.secret, err = hex.DecodeString(sec)
	return st, err
}

func (st authState) checkToken(tok string) bool {
	if st.tokenHash == "" || !strings.HasPrefix(tok, TokenPrefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashToken(tok)), []byte(st.tokenHash)) == 1
}

// Session cookies are "<subject>.<expiry-unix>.<hmac>", where subject is
// "t" (admin token) or "u<id>-<epoch>" (an account). The MAC covers the
// token hash for token sessions, so resetting the token logs them out; an
// account's sessions end when its session epoch changes (password change,
// suspension, role change).
func (st authState) mac(subject string, expiry int64) string {
	m := hmac.New(sha256.New, st.secret)
	fmt.Fprintf(m, "v2|%s|%d", subject, expiry)
	if subject == "t" {
		fmt.Fprintf(m, "|%s", st.tokenHash)
	}
	return hex.EncodeToString(m.Sum(nil))
}

func (st authState) newSession(subject string, now time.Time) (value string, expires time.Time) {
	expires = now.Add(sessionTTL)
	exp := expires.Unix()
	return subject + "." + strconv.FormatInt(exp, 10) + "." + st.mac(subject, exp), expires
}

func tokenSubject() string         { return "t" }
func userSubject(u db.User) string { return fmt.Sprintf("u%d-%d", u.ID, u.SessionEpoch) }

// checkSession validates a cookie and returns its subject.
func (st authState) checkSession(value string, now time.Time) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || now.Unix() >= exp {
		return "", false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(st.mac(parts[0], exp))) {
		return "", false
	}
	if parts[0] == "t" && st.tokenHash == "" {
		return "", false
	}
	return parts[0], true
}

// resolve turns a session subject into a principal, re-checking the account.
func (s *Server) resolve(ctx context.Context, subject string) (principal, bool) {
	if subject == "t" {
		return principal{}, true
	}
	var id, epoch int64
	if _, err := fmt.Sscanf(subject, "u%d-%d", &id, &epoch); err != nil {
		return principal{}, false
	}
	u, err := s.db.GetUserByID(ctx, id)
	if err != nil || u.SessionEpoch != epoch || !u.Active() || !u.HasPassword() {
		return principal{}, false
	}
	return principal{user: &u}, true
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, st authState, subject string) {
	val, exp := st.newSession(subject, s.now())
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: val, Path: "/", Expires: exp,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}
