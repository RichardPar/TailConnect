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
// previous token and invalidating existing sessions) and returns the token.
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

// authState is loaded per request so a token reset via the CLI takes effect
// immediately, even while the server is running.
type authState struct {
	tokenHash string // "" = no token configured; all logins fail
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

// Session cookies are "<expiry-unix>.<hmac>". The MAC covers the current
// token hash, so resetting the token logs out every session.
func (st authState) mac(expiry int64) string {
	m := hmac.New(sha256.New, st.secret)
	fmt.Fprintf(m, "v1|%d|%s", expiry, st.tokenHash)
	return hex.EncodeToString(m.Sum(nil))
}

func (st authState) newSession(now time.Time) (value string, expires time.Time) {
	expires = now.Add(sessionTTL)
	exp := expires.Unix()
	return strconv.FormatInt(exp, 10) + "." + st.mac(exp), expires
}

func (st authState) checkSession(value string, now time.Time) bool {
	if st.tokenHash == "" {
		return false
	}
	expStr, sig, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || now.Unix() >= exp {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(st.mac(exp)))
}
