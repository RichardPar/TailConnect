package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/ipam"
)

type fx struct {
	t     *testing.T
	db    *db.DB
	srv   *Server
	ts    *httptest.Server
	token string
	c     *http.Client // cookie-holding browser-like client
}

func newFx(t *testing.T) *fx {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	tok, err := ResetToken(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	s := New(d, Info{BaseDomain: "home.internal"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.authLimit = newLimiter(time.Millisecond, 1000) // tests sign in a lot; TestLoginFailures checks the real limit
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return &fx{t: t, db: d, srv: s, ts: ts, token: tok, c: &http.Client{Jar: jar}}
}

func (f *fx) do(c *http.Client, method, path string, body any, hdr map[string]string) (int, map[string]any, []byte) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.ts.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, raw
}

func (f *fx) login() {
	f.t.Helper()
	if code, m, _ := f.do(f.c, "POST", "/api/login", map[string]string{"Token": f.token}, nil); code != 200 {
		f.t.Fatalf("login: %d %v", code, m)
	}
}

func TestUIServed(t *testing.T) {
	f := newFx(t)
	code, _, raw := f.do(http.DefaultClient, "GET", "/", nil, nil)
	if code != 200 || !strings.Contains(string(raw), "TailConnect") {
		t.Fatalf("index: %d", code)
	}
	if code, _, _ := f.do(http.DefaultClient, "GET", "/app.js", nil, nil); code != 200 {
		t.Fatalf("app.js: %d", code)
	}
}

func TestAuthRequired(t *testing.T) {
	f := newFx(t)
	if code, _, _ := f.do(f.c, "GET", "/api/v1/nodes", nil, nil); code != 401 {
		t.Fatalf("unauthenticated: %d", code)
	}
	if code, _, _ := f.do(f.c, "POST", "/api/login", map[string]string{"Token": "tc-admin-wrong"}, nil); code != 401 {
		t.Fatalf("bad token login: %d", code)
	}
	f.login()
	if code, _, _ := f.do(f.c, "GET", "/api/v1/nodes", nil, nil); code != 200 {
		t.Fatalf("after login: %d", code)
	}
	// Bearer token works without a cookie.
	if code, _, _ := f.do(http.DefaultClient, "GET", "/api/v1/status", nil, map[string]string{"Authorization": "Bearer " + f.token}); code != 200 {
		t.Fatalf("bearer: %d", code)
	}
	// Resetting the token invalidates existing sessions.
	if _, err := ResetToken(context.Background(), f.db); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.do(f.c, "GET", "/api/v1/nodes", nil, nil); code != 401 {
		t.Fatalf("session survived token reset: %d", code)
	}
}

func TestSessionExpiry(t *testing.T) {
	f := newFx(t)
	f.login()
	f.srv.now = func() time.Time { return time.Now().Add(sessionTTL + time.Minute) }
	if code, _, _ := f.do(f.c, "GET", "/api/v1/nodes", nil, nil); code != 401 {
		t.Fatalf("expired session accepted: %d", code)
	}
}

func TestCSRFDefences(t *testing.T) {
	f := newFx(t)
	f.login()
	// Non-JSON mutation (what a cross-site HTML form would send) is rejected.
	req, _ := http.NewRequest("POST", f.ts.URL+"/api/v1/users", strings.NewReader("name=evil"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("form post: %d", resp.StatusCode)
	}
	// Foreign Origin is rejected.
	if code, _, _ := f.do(f.c, "POST", "/api/v1/users", map[string]string{"name": "evil"}, map[string]string{"Origin": "https://evil.example"}); code != 403 {
		t.Fatalf("cross-origin: %d", code)
	}
}

func TestCRUD(t *testing.T) {
	f := newFx(t)
	f.login()
	if code, _, _ := f.do(f.c, "POST", "/api/v1/users", map[string]string{"name": "alice"}, nil); code != 201 {
		t.Fatalf("create user: %d", code)
	}
	if code, _, _ := f.do(f.c, "POST", "/api/v1/users", map[string]string{"name": "alice"}, nil); code != 409 {
		t.Fatalf("dup user: %d", code)
	}
	if code, _, _ := f.do(f.c, "POST", "/api/v1/users", map[string]string{"name": "Bad Name"}, nil); code != 400 {
		t.Fatalf("invalid user: %d", code)
	}
	if code, _, _ := f.do(f.c, "POST", "/api/v1/keys", map[string]any{"user": "alice", "ttl": "9999h"}, nil); code != 400 {
		t.Fatalf("ttl too long: %d", code)
	}
	code, m, _ := f.do(f.c, "POST", "/api/v1/keys", map[string]any{"user": "alice", "ttl": "1h", "reusable": true}, nil)
	if code != 201 {
		t.Fatalf("create key: %d %v", code, m)
	}
	secret := m["key"].(string)
	if !strings.HasPrefix(secret, db.AuthKeyPrefix) {
		t.Fatalf("key = %q", secret)
	}

	// Register a node directly through the store, then manage it via the API.
	res, err := f.db.RegisterNode(context.Background(), db.RegisterParams{
		MachineKey: "m1", NodeKey: "n1", Hostname: "laptop", AuthKey: secret, Alloc: ipam.Default().Next,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = f.db.UpdateNodeStatus(context.Background(), res.Node.ID, db.NodeStatus{})

	_, _, raw := f.do(f.c, "GET", "/api/v1/nodes", nil, nil)
	var nodes []apiNode
	if err := json.Unmarshal(raw, &nodes); err != nil || len(nodes) != 1 {
		t.Fatalf("nodes: %s", raw)
	}
	if nodes[0].FQDN != "laptop.alice.home.internal" || !nodes[0].Online {
		t.Fatalf("node: %+v", nodes[0])
	}
	id := nodes[0].ID
	if code, _, _ := f.do(f.c, "POST", "/api/v1/nodes/"+itoa(id)+"/rename", map[string]string{"name": "work"}, nil); code != 200 {
		t.Fatalf("rename: %d", code)
	}
	if code, _, _ := f.do(f.c, "DELETE", "/api/v1/nodes/"+itoa(id), nil, nil); code != 204 {
		t.Fatalf("delete node: %d", code)
	}
	if code, _, _ := f.do(f.c, "DELETE", "/api/v1/nodes/"+itoa(id), nil, nil); code != 404 {
		t.Fatalf("delete node again: %d", code)
	}

	_, _, raw = f.do(f.c, "GET", "/api/v1/keys", nil, nil)
	var keys []apiKey
	json.Unmarshal(raw, &keys)
	if len(keys) != 1 || keys[0].Uses != 1 || !keys[0].Usable {
		t.Fatalf("keys: %s", raw)
	}
	if code, _, _ := f.do(f.c, "DELETE", "/api/v1/keys/"+itoa(keys[0].ID), nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _, _ := f.do(f.c, "DELETE", "/api/v1/users/alice", nil, nil); code != 204 {
		t.Fatalf("delete user: %d", code)
	}
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }
