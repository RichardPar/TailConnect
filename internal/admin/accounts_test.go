package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/ipam"
	"tailconnect/internal/password"
)

const pw = "correct horse battery"

func (f *fx) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

// account creates an active account with a password and returns a signed-in client.
func (f *fx) account(name, role string) *http.Client {
	f.t.Helper()
	h, err := password.Hash(pw)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.db.CreateAccount(context.Background(), db.NewAccount{Name: name, PasswordHash: h, Role: role}); err != nil {
		f.t.Fatal(err)
	}
	c := f.browser()
	if code, m, _ := f.do(c, "POST", "/api/login", map[string]string{"login": name, "password": pw}, nil); code != 200 {
		f.t.Fatalf("login %s: %d %v", name, code, m)
	}
	return c
}

// machine registers a node for user name directly in the store.
func (f *fx) machine(name, host string) int64 {
	f.t.Helper()
	u, err := f.db.GetUser(context.Background(), name)
	if err != nil {
		f.t.Fatal(err)
	}
	k, _, err := f.db.CreatePreAuthKey(context.Background(), db.CreatePreAuthKeyParams{UserID: u.ID, TTL: 3600e9})
	if err != nil {
		f.t.Fatal(err)
	}
	res, err := f.db.RegisterNode(context.Background(), db.RegisterParams{
		MachineKey: "m-" + host, NodeKey: "n-" + host, Hostname: host, AuthKey: k, Alloc: ipam.Default().Next,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return res.Node.ID
}

func TestSignupModes(t *testing.T) {
	f := newFx(t)
	signup := func(login, invite string) (int, map[string]any) {
		code, m, _ := f.do(f.browser(), "POST", "/api/signup", map[string]string{"login": login, "password": pw, "invite": invite}, nil)
		return code, m
	}
	login := func(name string) int {
		code, _, _ := f.do(f.browser(), "POST", "/api/login", map[string]string{"login": name, "password": pw}, nil)
		return code
	}

	// Off (the default when unset).
	if code, _ := signup("acme", ""); code != 403 {
		t.Fatalf("signup while off: %d", code)
	}

	// Approval: account is pending and can't sign in until approved.
	f.srv.info.Signup = SignupApproval
	if code, m := signup("acme", ""); code != 201 || m["status"] != db.StatusPending {
		t.Fatalf("approval signup: %d %v", code, m)
	}
	if code := login("acme"); code != 403 {
		t.Fatalf("pending login: %d", code)
	}
	if code, _ := signup("acme", ""); code != 409 {
		t.Fatalf("duplicate name: %d", code)
	}
	if code, _ := signup("Not Valid", ""); code != 400 {
		t.Fatalf("bad name: %d", code)
	}
	if code, _, _ := f.do(f.browser(), "POST", "/api/signup", map[string]string{"login": "short", "password": "x"}, nil); code != 400 {
		t.Fatalf("weak password: %d", code)
	}
	f.login()
	if code, m, _ := f.do(f.c, "POST", "/api/v1/users/acme/status", map[string]string{"status": "active"}, nil); code != 200 || m["status"] != "active" {
		t.Fatalf("approve: %d %v", code, m)
	}
	if code := login("acme"); code != 200 {
		t.Fatalf("login after approval: %d", code)
	}

	// Invite: a code is required, single use; it also skips approval.
	f.srv.info.Signup = SignupInvite
	if code, _ := signup("globex", ""); code != 400 {
		t.Fatalf("invite mode without code: %d", code)
	}
	code, m, _ := f.do(f.c, "POST", "/api/v1/invites", map[string]string{"ttl": "1h"}, nil)
	if code != 201 {
		t.Fatalf("create invite: %d %v", code, m)
	}
	inv := m["code"].(string)
	if code, m := signup("globex", inv); code != 201 || m["status"] != db.StatusActive {
		t.Fatalf("invite signup: %d %v", code, m)
	}
	if code, _ := signup("initech", inv); code != 400 {
		t.Fatalf("reused invite: %d", code)
	}

	// Open: straight in.
	f.srv.info.Signup = SignupOpen
	if code, m := signup("initech", ""); code != 201 || m["status"] != db.StatusActive {
		t.Fatalf("open signup: %d %v", code, m)
	}
	if code := login("initech"); code != 200 {
		t.Fatalf("login after open signup: %d", code)
	}
}

func TestLoginFailures(t *testing.T) {
	f := newFx(t)
	f.srv.authLimit = newLimiter(6*time.Second, 10) // the production limit
	f.account("acme", db.RoleTenant)
	if code, _, _ := f.do(f.browser(), "POST", "/api/login", map[string]string{"login": "acme", "password": "wrong password"}, nil); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	if code, _, _ := f.do(f.browser(), "POST", "/api/login", map[string]string{"login": "nobody", "password": pw}, nil); code != 401 {
		t.Fatalf("unknown account: %d", code)
	}
	// An account without a password (created by the CLI) can't sign in.
	f.db.CreateUser(context.Background(), "nopass")
	if code, _, _ := f.do(f.browser(), "POST", "/api/login", map[string]string{"login": "nopass", "password": ""}, nil); code != 401 {
		t.Fatalf("passwordless account: %d", code)
	}
	// The burst allowance runs out: further attempts are throttled.
	throttled := false
	for i := 0; i < 15 && !throttled; i++ {
		code, _, _ := f.do(f.browser(), "POST", "/api/login", map[string]string{"login": "acme", "password": "wrong password"}, nil)
		throttled = code == 429
	}
	if !throttled {
		t.Fatal("no rate limit on failed logins")
	}
}

func TestTenantScope(t *testing.T) {
	f := newFx(t)
	acme := f.account("acme", db.RoleTenant)
	f.account("globex", db.RoleTenant)
	mine := f.machine("acme", "laptop")
	theirs := f.machine("globex", "server")

	code, _, raw := f.do(acme, "GET", "/api/v1/nodes", nil, nil)
	if code != 200 || !contains(raw, "laptop") || contains(raw, "server") {
		t.Fatalf("tenant node list: %d %s", code, raw)
	}
	if code, m, _ := f.do(acme, "GET", "/api/v1/status", nil, nil); code != 200 || m["nodes"].(float64) != 1 || m["users"] != nil {
		t.Fatalf("tenant status: %d %v", code, m)
	}
	if code, m, _ := f.do(acme, "GET", "/api/v1/me", nil, nil); m["login"] != "acme" || m["operator"] != false {
		t.Fatalf("me: %d %v", code, m)
	}
	// Other tenants' machines look like they don't exist.
	if code, _, _ := f.do(acme, "DELETE", fmt.Sprintf("/api/v1/nodes/%d", theirs), nil, nil); code != 404 {
		t.Fatalf("delete other tenant's node: %d", code)
	}
	if code, _, _ := f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/rename", theirs), map[string]string{"name": "pwned"}, nil); code != 404 {
		t.Fatalf("rename other tenant's node: %d", code)
	}
	if code, _, _ := f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/rename", mine), map[string]string{"name": "desk"}, nil); code != 200 {
		t.Fatalf("rename own node: %d", code)
	}
	// Keys: own only. Creating one needs no user name.
	if code, _, _ := f.do(acme, "POST", "/api/v1/keys", map[string]any{"ttl": "1h"}, nil); code != 201 {
		t.Fatalf("create own key: %d", code)
	}
	if code, _, _ := f.do(acme, "POST", "/api/v1/keys", map[string]any{"user": "globex", "ttl": "1h"}, nil); code != 403 {
		t.Fatalf("create key for another tenant: %d", code)
	}
	gk, _ := f.db.ListPreAuthKeys(context.Background(), 0)
	var globexKey int64
	for _, k := range gk {
		if k.UserName == "globex" {
			globexKey = k.ID
		}
	}
	if code, _, _ := f.do(acme, "DELETE", fmt.Sprintf("/api/v1/keys/%d", globexKey), nil, nil); code != 404 {
		t.Fatalf("revoke another tenant's key: %d", code)
	}
	if code, _, raw := f.do(acme, "GET", "/api/v1/keys", nil, nil); code != 200 || contains(raw, "globex") {
		t.Fatalf("tenant key list: %s", raw)
	}
	// Operator endpoints are off limits.
	for _, ep := range [][2]string{{"GET", "/api/v1/users"}, {"POST", "/api/v1/users"}, {"GET", "/api/v1/invites"}, {"POST", "/api/v1/users/globex/status"}} {
		if code, _, _ := f.do(acme, ep[0], ep[1], map[string]string{"name": "x", "status": "suspended"}, nil); code != 403 {
			t.Errorf("tenant %s %s: %d", ep[0], ep[1], code)
		}
	}
	// An operator account sees everything.
	boss := f.account("boss", db.RoleOperator)
	if code, _, raw := f.do(boss, "GET", "/api/v1/nodes", nil, nil); code != 200 || !contains(raw, "server") || !contains(raw, "desk") {
		t.Fatalf("operator node list: %s", raw)
	}
	// ...but can't lock itself out.
	if code, _, _ := f.do(boss, "POST", "/api/v1/users/boss/status", map[string]string{"status": "suspended"}, nil); code != 400 {
		t.Fatalf("operator suspending itself: %d", code)
	}
	if code, _, _ := f.do(boss, "DELETE", "/api/v1/users/boss", nil, nil); code != 400 {
		t.Fatalf("operator deleting itself: %d", code)
	}
}

func TestSessionsEndOnAccountChanges(t *testing.T) {
	f := newFx(t)
	a1 := f.account("acme", db.RoleTenant)
	a2 := f.browser()
	f.do(a2, "POST", "/api/login", map[string]string{"login": "acme", "password": pw}, nil)
	ok := func(c *http.Client) bool {
		code, _, _ := f.do(c, "GET", "/api/v1/me", nil, nil)
		return code == 200
	}
	if !ok(a1) || !ok(a2) {
		t.Fatal("sessions not working")
	}
	// Changing the password keeps this session, ends the others.
	if code, m, _ := f.do(a1, "POST", "/api/v1/me/password", map[string]string{"current": "nope nope nope", "new": "another long password"}, nil); code != 403 {
		t.Fatalf("wrong current password: %d %v", code, m)
	}
	if code, m, _ := f.do(a1, "POST", "/api/v1/me/password", map[string]string{"current": pw, "new": "another long password"}, nil); code != 200 {
		t.Fatalf("change password: %d %v", code, m)
	}
	if !ok(a1) || ok(a2) {
		t.Fatalf("after password change: this=%v other=%v (want true, false)", ok(a1), ok(a2))
	}
	// Suspension ends every session immediately.
	f.login()
	if code, _, _ := f.do(f.c, "POST", "/api/v1/users/acme/status", map[string]string{"status": "suspended"}, nil); code != 200 {
		t.Fatalf("suspend: %d", code)
	}
	if ok(a1) {
		t.Fatal("suspended account still signed in")
	}
	if code, _, _ := f.do(f.browser(), "POST", "/api/login", map[string]string{"login": "acme", "password": "another long password"}, nil); code != 403 {
		t.Fatalf("suspended login: %d", code)
	}
	// Operators can reset a tenant's password.
	f.do(f.c, "POST", "/api/v1/users/acme/status", map[string]string{"status": "active"}, nil)
	if code, _, _ := f.do(f.c, "POST", "/api/v1/users/acme/password", map[string]string{"password": "reset by the operator"}, nil); code != 200 {
		t.Fatalf("operator password reset: %d", code)
	}
	if code, _, _ := f.do(f.browser(), "POST", "/api/login", map[string]string{"login": "acme", "password": "reset by the operator"}, nil); code != 200 {
		t.Fatalf("login with reset password: %d", code)
	}
}

func contains(b []byte, sub string) bool { return strings.Contains(string(b), sub) }
