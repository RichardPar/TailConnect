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

func TestSharingAPI(t *testing.T) {
	f := newFx(t)
	acme := f.account("acme", db.RoleTenant)
	globex := f.account("globex", db.RoleTenant)
	initech := f.account("initech", db.RoleTenant)
	nas := f.machine("acme", "nas")
	f.machine("globex", "laptop")

	// Only the owner can share a machine.
	if code, _, _ := f.do(globex, "POST", fmt.Sprintf("/api/v1/nodes/%d/shares", nas), map[string]string{"recipient": "globex"}, nil); code != 404 {
		t.Fatalf("sharing someone else's machine: %d", code)
	}
	code, m, _ := f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/shares", nas), map[string]string{"recipient": "globex"}, nil)
	if code != 201 || m["status"] != "pending" || m["fqdn"] != "nas.acme.home.internal" {
		t.Fatalf("share: %d %v", code, m)
	}
	id := int(m["id"].(float64))
	if code, _, _ := f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/shares", nas), map[string]string{"recipient": "acme"}, nil); code != 400 {
		t.Fatalf("sharing with yourself: %d", code)
	}
	// The recipient sees it as incoming and pending (with a badge count).
	if _, m, _ := f.do(globex, "GET", "/api/v1/status", nil, nil); m["pendingShares"].(float64) != 1 {
		t.Fatalf("pending badge: %v", m["pendingShares"])
	}
	_, _, raw := f.do(globex, "GET", "/api/v1/shares", nil, nil)
	if !contains(raw, `"incoming":[{`) || !contains(raw, `"outgoing":[]`) {
		t.Fatalf("globex shares: %s", raw)
	}
	// Third parties can't accept or delete it.
	if code, _, _ := f.do(initech, "POST", fmt.Sprintf("/api/v1/shares/%d/accept", id), map[string]string{}, nil); code != 404 {
		t.Fatalf("accept by a third party: %d", code)
	}
	if code, _, _ := f.do(initech, "DELETE", fmt.Sprintf("/api/v1/shares/%d", id), nil, nil); code != 404 {
		t.Fatalf("delete by a third party: %d", code)
	}
	if code, m, _ := f.do(globex, "POST", fmt.Sprintf("/api/v1/shares/%d/accept", id), map[string]string{}, nil); code != 200 || m["inEffect"] != true {
		t.Fatalf("accept: %d %v", code, m)
	}
	// The owner revokes.
	if code, _, _ := f.do(acme, "DELETE", fmt.Sprintf("/api/v1/shares/%d", id), nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}

	// Links: create, redeem once.
	code, m, _ = f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/share-links", nas), map[string]string{"ttl": "1h"}, nil)
	if code != 201 {
		t.Fatalf("share link: %d %v", code, m)
	}
	link := m["code"].(string)
	if !strings.HasPrefix(link, db.ShareLinkPrefix) {
		t.Fatalf("link code %q", link)
	}
	if code, _, _ := f.do(acme, "POST", "/api/v1/shares/redeem", map[string]string{"code": link}, nil); code != 400 {
		t.Fatalf("owner redeeming: %d", code)
	}
	if code, m, _ := f.do(initech, "POST", "/api/v1/shares/redeem", map[string]string{"code": link}, nil); code != 200 || m["recipient"] != "initech" || m["inEffect"] != true {
		t.Fatalf("redeem: %d %v", code, m)
	}
	if code, _, _ := f.do(globex, "POST", "/api/v1/shares/redeem", map[string]string{"code": link}, nil); code != 400 {
		t.Fatalf("second redemption: %d", code)
	}
	// The recipient can leave a share.
	_, _, raw = f.do(initech, "GET", "/api/v1/shares", nil, nil)
	if !contains(raw, "nas.acme.home.internal") {
		t.Fatalf("initech shares: %s", raw)
	}
	shares, _ := f.db.ListShares(context.Background(), db.ShareFilter{})
	if code, _, _ := f.do(initech, "DELETE", fmt.Sprintf("/api/v1/shares/%d", shares[0].ID), nil, nil); code != 204 {
		t.Fatalf("leave: %d", code)
	}
}

func TestLifecycleAPI(t *testing.T) {
	f := newFx(t)
	f.srv.info.KeyExpiry = 180 * 24 * time.Hour
	acme := f.account("acme", db.RoleTenant)
	globex := f.account("globex", db.RoleTenant)

	// Require approval for new machines in acme.
	if code, m, _ := f.do(acme, "POST", "/api/v1/me/settings", map[string]bool{"requireMachineApproval": true}, nil); code != 200 || m["requireMachineApproval"] != true {
		t.Fatalf("settings: %d %v", code, m)
	}
	if _, m, _ := f.do(acme, "GET", "/api/v1/me/settings", nil, nil); m["requireMachineApproval"] != true {
		t.Fatalf("settings read back: %v", m)
	}
	id := f.machine("acme", "laptop")
	if _, m, _ := f.do(acme, "GET", "/api/v1/status", nil, nil); m["pendingMachines"].(float64) != 1 {
		t.Fatalf("pending machines badge: %v", m["pendingMachines"])
	}
	// Only acme (or an operator) can approve it.
	if code, _, _ := f.do(globex, "POST", fmt.Sprintf("/api/v1/nodes/%d/approve", id), map[string]string{}, nil); code != 404 {
		t.Fatalf("approve by another account: %d", code)
	}
	if code, m, _ := f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/approve", id), map[string]string{}, nil); code != 200 || m["approved"] != true {
		t.Fatalf("approve: %d %v", code, m)
	}
	// Expiry: never, then back to the default lifetime.
	if code, m, _ := f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/expiry", id), map[string]string{"expiry": "never"}, nil); code != 200 || m["keyExpiry"] != nil {
		t.Fatalf("expiry never: %d %v", code, m)
	}
	code, m, _ := f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/expiry", id), map[string]string{"expiry": "default"}, nil)
	if code != 200 || m["keyExpiry"] == nil {
		t.Fatalf("expiry default: %d %v", code, m)
	}
	exp, _ := time.Parse(time.RFC3339, m["keyExpiry"].(string))
	if d := time.Until(exp); d < 179*24*time.Hour || d > 181*24*time.Hour {
		t.Fatalf("default expiry %v away, want ~180 days", d)
	}
	if code, _, _ := f.do(globex, "POST", fmt.Sprintf("/api/v1/nodes/%d/expiry", id), map[string]string{"expiry": "never"}, nil); code != 404 {
		t.Fatalf("expiry by another account: %d", code)
	}
	// Pre-approved keys.
	if code, m, _ := f.do(acme, "POST", "/api/v1/keys", map[string]any{"ttl": "1h", "preapproved": true}, nil); code != 201 || m["info"].(map[string]any)["preapproved"] != true {
		t.Fatalf("pre-approved key: %d %v", code, m)
	}
}

func TestRulesAPI(t *testing.T) {
	f := newFx(t)
	acme := f.account("acme", db.RoleTenant)
	globex := f.account("globex", db.RoleTenant)
	id := f.machine("acme", "server")
	if code, m, _ := f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/tags", id), map[string]any{"tags": []string{"Web", "tag:db", "web"}}, nil); code != 200 || fmt.Sprint(m["tags"]) != "[db web]" {
		t.Fatalf("tags: %d %v", code, m)
	}
	if code, _, _ := f.do(acme, "POST", fmt.Sprintf("/api/v1/nodes/%d/tags", id), map[string]any{"tags": []string{"bad tag"}}, nil); code != 400 {
		t.Fatalf("bad tag: %d", code)
	}
	if code, _, _ := f.do(globex, "POST", fmt.Sprintf("/api/v1/nodes/%d/tags", id), map[string]any{"tags": []string{"x"}}, nil); code != 404 {
		t.Fatalf("tagging another account's machine: %d", code)
	}
	code, m, _ := f.do(acme, "POST", "/api/v1/rules", map[string]string{"src": "tag:staff", "dst": "tag:web", "ports": "tcp:443, 22"}, nil)
	if code != 201 || m["ports"] != "tcp:443,22" || m["user"] != "acme" {
		t.Fatalf("add rule: %d %v", code, m)
	}
	rid := int(m["id"].(float64))
	for _, bad := range []map[string]string{{"src": "tag:", "dst": "*"}, {"src": "*", "dst": "*", "ports": "99999"}} {
		if code, _, _ := f.do(acme, "POST", "/api/v1/rules", bad, nil); code != 400 {
			t.Errorf("bad rule %v: %d", bad, code)
		}
	}
	// Tenants see and edit only their own rules, even if they name another account.
	if _, _, raw := f.do(globex, "GET", "/api/v1/rules", nil, nil); contains(raw, "tag:staff") {
		t.Fatalf("globex sees acme's rules: %s", raw)
	}
	if code, m, _ := f.do(globex, "POST", "/api/v1/rules", map[string]string{"src": "*", "dst": "*", "user": "acme"}, nil); code != 201 || m["user"] != "globex" {
		t.Fatalf("tenant naming another account: %d %v", code, m)
	}
	if code, _, _ := f.do(globex, "DELETE", fmt.Sprintf("/api/v1/rules/%d", rid), nil, nil); code != 404 {
		t.Fatalf("deleting another account's rule: %d", code)
	}
	// Operators work on any account.
	f.login()
	if _, _, raw := f.do(f.c, "GET", "/api/v1/rules?user=acme", nil, nil); !contains(raw, "tag:staff") {
		t.Fatalf("operator listing acme's rules: %s", raw)
	}
	if code, _, _ := f.do(f.c, "POST", "/api/v1/rules", map[string]string{"src": "*", "dst": "*"}, nil); code != 400 {
		t.Fatalf("admin token without an account: %d", code)
	}
	if code, _, _ := f.do(acme, "DELETE", fmt.Sprintf("/api/v1/rules/%d", rid), nil, nil); code != 204 {
		t.Fatalf("delete own rule: %d", code)
	}
}

func TestExitNodeAPI(t *testing.T) {
	f := newFx(t)
	acme := f.account("acme", db.RoleTenant)
	globex := f.account("globex", db.RoleTenant)
	phone := f.machine("acme", "phone") // no OS reported
	u, _ := f.db.GetUser(context.Background(), "acme")
	k, _, _ := f.db.CreatePreAuthKey(context.Background(), db.CreatePreAuthKeyParams{UserID: u.ID, TTL: 3600e9})
	res, err := f.db.RegisterNode(context.Background(), db.RegisterParams{
		MachineKey: "m-gw", NodeKey: "n-gw", Hostname: "gw", Hostinfo: `{"OS":"linux"}`, AuthKey: k, Alloc: ipam.Default().Next,
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := res.Node.ID
	path := func(id int64) string { return fmt.Sprintf("/api/v1/nodes/%d/exit-node", id) }

	if code, m, _ := f.do(acme, "POST", path(gw), map[string]bool{"enabled": true}, nil); code != 200 || m["exitNode"] != true {
		t.Fatalf("enable on Linux: %d %v", code, m)
	}
	if code, m, _ := f.do(acme, "POST", path(phone), map[string]bool{"enabled": true}, nil); code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "only Linux") {
		t.Fatalf("enable on a non-Linux machine: %d %v", code, m)
	}
	if code, _, _ := f.do(globex, "POST", path(gw), map[string]bool{"enabled": false}, nil); code != 404 {
		t.Fatalf("another account's machine: %d", code)
	}
	if code, m, _ := f.do(acme, "POST", path(gw), map[string]bool{"enabled": false}, nil); code != 200 || m["exitNode"] != false {
		t.Fatalf("disable: %d %v", code, m)
	}
}
