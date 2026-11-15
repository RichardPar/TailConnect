package db

import (
	"errors"
	"testing"
	"time"
)

func TestAccounts(t *testing.T) {
	d := open(t)
	u, err := d.CreateAccount(ctx, NewAccount{Name: "acme", PasswordHash: "h1", Status: StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	if u.Active() || u.Operator() || !u.HasPassword() {
		t.Fatalf("new account: %+v", u)
	}
	for _, bad := range []string{"Acme", "a.b", "a_b", "-a", "a-", "", "this-name-is-far-too-long-for-a-tenant"} {
		if _, err := d.CreateAccount(ctx, NewAccount{Name: bad}); !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q: got %v, want ErrInvalid", bad, err)
		}
	}

	// Status/role/password changes bump the session epoch.
	epoch := u.SessionEpoch
	steps := []func() error{
		func() error { return d.SetUserStatus(ctx, "acme", StatusActive) },
		func() error { return d.SetUserRole(ctx, "acme", RoleOperator) },
		func() error { return d.SetPassword(ctx, "acme", "h2") },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
		got, _ := d.GetUser(ctx, "acme")
		if got.SessionEpoch <= epoch {
			t.Fatalf("step %d: epoch not bumped", i)
		}
		epoch = got.SessionEpoch
	}
	got, _ := d.GetUserByID(ctx, u.ID)
	if !got.Active() || !got.Operator() || got.PasswordHash != "h2" {
		t.Fatalf("after updates: %+v", got)
	}
	if err := d.SetUserStatus(ctx, "acme", "bogus"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bogus status: %v", err)
	}
	if err := d.SetUserRole(ctx, "nobody", RoleTenant); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestInvites(t *testing.T) {
	d := open(t)
	code, inv, err := d.CreateInvite(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !inv.Usable(time.Now()) {
		t.Fatal("new invite not usable")
	}
	if _, err := d.CreateAccount(ctx, NewAccount{Name: "a", Invite: "tc-invite-nope"}); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("bad invite: %v", err)
	}
	if _, err := d.GetUser(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("account created despite a bad invite")
	}
	if _, err := d.CreateAccount(ctx, NewAccount{Name: "a", Invite: code}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccount(ctx, NewAccount{Name: "b", Invite: code}); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("reused invite: %v", err)
	}
	list, _ := d.ListInvites(ctx)
	if len(list) != 1 || list[0].UsedBy != "a" || list[0].Usable(time.Now()) {
		t.Fatalf("invites: %+v", list)
	}
	code2, inv2, _ := d.CreateInvite(ctx, time.Hour)
	if err := d.RevokeInvite(ctx, inv2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAccount(ctx, NewAccount{Name: "c", Invite: code2}); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("revoked invite: %v", err)
	}
	code3, _, _ := d.CreateInvite(ctx, time.Hour)
	d.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := d.CreateAccount(ctx, NewAccount{Name: "c", Invite: code3}); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("expired invite: %v", err)
	}
}

func TestInactiveAccountsCannotJoin(t *testing.T) {
	d := open(t)
	u := mustUser(t, d, "acme")
	k := mustKey(t, d, u.ID, true)
	if _, err := reg(d, "m1", "n1", "laptop", k); err != nil {
		t.Fatal(err)
	}
	g0, _ := d.Generation(ctx)
	if err := d.SetUserStatus(ctx, "acme", StatusSuspended); err != nil {
		t.Fatal(err)
	}
	if g1, _ := d.Generation(ctx); g1 <= g0 {
		t.Fatal("suspension must bump the map generation")
	}
	if _, err := reg(d, "m2", "n2", "desktop", k); !errors.Is(err, ErrAccountInactive) {
		t.Fatalf("new machine of suspended account: %v", err)
	}
	if _, err := reg(d, "m1", "n1", "laptop", ""); !errors.Is(err, ErrAccountInactive) {
		t.Fatalf("known machine of suspended account: %v", err)
	}
	n, err := d.GetNodeByNodeKey(ctx, "n1")
	if err != nil || n.UserStatus != StatusSuspended {
		t.Fatalf("node user status: %+v %v", n, err)
	}
	if err := d.SetUserStatus(ctx, "acme", StatusActive); err != nil {
		t.Fatal(err)
	}
	if _, err := reg(d, "m1", "n1", "laptop", ""); err != nil {
		t.Fatalf("after reactivation: %v", err)
	}
}

func TestRevokeOwnKeyOnly(t *testing.T) {
	d := open(t)
	a, b := mustUser(t, d, "a"), mustUser(t, d, "b")
	mustKey(t, d, a.ID, false)
	keys, _ := d.ListPreAuthKeys(ctx, a.ID)
	if err := d.RevokeUserPreAuthKey(ctx, keys[0].ID, b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking another user's key: %v", err)
	}
	if err := d.RevokeUserPreAuthKey(ctx, keys[0].ID, a.ID); err != nil {
		t.Fatal(err)
	}
}
