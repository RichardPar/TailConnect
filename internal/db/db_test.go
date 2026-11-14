package db

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"tailconnect/internal/ipam"
)

func open(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

var ctx = context.Background()

func mustUser(t *testing.T, d *DB, name string) User {
	t.Helper()
	u, err := d.CreateUser(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustKey(t *testing.T, d *DB, uid int64, reusable bool) string {
	t.Helper()
	s, _, err := d.CreatePreAuthKey(ctx, CreatePreAuthKeyParams{UserID: uid, Reusable: reusable, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func reg(d *DB, machine, node, host, authKey string) (RegisterResult, error) {
	return d.RegisterNode(ctx, RegisterParams{
		MachineKey: machine, NodeKey: node, DiscoKey: "disco-" + node, Hostname: host,
		AuthKey: authKey, Alloc: ipam.Default().Next,
	})
}

func TestReopenKeepsSchema(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.db")
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	mustUser(t, d, "alice")
	d.Close()
	d, err = Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.GetUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
}

func TestUsers(t *testing.T) {
	d := open(t)
	mustUser(t, d, "alice")
	if _, err := d.CreateUser(ctx, "alice"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate user: got %v", err)
	}
	if _, err := d.CreateUser(ctx, "Bad Name"); err == nil {
		t.Fatal("expected invalid name error")
	}
	if err := d.DeleteUser(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: got %v", err)
	}
}

func TestSingleUseKey(t *testing.T) {
	d := open(t)
	u := mustUser(t, d, "alice")
	k := mustKey(t, d, u.ID, false)

	r, err := reg(d, "m1", "n1", "Laptop.local", k)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Created || r.Node.IPv4.String() != "100.64.0.1" || r.Node.GivenName != "laptop" || r.Node.UserName != "alice" {
		t.Fatalf("unexpected node: %+v", r)
	}
	if _, err := reg(d, "m2", "n2", "phone", k); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("reused single-use key: got %v", err)
	}
	// The failed attempt must not have consumed an address or created a node.
	nodes, _ := d.ListNodes(ctx, 0)
	if len(nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(nodes))
	}
}

func TestReusableKeyAndNameDedupe(t *testing.T) {
	d := open(t)
	u := mustUser(t, d, "alice")
	k := mustKey(t, d, u.ID, true)
	var names []string
	for i, m := range []string{"m1", "m2", "m3"} {
		r, err := reg(d, m, "n"+m, "box", k)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, r.Node.GivenName)
		if want := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)}); r.Node.IPv4 != want {
			t.Fatalf("ip %s want %s", r.Node.IPv4, want)
		}
	}
	if names[0] != "box" || names[1] != "box-2" || names[2] != "box-3" {
		t.Fatalf("names = %v", names)
	}
}

func TestExpiredAndRevokedKeys(t *testing.T) {
	d := open(t)
	u := mustUser(t, d, "alice")
	base := time.Now()
	d.SetClock(func() time.Time { return base })
	k := mustKey(t, d, u.ID, true)

	d.SetClock(func() time.Time { return base.Add(2 * time.Hour) })
	if _, err := reg(d, "m1", "n1", "a", k); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("expired key: got %v", err)
	}

	d.SetClock(time.Now)
	k2 := mustKey(t, d, u.ID, true)
	keys, _ := d.ListPreAuthKeys(ctx, u.ID)
	if err := d.RevokePreAuthKey(ctx, keys[len(keys)-1].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reg(d, "m1", "n1", "a", k2); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("revoked key: got %v", err)
	}
	if _, err := reg(d, "m1", "n1", "a", "tc-auth-bogus"); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("unknown key: got %v", err)
	}
}

func TestReRegisterAndRotate(t *testing.T) {
	d := open(t)
	u := mustUser(t, d, "alice")
	k := mustKey(t, d, u.ID, false)
	first, err := reg(d, "m1", "n1", "laptop", k)
	if err != nil {
		t.Fatal(err)
	}
	// Same machine + node key: no auth key needed, nothing changes.
	again, err := reg(d, "m1", "n1", "laptop", "")
	if err != nil {
		t.Fatal(err)
	}
	if again.Created || again.Rotated || again.Node.ID != first.Node.ID {
		t.Fatalf("re-register: %+v", again)
	}
	// A known (machine-authenticated) machine may rotate its node key without an auth key.
	rot, err := reg(d, "m1", "n1b", "laptop", "")
	if err != nil {
		t.Fatal(err)
	}
	if !rot.Rotated || rot.Node.ID != first.Node.ID || rot.Node.IPv4 != first.Node.IPv4 || rot.Node.NodeKey != "n1b" {
		t.Fatalf("rotate: %+v", rot)
	}
	// Rotating with an auth key moves the node to that key's user; a bad key fails.
	if _, err := reg(d, "m1", "n1c", "laptop", "tc-auth-bogus"); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("rotate with bad key: got %v", err)
	}
	bob := mustUser(t, d, "bob")
	moved, err := reg(d, "m1", "n1c", "laptop", mustKey(t, d, bob.ID, false))
	if err != nil {
		t.Fatal(err)
	}
	if moved.Node.UserName != "bob" || moved.Node.IPv4 != first.Node.IPv4 {
		t.Fatalf("move: %+v", moved.Node)
	}
}

func TestGeneration(t *testing.T) {
	d := open(t)
	g := func() int64 {
		v, err := d.Generation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	g0 := g()
	u := mustUser(t, d, "alice")
	k := mustKey(t, d, u.ID, true)
	if g() != g0 {
		t.Fatal("creating a user/key should not bump the generation")
	}
	r, _ := reg(d, "m1", "n1", "a", k)
	g1 := g()
	if g1 <= g0 {
		t.Fatal("node insert did not bump generation")
	}
	if err := d.TouchNode(ctx, r.Node.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateNodeStatus(ctx, r.Node.ID, r.Node.DiscoKey, nil, ""); err != nil {
		t.Fatal(err)
	}
	if g() != g1 {
		t.Fatal("last_seen / unchanged status should not bump generation")
	}
	ep := []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:41641")}
	d.UpdateNodeStatus(ctx, r.Node.ID, r.Node.DiscoKey, ep, "")
	g2 := g()
	if g2 <= g1 {
		t.Fatal("endpoint change did not bump generation")
	}
	d.DeleteUser(ctx, "alice")
	if g() <= g2 {
		t.Fatal("user delete did not bump generation")
	}
}

func TestStatusRenameDelete(t *testing.T) {
	d := open(t)
	u := mustUser(t, d, "alice")
	k := mustKey(t, d, u.ID, true)
	a, _ := reg(d, "m1", "n1", "a", k)
	b, _ := reg(d, "m2", "n2", "b", k)

	ep := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41641")}
	if err := d.UpdateNodeStatus(ctx, a.Node.ID, "disco-new", ep, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := d.GetNodeByNodeKey(ctx, "n1")
	if got.DiscoKey != "disco-new" || len(got.Endpoints) != 1 || got.Endpoints[0] != ep[0] {
		t.Fatalf("status not stored: %+v", got)
	}

	if err := d.RenameNode(ctx, a.Node.ID, "b"); !errors.Is(err, ErrExists) {
		t.Fatalf("rename collision: got %v", err)
	}
	if err := d.RenameNode(ctx, a.Node.ID, "Not Valid"); err == nil {
		t.Fatal("expected invalid name error")
	}
	if err := d.RenameNode(ctx, a.Node.ID, "server"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteNode(ctx, b.Node.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if nodes, _ := d.ListNodes(ctx, 0); len(nodes) != 0 {
		t.Fatalf("user delete should cascade, %d nodes left", len(nodes))
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"Laptop.local":       "laptop",
		"My_PC (Home)":       "my-pc-home",
		"--x--":              "x",
		"":                   "node",
		"日本":                 "node",
		"DESKTOP-ABC123.lan": "desktop-abc123",
	}
	for in, want := range cases {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSettingIfAbsent(t *testing.T) {
	d := open(t)
	v, err := d.SetSettingIfAbsent(ctx, "k", "one")
	if err != nil || v != "one" {
		t.Fatalf("%q %v", v, err)
	}
	v, _ = d.SetSettingIfAbsent(ctx, "k", "two")
	if v != "one" {
		t.Fatalf("overwrote existing setting: %q", v)
	}
}
