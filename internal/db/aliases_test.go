package db

import (
	"errors"
	"slices"
	"testing"
	"time"

	"tailconnect/internal/ipam"
)

func TestNodeAliases(t *testing.T) {
	d := open(t)
	acme := mustUser(t, d, "acme")
	globex := mustUser(t, d, "globex")
	jf, err := reg(d, "m1", "n1", "jellyfin", mustKey(t, d, acme.ID, false))
	if err != nil {
		t.Fatal(err)
	}
	lap, _ := reg(d, "m2", "n2", "laptop", mustKey(t, d, acme.ID, false))
	g, _ := reg(d, "m3", "n3", "desk", mustKey(t, d, globex.ID, false))

	got, err := d.SetNodeAliases(ctx, jf.Node.ID, []string{" NAS", "media", "nas", ""})
	if err != nil || !slices.Equal(got, []string{"media", "nas"}) {
		t.Fatalf("set aliases: %v %v", got, err)
	}
	n, _ := d.GetNode(ctx, jf.Node.ID)
	if !slices.Equal(n.Aliases, []string{"media", "nas"}) {
		t.Fatalf("stored aliases: %v", n.Aliases)
	}
	// Clashes within the account: another machine's name or alias, own name.
	if _, err := d.SetNodeAliases(ctx, lap.Node.ID, []string{"jellyfin"}); !errors.Is(err, ErrExists) {
		t.Fatalf("alias onto another machine's name: %v", err)
	}
	if _, err := d.SetNodeAliases(ctx, lap.Node.ID, []string{"nas"}); !errors.Is(err, ErrExists) {
		t.Fatalf("alias onto another machine's alias: %v", err)
	}
	if _, err := d.SetNodeAliases(ctx, lap.Node.ID, []string{"laptop"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("alias onto own name: %v", err)
	}
	if _, err := d.SetNodeAliases(ctx, lap.Node.ID, []string{"bad.name"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad alias: %v", err)
	}
	if err := d.RenameNode(ctx, lap.Node.ID, "nas"); !errors.Is(err, ErrExists) {
		t.Fatalf("rename onto another machine's alias: %v", err)
	}
	// Another account may use the same label.
	if _, err := d.SetNodeAliases(ctx, g.Node.ID, []string{"nas"}); err != nil {
		t.Fatalf("alias in another account: %v", err)
	}
	// Renaming onto one's own alias drops that alias.
	if err := d.RenameNode(ctx, jf.Node.ID, "media"); err != nil {
		t.Fatal(err)
	}
	n, _ = d.GetNode(ctx, jf.Node.ID)
	if n.GivenName != "media" || !slices.Equal(n.Aliases, []string{"nas"}) {
		t.Fatalf("after rename: %s %v", n.GivenName, n.Aliases)
	}
	// A new machine named like an alias gets a free name.
	nas, _ := reg(d, "m4", "n4", "nas", mustKey(t, d, acme.ID, false))
	if nas.Node.GivenName != "nas-2" {
		t.Fatalf("new machine named like an alias: %s", nas.Node.GivenName)
	}
	// Aliases change the map generation.
	g0, _ := d.Generation(ctx)
	if _, err := d.SetNodeAliases(ctx, jf.Node.ID, nil); err != nil {
		t.Fatal(err)
	}
	if g1, _ := d.Generation(ctx); g1 == g0 {
		t.Fatal("generation unchanged after aliases change")
	}
	// Moving to another account drops aliases.
	d.SetNodeAliases(ctx, lap.Node.ID, []string{"work"})
	moved, err := reg(d, "m2", "n2", "laptop", mustKey(t, d, globex.ID, false))
	if err != nil {
		t.Fatal(err)
	}
	if len(moved.Node.Aliases) != 0 {
		t.Fatalf("aliases kept across accounts: %v", moved.Node.Aliases)
	}
}

// Moving a machine to another account drops what its old account granted:
// tags, the exit node role and a never-expiring key.
func TestMoveResetsGrants(t *testing.T) {
	d := open(t)
	a := mustUser(t, d, "tenanta")
	b := mustUser(t, d, "tenantb")
	r, err := reg(d, "m1", "n1", "box", mustKey(t, d, a.ID, false))
	if err != nil {
		t.Fatal(err)
	}
	id := r.Node.ID
	if err := d.SetNodeTags(ctx, id, []string{"prod"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetNodeExitNode(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	if err := d.SetNodeExpiry(ctx, id, time.Time{}); err != nil { // never
		t.Fatal(err)
	}
	moved, err := d.RegisterNode(ctx, RegisterParams{MachineKey: "m1", NodeKey: "n1", DiscoKey: "disco-n1", Hostname: "box",
		AuthKey: mustKey(t, d, b.ID, false), Alloc: ipam.Default().Next, KeyExpiry: 180 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	n := moved.Node
	if n.UserName != "tenantb" || len(n.Tags) != 0 || n.ExitNode || n.ExpiresAt.IsZero() {
		t.Fatalf("after moving: user=%s tags=%v exit=%v expires=%v", n.UserName, n.Tags, n.ExitNode, n.ExpiresAt)
	}
}
