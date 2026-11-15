package db

import (
	"testing"
	"time"

	"tailconnect/internal/ipam"
)

func regExp(d *DB, machine, node, authKey string, exp time.Duration) (RegisterResult, error) {
	return d.RegisterNode(ctx, RegisterParams{
		MachineKey: machine, NodeKey: node, Hostname: machine, AuthKey: authKey, Alloc: ipam.Default().Next, KeyExpiry: exp,
	})
}

func TestMachineApproval(t *testing.T) {
	d := open(t)
	u := mustUser(t, d, "acme")
	if err := d.SetMachineApproval(ctx, "acme", true); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.GetUser(ctx, "acme"); !got.RequireMachineApproval {
		t.Fatal("setting not stored")
	}
	r, err := reg(d, "m1", "n1", "laptop", mustKey(t, d, u.ID, false))
	if err != nil {
		t.Fatal(err)
	}
	if r.Node.Approved || r.Node.Usable(time.Now()) {
		t.Fatal("new machine should wait for approval")
	}
	g0, _ := d.Generation(ctx)
	if err := d.ApproveNode(ctx, r.Node.ID); err != nil {
		t.Fatal(err)
	}
	if g1, _ := d.Generation(ctx); g1 <= g0 {
		t.Fatal("approval must bump the generation")
	}
	n, _ := d.GetNode(ctx, r.Node.ID)
	if !n.Approved || !n.Usable(time.Now()) {
		t.Fatalf("approved node: %+v", n)
	}
	// Pre-approved keys skip approval.
	pk, _, _ := d.CreatePreAuthKey(ctx, CreatePreAuthKeyParams{UserID: u.ID, Preapproved: true, TTL: time.Hour})
	if r2, _ := reg(d, "m2", "n2", "server", pk); !r2.Node.Approved {
		t.Fatal("pre-approved key: machine not approved")
	}
	// Re-authenticating in the same account keeps approval.
	if r3, err := reg(d, "m1", "n1b", "laptop", mustKey(t, d, u.ID, false)); err != nil || !r3.Node.Approved {
		t.Fatalf("re-auth: %+v %v", r3.Node, err)
	}
	// Moving to another account that requires approval starts over.
	g := mustUser(t, d, "globex")
	d.SetMachineApproval(ctx, "globex", true)
	if r4, err := reg(d, "m1", "n1c", "laptop", mustKey(t, d, g.ID, false)); err != nil || r4.Node.Approved {
		t.Fatalf("moved machine should need globex's approval: %+v %v", r4.Node, err)
	}
	// Accounts without the setting approve automatically.
	o := mustUser(t, d, "open")
	if r5, _ := reg(d, "m5", "n5", "x", mustKey(t, d, o.ID, false)); !r5.Node.Approved {
		t.Fatal("account without approval: machine not approved")
	}
}

func TestKeyExpiry(t *testing.T) {
	d := open(t)
	u := mustUser(t, d, "acme")
	r, err := regExp(d, "m1", "n1", mustKey(t, d, u.ID, false), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if r.Node.ExpiresAt.IsZero() || r.Node.Expired(now) || !r.Node.Expired(now.Add(2*time.Hour)) {
		t.Fatalf("expiry: %v", r.Node.ExpiresAt)
	}
	if r.Node.Usable(now.Add(2 * time.Hour)) {
		t.Fatal("expired machine still usable")
	}
	// Re-authenticating renews.
	d.now = func() time.Time { return now.Add(50 * time.Minute) }
	r2, err := regExp(d, "m1", "n1", mustKey(t, d, u.ID, false), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Node.ExpiresAt.After(r.Node.ExpiresAt) {
		t.Fatalf("not renewed: %v -> %v", r.Node.ExpiresAt, r2.Node.ExpiresAt)
	}
	d.now = time.Now
	// Never: set by an operator, kept across re-authentication.
	g0, _ := d.Generation(ctx)
	if err := d.SetNodeExpiry(ctx, r.Node.ID, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if g1, _ := d.Generation(ctx); g1 <= g0 {
		t.Fatal("expiry change must bump the generation")
	}
	r3, _ := regExp(d, "m1", "n1", mustKey(t, d, u.ID, false), time.Hour)
	if !r3.Node.ExpiresAt.IsZero() {
		t.Fatalf("never-expiring machine got an expiry on re-auth: %v", r3.Node.ExpiresAt)
	}
	// Servers with expiry off register machines that never expire.
	if r4, _ := regExp(d, "m4", "n4", mustKey(t, d, u.ID, false), 0); !r4.Node.ExpiresAt.IsZero() {
		t.Fatal("expiry 0 should mean never")
	}
}

func TestStaleEphemeral(t *testing.T) {
	d := open(t)
	u := mustUser(t, d, "ci")
	ek, _, _ := d.CreatePreAuthKey(ctx, CreatePreAuthKeyParams{UserID: u.ID, Ephemeral: true, Reusable: true, TTL: time.Hour})
	r1, _ := reg(d, "m1", "n1", "runner", ek)
	reg(d, "m2", "n2", "keeper", mustKey(t, d, u.ID, false)) // not ephemeral
	if l, _ := d.StaleEphemeralNodes(ctx, time.Now().Add(-time.Minute)); len(l) != 0 {
		t.Fatalf("fresh ephemeral listed as stale: %d", len(l))
	}
	l, err := d.StaleEphemeralNodes(ctx, time.Now().Add(time.Minute))
	if err != nil || len(l) != 1 || l[0].ID != r1.Node.ID {
		t.Fatalf("stale ephemeral: %+v %v", l, err)
	}
}

func TestTagsAndRules(t *testing.T) {
	d := open(t)
	acme, globex := mustUser(t, d, "acme"), mustUser(t, d, "globex")
	r, _ := reg(d, "m1", "n1", "server", mustKey(t, d, acme.ID, false))
	g0, _ := d.Generation(ctx)
	if err := d.SetNodeTags(ctx, r.Node.ID, []string{"web", "db"}); err != nil {
		t.Fatal(err)
	}
	if g1, _ := d.Generation(ctx); g1 <= g0 {
		t.Fatal("tags must bump the generation")
	}
	n, _ := d.GetNode(ctx, r.Node.ID)
	if len(n.Tags) != 2 || n.Tags[0] != "web" {
		t.Fatalf("tags: %v", n.Tags)
	}
	g0, _ = d.Generation(ctx)
	rule, err := d.AddRule(ctx, acme.ID, "tag:staff", "tag:web", "tcp:443")
	if err != nil {
		t.Fatal(err)
	}
	if g1, _ := d.Generation(ctx); g1 <= g0 {
		t.Fatal("rules must bump the generation")
	}
	d.AddRule(ctx, globex.ID, "*", "*", "*")
	if l, _ := d.ListRules(ctx, acme.ID); len(l) != 1 || l[0].UserName != "acme" || l[0].Ports != "tcp:443" {
		t.Fatalf("acme rules: %+v", l)
	}
	if l, _ := d.ListRules(ctx, 0); len(l) != 2 {
		t.Fatalf("all rules: %d", len(l))
	}
	if err := d.DeleteRule(ctx, rule.ID, globex.ID); err == nil {
		t.Fatal("deleted another account's rule")
	}
	if err := d.DeleteRule(ctx, rule.ID, acme.ID); err != nil {
		t.Fatal(err)
	}
}
