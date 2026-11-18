package db

import "testing"

func TestReadState(t *testing.T) {
	d := open(t)
	alice, bob := mustUser(t, d, "alice"), mustUser(t, d, "bob")
	r, err := reg(d, "m1", "n1", "nas", mustKey(t, d, alice.ID, false))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetNodeTags(ctx, r.Node.ID, []string{"web"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddRule(ctx, alice.ID, "*", "tag:web", "tcp:443"); err != nil {
		t.Fatal(err)
	}
	sh, err := d.ShareWith(ctx, r.Node.ID, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := d.ReadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Shares) != 0 {
		t.Fatal("pending share in the state")
	}
	if err := d.AcceptShare(ctx, sh.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	st2, err := d.ReadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gen, _ := d.Generation(ctx)
	if st2.Generation != gen || st2.Generation <= st.Generation {
		t.Fatalf("generation %d → %d (current %d)", st.Generation, st2.Generation, gen)
	}
	if len(st2.Nodes) != 1 || len(st2.Nodes[0].Tags) != 1 || len(st2.Rules) != 1 || len(st2.Shares) != 1 {
		t.Fatalf("state: %+v", st2)
	}
}
