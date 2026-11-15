package db

import (
	"errors"
	"testing"
	"time"
)

func TestShares(t *testing.T) {
	d := open(t)
	acme, globex := mustUser(t, d, "acme"), mustUser(t, d, "globex")
	initech := mustUser(t, d, "initech")
	nas, _ := reg(d, "m1", "n1", "nas", mustKey(t, d, acme.ID, false))
	node := nas.Node.ID

	if _, err := d.ShareWith(ctx, node, "acme"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("sharing with the owner: %v", err)
	}
	if _, err := d.ShareWith(ctx, node, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sharing with an unknown account: %v", err)
	}
	g0, _ := d.Generation(ctx)
	s, err := d.ShareWith(ctx, node, "globex")
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != SharePending || s.InEffect() || s.OwnerName != "acme" || s.RecipientName != "globex" || s.NodeName != "nas" {
		t.Fatalf("new share: %+v", s)
	}
	if g1, _ := d.Generation(ctx); g1 <= g0 {
		t.Fatal("sharing must bump the generation")
	}
	if _, err := d.ShareWith(ctx, node, "globex"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate share: %v", err)
	}
	// Only the recipient can accept.
	if err := d.AcceptShare(ctx, s.ID, initech.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("accept by a third party: %v", err)
	}
	if err := d.AcceptShare(ctx, s.ID, globex.ID); err != nil {
		t.Fatal(err)
	}
	s, _ = d.GetShare(ctx, s.ID)
	if !s.InEffect() || s.AcceptedAt.IsZero() {
		t.Fatalf("accepted share: %+v", s)
	}
	// Suspending either side takes it out of effect.
	d.SetUserStatus(ctx, "globex", StatusSuspended)
	if s, _ = d.GetShare(ctx, s.ID); s.InEffect() {
		t.Fatal("share in effect with a suspended recipient")
	}
	d.SetUserStatus(ctx, "globex", StatusActive)

	// Listing by side.
	if l, _ := d.ListShares(ctx, ShareFilter{OwnerID: acme.ID}); len(l) != 1 {
		t.Fatalf("owner list: %d", len(l))
	}
	if l, _ := d.ListShares(ctx, ShareFilter{RecipientID: globex.ID, Accepted: true}); len(l) != 1 {
		t.Fatalf("recipient list: %d", len(l))
	}
	if l, _ := d.ListShares(ctx, ShareFilter{RecipientID: initech.ID}); len(l) != 0 {
		t.Fatalf("unrelated list: %d", len(l))
	}

	// A third party can't delete it; the recipient can leave it.
	if err := d.DeleteShare(ctx, s.ID, initech.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete by a third party: %v", err)
	}
	if err := d.DeleteShare(ctx, s.ID, globex.ID); err != nil {
		t.Fatal(err)
	}

	// Links: single use, not by the owner, expire.
	code, ls, err := d.CreateShareLink(ctx, node, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !ls.Link || ls.RecipientID != 0 || ls.InEffect() {
		t.Fatalf("new link: %+v", ls)
	}
	if _, err := d.RedeemShareLink(ctx, code, acme.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("owner redeeming own link: %v", err)
	}
	got, err := d.RedeemShareLink(ctx, code, initech.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.InEffect() || got.RecipientName != "initech" {
		t.Fatalf("redeemed: %+v", got)
	}
	if _, err := d.RedeemShareLink(ctx, code, globex.ID); !errors.Is(err, ErrInvalidShareLink) {
		t.Fatalf("second redemption: %v", err)
	}
	code2, _, _ := d.CreateShareLink(ctx, node, time.Hour)
	if _, err := d.RedeemShareLink(ctx, code2, initech.ID); !errors.Is(err, ErrExists) {
		t.Fatalf("redeeming a second link to the same machine: %v", err)
	}
	code3, _, _ := d.CreateShareLink(ctx, node, time.Hour)
	d.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := d.RedeemShareLink(ctx, code3, globex.ID); !errors.Is(err, ErrInvalidShareLink) {
		t.Fatalf("expired link: %v", err)
	}
	d.now = time.Now

	// Moving the machine to another tenant ends its shares.
	if _, err := reg(d, "m1", "n1", "nas", mustKey(t, d, globex.ID, false)); err != nil {
		t.Fatal(err)
	}
	if l, _ := d.ListShares(ctx, ShareFilter{}); len(l) != 0 {
		t.Fatalf("%d shares survived the machine moving tenant", len(l))
	}
}
