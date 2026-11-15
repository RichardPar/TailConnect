package db

import (
	"errors"
	"testing"
)

func TestUserDNSDomain(t *testing.T) {
	d := open(t)
	for _, n := range []string{"acme", "globex"} {
		if _, err := d.CreateUser(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	g0, _ := d.Generation(ctx)
	if err := d.SetUserDNSDomain(ctx, "acme", "Acme.Internal.", "home.internal"); err != nil {
		t.Fatal(err)
	}
	u, _ := d.GetUser(ctx, "acme")
	if u.DNSDomain != "acme.internal" {
		t.Fatalf("stored domain %q", u.DNSDomain)
	}
	if g1, _ := d.Generation(ctx); g1 == g0 {
		t.Fatal("changing a domain must bump the generation (it renames machines)")
	}
	if got := TenantDomain(u.Name, u.DNSDomain, "home.internal"); got != "acme.internal" {
		t.Fatalf("TenantDomain = %q", got)
	}
	if got := TenantDomain("globex", "", "home.internal"); got != "globex.home.internal" {
		t.Fatalf("default TenantDomain = %q", got)
	}

	for dom, want := range map[string]error{
		"acme.internal":      ErrExists,  // taken
		"lab.acme.internal":  ErrExists,  // inside another account's
		"internal":           ErrInvalid, // one label
		"home.internal":      ErrInvalid, // the base
		"x.home.internal":    ErrInvalid, // inside the base (another account's default)
		"bad_label.internal": ErrInvalid,
		"-bad.internal":      ErrInvalid,
	} {
		if err := d.SetUserDNSDomain(ctx, "globex", dom, "home.internal"); !errors.Is(err, want) {
			t.Errorf("%q: got %v, want %v", dom, err, want)
		}
	}
	// Containing another account's domain overlaps too.
	if err := d.SetUserDNSDomain(ctx, "acme", "lab.acme.internal", "home.internal"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetUserDNSDomain(ctx, "globex", "acme.internal", "home.internal"); !errors.Is(err, ErrExists) {
		t.Fatalf("parent of another account's domain: %v", err)
	}
	if err := d.SetUserDNSDomain(ctx, "globex", "globex.internal", "home.internal"); err != nil {
		t.Fatal(err)
	}
	// Machines carry their account's domain.
	if err := d.SetUserDNSDomain(ctx, "acme", "", "home.internal"); err != nil {
		t.Fatal(err)
	}
	if u, _ := d.GetUser(ctx, "acme"); u.DNSDomain != "" {
		t.Fatalf("reset: %q", u.DNSDomain)
	}
	if err := d.SetUserDNSDomain(ctx, "nobody", "n.internal", "home.internal"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}
