package ipam

import (
	"net/netip"
	"testing"
)

func TestSequentialAllocation(t *testing.T) {
	a := Default()
	used := map[netip.Addr]bool{}
	want := []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"}
	for _, w := range want {
		v4, v6, err := a.Next(used)
		if err != nil {
			t.Fatal(err)
		}
		if v4.String() != w {
			t.Fatalf("got %s want %s", v4, w)
		}
		if !DefaultV6.Contains(v6) {
			t.Fatalf("v6 %s not in pool", v6)
		}
		used[v4] = true
	}
}

func TestV6Mapping(t *testing.T) {
	a := Default()
	got := a.V6For(netip.MustParseAddr("100.64.1.2"))
	if want := netip.MustParseAddr("fd7c:7c0e:a1e0::6440:102"); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestSkipsReservedAndFillsGaps(t *testing.T) {
	a, err := New(netip.MustParsePrefix("100.100.96.0/21"), DefaultV6)
	if err != nil {
		t.Fatal(err)
	}
	// Pool is 100.100.96.0-103.255; mark everything below the reserved /24 as used.
	used := map[netip.Addr]bool{}
	for ip := netip.MustParseAddr("100.100.96.1"); ip.Less(netip.MustParseAddr("100.100.100.0")); ip = ip.Next() {
		used[ip] = true
	}
	v4, _, err := a.Next(used)
	if err != nil {
		t.Fatal(err)
	}
	if v4.String() != "100.100.101.0" {
		t.Fatalf("expected first address after reserved /24, got %s", v4)
	}
	delete(used, netip.MustParseAddr("100.100.97.7"))
	v4, _, _ = a.Next(used)
	if v4.String() != "100.100.97.7" {
		t.Fatalf("expected gap to be reused, got %s", v4)
	}
}

func TestExhaustion(t *testing.T) {
	a, err := New(netip.MustParsePrefix("10.0.0.0/30"), DefaultV6)
	if err != nil {
		t.Fatal(err)
	}
	used := map[netip.Addr]bool{}
	for i := 0; i < 2; i++ { // /30 has two usable addresses
		v4, _, err := a.Next(used)
		if err != nil {
			t.Fatal(err)
		}
		used[v4] = true
	}
	if _, _, err := a.Next(used); err != ErrExhausted {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
}
