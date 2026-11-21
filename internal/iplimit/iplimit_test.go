package iplimit

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRate(t *testing.T) {
	l := NewRate(time.Hour, 2)
	if l.Blocked("a") || !l.Allow("a") || !l.Allow("a") {
		t.Fatal("burst refused")
	}
	if !l.Blocked("a") || l.Allow("a") {
		t.Fatal("past the burst allowed")
	}
	if l.Blocked("b") || !l.Allow("b") {
		t.Fatal("another IP limited")
	}
	var none *Rate
	if !none.Allow("a") || none.Blocked("a") {
		t.Fatal("nil Rate limits")
	}
}

func TestCount(t *testing.T) {
	c := NewCount(2, 3)
	if !c.Acquire("a") || !c.Acquire("a") || c.Acquire("a") {
		t.Fatal("per-IP cap")
	}
	if !c.Acquire("b") || c.Acquire("c") {
		t.Fatal("total cap")
	}
	c.Release("a")
	if !c.Acquire("c") {
		t.Fatal("released slot not reusable")
	}
	var none *Count
	if !none.Acquire("a") {
		t.Fatal("nil Count limits")
	}
	none.Release("a")
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{"1.2.3.4:5": "1.2.3.4", "[::1]:80": "::1", "bare": "bare"} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClient(t *testing.T) {
	for addr, want := range map[string]string{
		"192.0.2.7:1234":             "192.0.2.7",
		"[::ffff:192.0.2.7]:1234":    "192.0.2.7",
		"[2001:db8:1:2:3:4:5:6]:443": "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff::1]:443": "2001:db8:1:2::/64",
		"[fe80::1%eth0]:443":         "fe80::/64",
		"not-an-address":             "not-an-address",
	} {
		r := &http.Request{RemoteAddr: addr}
		if got := Client(r); got != want {
			t.Errorf("Client(%q) = %q, want %q", addr, got, want)
		}
	}
}

// Flooding the table must not reset a busy key's limit: checking a key adds
// nothing, and when the table fills, idle entries go first.
func TestFloodKeepsBusyLimits(t *testing.T) {
	l := NewRate(time.Hour, 1)
	l.Allow("victim")
	for i := 0; i < maxTracked+50; i++ {
		l.Blocked(fmt.Sprintf("probe%d", i))
	}
	if !l.Blocked("victim") {
		t.Fatal("read-only checks of other keys reset the victim's limit")
	}
	// Entries that refilled (here: a fast refill) are idle and evicted
	// first, so the busy victim survives a flood of them.
	l = NewRate(time.Nanosecond, 1)
	l.clients["victim"] = rate.NewLimiter(rate.Every(time.Hour), 1)
	l.clients["victim"].Allow()
	for i := 0; i < maxTracked+50; i++ {
		l.Allow(fmt.Sprintf("flood%d", i))
	}
	if !l.Blocked("victim") {
		t.Fatal("a flood of idle entries reset the busy victim")
	}
}
