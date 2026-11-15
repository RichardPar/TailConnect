package iplimit

import (
	"testing"
	"time"
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
